# DeltaForge — AI 执行简报 v1.0

> 本文档面向接手此项目的 AI 执行代理。阅读完整后再动手。
> 当前 8.7 架构、真源和联动关系以 `KNOWLEDGE.md` 为最高优先级；本文后续 TASK 表为历史执行记录。

---

## 一、项目背景

DeltaForge 是针对 Android ARM64 云手机的运行时环境管理工具集，目标游戏为腾讯
`com.tencent.tmgp.dfm`（三角洲行动）。

**核心问题**：云手机是虚拟化环境，游戏内置反作弊模块 `libtersafe.so` 会检测
虚拟机特征、进程注入痕迹、GPU 型号异常、kill 信号链等，触发后封号或踢出。

**DeltaForge 的解法**：五层防御架构——

| 层 | 位置 | 手段 |
|----|------|------|
| L1 | 内核 | seccomp-BPF（当前已禁用，ART 崩溃） |
| L2 | 进程内 | /proc 虚假文件内容返回（43 条路径） |
| L3 | 进程内 | libc PLT hook（30+ 函数） |
| L4 | 进程内 | 代码 patch（67+6+40 处） |
| L5 | 外部 | forge 守护进程 100ms 轮询重推 |

---

## 二、代码仓库结构

```
DeltaForge-repo/
├── cloud-agent/native/
│   ├── forge.c            守护进程，L5，~1300 行
│   ├── libforgehook.c     注入库，L2/L3/L4，~2300 行
│   ├── injector.c         ptrace 注入器，612 行
│   ├── forge_monitor.c    独立监控，~300 行
│   ├── touch_injector.c   虚拟触摸，~150 行
│   ├── crypt_strings.h    编译期字符串加密
│   └── Makefile
├── runner/
│   ├── forge_controller.py   TCP 控制层（Python）
│   ├── bot_runner.py         自动化 bot（Python）
│   └── config/
│       ├── forge_config.json
│       └── map_routes.json
├── DELTAFORGE_GUIDE.md    完整技术文档
└── AGENT_BRIEF.md         本文档
```

**编译**（Termux 云手机原生）：
```bash
cd cloud-agent/native && make termux
```

**部署**：
```bash
su -c "cp forge injector libforgehook.so /data/local/tmp/"
su -c "/data/local/tmp/forge -l"
```

---

## 三、待实现任务执行表

每项任务独立，可并行分配给不同 AI。完成后需通过验收标准方可提交。

---

### TASK-01：patch 版本绑定校验

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/forge.c` |
| **优先级** | P0（最高，防止写坏内存） |
| **问题** | `kTersafePatches` 偏移表针对特定版本硬编码，游戏更新后偏移失效，forge 会静默写入错误地址 |

**实现方案**：

在 `forge.c` 中，`do_launch()` 调用实际 patch 之前，新增 `verify_tersafe_version()` 函数：

1. 找到目标进程中 `libtersafe.so` 的磁盘路径（从 `/proc/pid/maps` 的路径列读取）
2. 读取该文件的 ELF `.note.gnu.build-id` section（`SHT_NOTE`，tag `NT_GNU_BUILD_ID`）
3. 与 `forge.c` 顶部的 `EXPECTED_TERSAFE_BUILD_ID` 常量对比（十六进制字符串）
4. 不匹配时：打印警告 + 写 `DETECT_LOG` + **跳过所有 patch**，不崩溃

```c
// 在 forge.c 顶部新增
#define EXPECTED_TERSAFE_BUILD_ID  "a1b2c3d4e5f6..."  /* 从当前版本读取后填入 */

static int verify_tersafe_version(pid_t pid);
// 返回 1 = 版本匹配可 patch；返回 0 = 版本不符跳过
```

读取 build-id 的方法：`/proc/pid/maps` 找到 libtersafe.so 路径 → `open` 读 ELF header → 遍历 section headers 找 `.note.gnu.build-id`。

**验收标准**：
- 用错误的 `EXPECTED_TERSAFE_BUILD_ID` 值启动 forge，日志中出现跳过 patch 的警告，进程不崩溃
- 用正确的 build-id 值，patch 正常执行

---

### TASK-02：forge 主循环注入后降频

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/forge.c` |
| **优先级** | P1 |
| **问题** | 注入成功后 forge 仍以 100ms 轮询重推全部 patch，访问 `/proc/pid/mem` 频率过高，增加被 tersafe 内存扫描检测到的概率 |

**实现方案**：

在 forge 主循环中加入两阶段轮询：

```c
typedef enum { PHASE_INJECT, PHASE_MAINTAIN } forge_phase_t;

// PHASE_INJECT:  100ms 轮询，直到注入成功
// PHASE_MAINTAIN: 注入成功后：
//   - 每 5000ms 做一次完整 patch 重推（覆盖 tersafe 自修复）
//   - 每 500ms 只做 BSS 清零（开销极低）
//   - 每 1000ms 做 kKillChain 6 节点快速校验（读回对比）
```

具体实现：在现有轮询循环里加 `phase` 变量和 `struct timespec` 计时器组，不同操作按各自周期触发。

**验收标准**：
- `strace -e openat forge` 输出中，注入成功后 `/proc/pid/mem` 打开频率从 ~10次/秒 降至 ~2次/秒

---

### TASK-03：forge 崩溃自恢复 watchdog

| 字段 | 内容 |
|------|------|
| **文件** | `runner/forge_controller.py` 新增逻辑 |
| **优先级** | P1 |
| **问题** | forge 进程被 OOM killer 或 tersafe 打死后无人重启，外部 patch 停止 |

**实现方案**：

在 `forge_controller.py` 中新增 `WatchdogThread` 类：

```python
class WatchdogThread(threading.Thread):
    def __init__(self, ctrl: ForgeController, interval: int = 10):
        # interval 秒检查一次
        # 检查方法: send_forge_command("ping")
        # 失败则: push_and_start_forge() → setup_adb_forward() → ctrl.connect()
        # 最多重试 3 次，3 次失败写告警日志退出
        pass
```

在 `bot_runner.py` 的 `BotRunner.run()` 开头启动 `WatchdogThread`，`daemon=True`。

**验收标准**：
- 手动 `su -c killall forge`，10 秒内 forge 自动重启
- `forge.log` 中出现 watchdog 重启记录

---

### TASK-04：`/proc/self/status` TracerPid 伪造

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/libforgehook.c` |
| **优先级** | P0 |
| **问题** | forge 通过 `/proc/pid/mem` 写 patch 期间，目标进程的 `/proc/self/status` 中 `TracerPid` 字段短暂非零，tersafe 可检测到调试器附加 |

**实现方案**：

`libforgehook.c` 已有 `/proc` 文件拦截机制（`hook_open`/`hook_read` 等）。在现有的 `make_filtered_*` 系列函数中，新增对 `status` 文件的处理：

```c
// 在 hook_read / hook_pread64 的 proc 过滤逻辑中，
// 检测到读取路径为 /proc/self/status 时，
// 对返回内容做行级过滤：
//   找到 "TracerPid:" 行 → 替换值为 0
//   找到 "State:" 行 → 如果是 't'（traced）→ 替换为 'S'
static void filter_status_content(char *buf, size_t len);
```

注意：要处理 `TracerPid` 字段不仅在 `/proc/self/status`，也可能被读 `/proc/<pid>/status`（tersafe 可能读主进程 pid）。

**验收标准**：
- 注入后在游戏进程内执行：`cat /proc/self/status | grep TracerPid` → 输出 `TracerPid:\t0`
- 通过 `forge_monitor` 确认 tersafe 没有触发 tracer 告警

---

### TASK-05：memfd 无落盘 so 加载

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/injector.c` + `libforgehook.c` |
| **优先级** | P2 |
| **问题** | 当前 libforgehook.so 先落盘到 `/data/local/tmp/`，chainload 后才删文件，磁盘上有窗口期；tersafe 可能在此期间扫描到文件 |

**实现方案**：

分两步：

**Step 1 — injector.c**：注入前用 `memfd_create` 在目标进程创建匿名 fd：

```c
// 在目标进程中远程调用 memfd_create
int64_t remote_memfd = remote_syscall(pid, svc_addr,
    279,                    // __NR_memfd_create
    str_addr,               // name (任意字符串指针)
    0x2,                    // MFD_ALLOW_SEALING
    0, 0, 0, 0);

// 再用 remote_syscall(__NR_write) 把 so 内容通过 process_vm_writev 写入 memfd
// 最后 dlopen("/proc/<pid>/fd/<memfd>", RTLD_NOW)
```

**Step 2 — libforgehook.c 的 chainload**：同样用 memfd 加载 `libtdmqimei_real.so`，消除磁盘文件。

**验收标准**：
- 注入完成后，`ls /data/local/tmp/libforgehook.so` 找不到文件
- `cat /proc/<pid>/maps | grep forgehook` 也找不到路径（已被 mremap 隐藏）
- 游戏功能正常

---

### TASK-06：偏移表外置为 JSON 热更新

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/forge.c` + 新建 `cloud-agent/native/patch_loader.c/h` + 新建 `runner/config/tersafe_patches.json` |
| **优先级** | P1 |
| **问题** | `kTersafePatches` 等偏移表硬编码在 C 文件中，每次游戏更新都要重新编译整个二进制 |

**实现方案**：

新建 `patch_loader.h` / `patch_loader.c`，提供：

```c
typedef struct {
    uint64_t offset;
    uint32_t value;
    char     comment[64];
} patch_entry_dyn_t;

// 从 JSON 文件解析偏移表（不依赖 cJSON 等库，自己写简单解析器）
int patch_loader_load(const char *json_path,
                      patch_entry_dyn_t **out, int *count);
void patch_loader_free(patch_entry_dyn_t *entries);
```

JSON 格式：
```json
{
  "tersafe_build_id": "a1b2c3d4...",
  "tersafe_patches": [
    {"offset": "0x5137C0", "value": "0x2A1F03FF", "comment": "return 0xFF"},
    ...
  ],
  "tersafe_bss": ["0x47F0", "0x4C28", ...],
  "ue4_patches": [...]
}
```

forge.c 启动时优先加载 `/data/local/tmp/forge_patches.json`，失败则回退内置静态表。

JSON 解析器要求：纯 C，无 malloc 依赖（可用静态 arena），总代码 < 200 行。

**验收标准**：
- 修改 JSON 文件中任一 offset/value，不重新编译 forge，重启后新值生效
- JSON 文件不存在时，forge 回退静态表并打印提示，功能不中断

---

### TASK-07：forge_monitor → forge 实时 IPC 告警

| 字段 | 内容 |
|------|------|
| **文件** | `cloud-agent/native/forge_monitor.c` + `cloud-agent/native/forge.c` |
| **优先级** | P1 |
| **问题** | forge_monitor 发现 tersafe 上报连接或 tracer 告警后只写日志，forge 要等下一个 100ms 轮询才能响应 |

**实现方案**：

使用 Unix domain socket 连接两个进程：

**forge.c 侧（server）**：
```c
// 在 forge 主循环的初始化阶段创建 UDS server
// 路径: /data/local/tmp/forge_ipc.sock
// 收到消息格式: { "event": "ALERT_TDM_CONNECT" | "ALERT_TRACER" | "ALERT_KEYWORD" }
// 响应: 立即触发一次完整 patch 重推
int ipc_server_fd = setup_ipc_server("/data/local/tmp/forge_ipc.sock");
// 在 select() 或 epoll 中加入 ipc_server_fd
```

**forge_monitor.c 侧（client）**：
```c
// 在检测到告警时连接 UDS，发送 JSON 消息，发完断开
static void notify_forge(const char *event);
```

告警触发条件（已在 forge_monitor.c 中）：
- TCP 连接检测到 tersafe 上报目标 IP
- 关键词扫描命中 `ban/frozen/kicked`
- fd 枚举发现 tracer

**验收标准**：
- 手动向 forge_monitor 监控的目录写一个包含 "tersafe" 的文件，forge 日志中在 200ms 内出现紧急 patch 记录

---

### TASK-08：bot_runner.py forge 连接重试

| 字段 | 内容 |
|------|------|
| **文件** | `runner/bot_runner.py` + `runner/forge_controller.py` |
| **优先级** | P1 |
| **问题** | bot_runner 调用 forge TCP 接口时没有连接级重试，forge 重启后 bot 直接报失败退出 |

**实现方案**：

在 `forge_controller.py` 的 `send_forge_command` 外层包装重试逻辑：

```python
def send_forge_command_with_retry(cmd: str, timeout: float = 30.0,
                                   retries: int = 3,
                                   retry_delay: float = 5.0) -> dict:
    for attempt in range(retries):
        resp = send_forge_command(cmd, timeout)
        if resp.get("status") not in ("err",):
            return resp
        if attempt < retries - 1:
            print(f"[retry] {cmd} failed (attempt {attempt+1}), waiting {retry_delay}s")
            # 尝试重新建立 adb forward
            setup_adb_forward()
            time.sleep(retry_delay)
    return resp
```

在 `bot_runner.py` 所有调用 `send_forge_command` 的地方替换为 `send_forge_command_with_retry`。

另外，`BotRunner._ensure_game()` 方法在 forge 连接失败时应调用 `ForgeController.connect()` 重连，而不是直接返回 False。

**验收标准**：
- 手动重启 forge 后，bot_runner 在下一轮循环中自动恢复，不退出
- 日志中出现重试记录

---

## 四、任务分配优先级汇总

| 任务 | 文件 | 优先级 | 预估难度 | 依赖 |
|------|------|--------|----------|------|
| TASK-01 版本校验 | forge.c | P0 | 中 | 无 |
| TASK-04 TracerPid 伪造 | libforgehook.c | P0 | 中 | 无 |
| TASK-02 轮询降频 | forge.c | P1 | 低 | TASK-01 |
| TASK-03 watchdog | forge_controller.py | P1 | 低 | 无 |
| TASK-06 偏移表外置 | forge.c + 新文件 | P1 | 中 | TASK-01 |
| TASK-07 IPC 告警 | forge.c + forge_monitor.c | P1 | 中 | 无 |
| TASK-08 bot 重试 | bot_runner.py | P1 | 低 | TASK-03 |
| TASK-05 memfd 加载 | injector.c + libforgehook.c | P2 | 高 | 无 |

**建议执行顺序**：TASK-01 → TASK-04 → TASK-06（这三项串行，都在 patch 安全性链路上）；TASK-02/03/07/08 可并行。TASK-05 单独排期。

---

## 五、代码规范要求

所有修改必须遵守：

1. **C 文件**：`-fno-stack-protector -fomit-frame-pointer -Os`，不引入新的外部依赖，新函数加 `static`
2. **字符串常量**：敏感路径/名称使用 `crypt_strings.h` 的 `CRYPT_STR` 宏，不直接写明文
3. **日志**：用 `OK()` / `WARN()` / `ERR()` 宏，不用 `printf`；libforgehook.c 里用 `hook_log()`
4. **错误处理**：每个 syscall/文件操作必须检查返回值，失败路径必须 log
5. **Python 文件**：函数加类型注解，新增功能写注释说明 why

---

## 六、验收流程

每个 TASK 完成后提交 diff，由主审 AI 执行以下步骤：

1. `make termux` 编译通过，无新 warning
2. 运行对应 TASK 的**验收标准**中的测试步骤
3. 检查 `forge.log` 确认新功能有对应日志输出
4. 回归测试：正常启动流程不受影响，游戏进入游戏后无封号

---

*文档版本: v1.0 | 项目: DeltaForge v8.7 | 维护者: 主控 AI*
