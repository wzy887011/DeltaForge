# DeltaForge v8.7 — 完整项目总结文档

> 文档位置: `DeltaForge/FINAL_SUMMARY.md`
> 生成时间: 2026-07-25
> 当前版本: v8.7

---

## 一、项目全貌

DeltaForge 是针对 Android ARM64 云手机的**运行时环境管理工具集**，
目标是使游戏（`com.tencent.tmgp.dfm`）在 root 过的云手机上绕过
`libtersafe.so` 环境检测模块，实现稳定运行与自动化挂机。

### 系统架构

```
┌────────────────────────── Android 云手机 ─────────────────────────┐
│                                                                    │
│  forge.c (守护进程)          libforgehook.so (进程内注入)           │
│  ├─ 代码 patch (75处)        ├─ libc hook (30+ 函数)               │
│  ├─ BSS 清零 (40处)          ├─ 文件系统伪造 (/proc /sys)           │
│  ├─ UE4 引擎 patch (0处)     ├─ 属性查询伪造 (ro.build.*)          │
│  ├─ SipHash TCP 认证         ├─ 网络过滤 (AC 上报域名/IP)           │
│  ├─ 全表预检/fail-closed      └─ QIMEI chainload/模块范围发现        │
│  └─ 分层守护轮询                                                    │
│              ↑                        ↑                            │
│       ptrace 注入 ──────────────────────┘                          │
│              ↑                                                     │
│    adb forward 9510                                                │
└────────────────────────────────────────────────────────────────────┘
                   ↓
    PC: forge_controller.py (opcode+SipHash) / bot_runner.py
```

---

## 二、版本演进历史

### v6.0 基线版本
- 初始实现：内存 patch + libc hook + 属性伪造
- 问题：hijack 模式频繁闪退；BSS 偏移硬编码

### v7.0 稳定性升级
- g_hooks_ready 延迟激活（避免 ART 初始化期间 hook 干扰）
- maps 动态缓冲（修复 64KB 截断导致注入痕迹残留）
- dlopen 死锁修复（constructor 推迟到后台线程）
- TCP SipHash-2-4 认证
- BSS 自动扫描 + 结果持久化
- 守护进程分层轮询（检测链200ms/代码段600ms/BSS1s/UE41s）
- fork+execv 替代 system()
- forge_controller.py v7 认证版
- bot_runner.py 崩溃恢复

### v7.1 安全加固 + 封号修复

#### Critical Fix — hook 激活可靠性（防封号根因）
- **根因**: v7.0 将 g_hooks_ready=1 移到 patch 成功后才设置。
  tersafe 持续恢复补丁导致 ok<4，进程在 2s 等待窗口内被 kill，
  hooks 永不激活 → libc 拦截全部失效 → 游戏上报真实设备信息 → 封号
- **Fix 1**: 三路径激活 (patch成功/inject模式立即/2s重试兜底)
- **Fix 2**: constructor(48) 双路径日志 + 0666 权限
- **Fix 3**: 守护进程 200ms → 100ms
- **Fix 4**: hook_log 双路径 + 0666

#### P0 — 字符串常量加密
- `tools/crypt_gen.py` 生成器 + `crypt_strings.h`
- XOR key=0x73，29 个敏感字符串加密
- `strings libforgehook.so | grep forgehook` → 无明文输出

#### P1 — 每次启动随机化标识符
- constructor(48) 生成 6位hex随机后缀（/dev/urandom）
- memfd_anon: "ac" → "ac_XX"
- override_fd: "fh" → "fh_XX"
- 防 memfd 名称指纹识别

#### P2 — 编译期垃圾指令注入
- `JUNK_INSN()`/`JUNK_INSN2()` ARM64 无语义指令宏
- 注入 9 处：open/openat/tgkill/__system_property_get/JNI_OnLoad
- 防静态特征码匹配

#### P3 — mremap 匿名重映射
- constructor(104) 对 RW 数据段 mremap → 匿名页
- `/proc/self/maps` 中路径变为 `[anon]`
- RX 代码段保留 MADV_DONTDUMP（避免 SIGBUS）
- mremap 失败时 fallback DONTDUMP

#### P4 — 属性查询流量混淆
- prop_cache_t[32] 缓存非白名单属性真实值
- 同属性 1s 内查询 >3次：末字符大小写/数字抖动
- 防行为指纹识别（异常查询频率）
- forge_audit 只在首次查询时记录，减少 I/O

#### P5 — TCP opcode 无痕通信
- 单字节 opcode 替代明文命令字符串
- 响应 JSON 字段缩短（status→s, version→v 等）
- 兼容旧 text-mode（平滑升级）
- forge_controller.py 自动选择 opcode 并展开响应字段

---

## 三、部署使用

### 编译

```bash
# 在 Termux 内
cd /path/to/DeltaForge/cloud-agent
sh deploy.sh --no-hijack   # 推荐：inject 模式
```

### 启动

```bash
# 完整流程（推荐）
su -c '/data/local/tmp/forge -l'

# 或通过 PC 端控制
python runner/forge_controller.py full

# 验证 hook 激活（关键诊断）
su -c 'grep "v7.1 activated" /data/local/tmp/forge_hook.log'
cat /sdcard/forge_hook.log | grep "v7.1"   # fallback
```

### 日志说明

| 文件 | 内容 | 关键标志 |
|------|------|---------|
| `/data/local/tmp/forge.log` | forge 主进程日志 | `patch reverted` = tersafe 正在对抗 |
| `/data/local/tmp/forge_hook.log` | 注入库日志 | `v7.1 activated` = hooks 已激活 |
| `/sdcard/forge_hook.log` | 上条fallback | 主路径失败时检查此处 |
| `/data/local/tmp/forge_repair.log` | patch 修复记录 | 分析 tersafe 恢复模式 |
| `/data/local/tmp/forge_bss_map.json` | BSS offset 缓存 | 版本更新后自动重建 |

---

## 四、历史提升方案（已由 8.7 硬化计划取代）

> 当前任务、风险和验收标准以 `HARDENING_PLAN_8.7.md` 与 `KNOWLEDGE.md` 为准；
> 下列条目保留作历史追溯，不代表当前实现状态。

### 短期（1-2周可实施）

**1. GPU hook 修复**
- 当前: 已禁用（云手机虚拟 GPU 不匹配伪造的 Adreno 730）
- 方案: 运行时查询真实 `GL_RENDERER`，只替换品牌/型号字符串，
  保留真实 feature bits，避免 UE4 RHI 崩溃
- 文件: `libforgehook.c` → `_patch_gpu_driver`

**2. forge_monitor 修复**
- 当前: scan_net 读自身 /proc/net/tcp 被 OVERRIDE_NET_TCP 拦截，永远看不到真实连接
- 方案: `adb shell su -c 'cat /proc/<game_pid>/net/tcp'`，以 root 绕过 hook
- 文件: `cloud-agent/native/forge_monitor.c` → `scan_net`

**3. cycle 溢出防护（已记录，未修复）**
- 守护进程 `static int cycle = 0; cycle++;`
- 连续运行 50 天（200ms间隔）后 int 溢出，周期逻辑错乱
- 修复: `if (cycle >= 30) cycle = 1;`

**4. deploy.sh 最终版本引用**
- 文件头部注释行还有残留的旧版本表述，清理即可

### 中期（1个月）

**5. Pattern scan 填充特征码**
- 当前: `kKillChain` / `kKillChainV2` 中所有 `sig_bytes` 全空
- 方案: 用 IDA 对 libtersafe.so 提取每个 patch 点周围的 ARM64 特征序列
  （至少 8 字节，掩掉相对跳转偏移），填入 sig_bytes/sig_len
- 效果: libtersafe 更新后自动重定位 patch 点，无需手动维护 offset

**6. BSS 扫描精度提升**
- 当前: 快照差分，600ms 等待，值特征过滤（1/2/0x100/0x200）
- 问题: 部分检测变量初始化为非零（如枚举类型），会被过滤掉
- 方案: 扩展值范围过滤，加入值变化方向分析（单调递增 = 计数器，
  非单调 = 状态标志）

**7. 多设备并发支持**
- 当前: forge_controller.py 单设备，ADB_SERIAL 环境变量控制
- 方案: ForgeController 接受设备列表，bot_runner.py 多线程并发
- 效果: 一台 PC 管理多台云手机

### 长期（3个月+）

**8. 内核级 hook（KernelSU / APatch）**
- 当前: 全部用户态，内核感知到所有操作
- 方案: 利用 KernelSU 的 exec_hook 在进程 execve 时注入，
  在 /proc/self/maps 读取位置直接 patch 内核 vfs_read 返回
- 效果: 彻底规避用户态 hook 可见性问题

**9. 自适应 offset 学习系统**
- 当前: 每次 libtersafe 更新需人工逆向新 offset
- 方案: 利用 forge_monitor 记录封号前的 patch 失败日志，
  结合 pattern_scan 的回退命中率，自动建立 offset 更新规则库
- 效果: 版本更新后 24h 内自动适配，无需人工介入

**10. 云端 offset 分发**
- 当前: offset 硬编码在源码中，更新需重新编译
- 方案: forge daemon 启动时从私有 CDN 拉取最新 offset 配置
  （JSON 格式，SipHash 签名），无需重新部署二进制
- 效果: 即时更新，无部署窗口

---

## 五、已知不足与改进建议

### 高优先级缺陷

| 缺陷 | 影响 | 修复难度 | 状态 |
|------|------|---------|------|
| GPU hook 禁用 | 云手机 GPU 信息可能被识别 | 中 | 待修复 |
| cycle int 溢出 | 连续运行 50天+ 守护失效 | 低 | 已记录 |
| FILTER_SONAMES 未加密 | .rodata 中仍有明文 | 低 | 接受 |
| /proc/*/status 写入时机 | g_proc_status_buf 在首次读时才生成 | 低 | 接受 |

### 架构层面限制

1. **用户态天花板**: 所有防护都在用户态，内核仍能看到真实行为。
   解法: KernelSU hook（需要 root 内核）

2. **硬编码 offset 脆弱性**: libtersafe 每次更新所有 offset 失效。
   解法: pattern scan 特征码（P5 框架已就位，需填充特征值）

3. **TCP 控制面单线程**: run_tcp_server 一次只处理一个连接。
   解法: fork() 或 poll() 多路复用（当前场景单客户端，优先级低）

4. **BOT 行为模式固定**: bot_runner 的路线/坐标可被行为分析识别。
   解法: 加入深度学习驱动的行为随机化（超出当前范围）

5. **libforgehook.so 仍在 /data/app 可见**: 即使 mremap 后，
   stage_hook_so 复制的 so 文件仍存在于磁盘。
   解法: 注入后删除磁盘文件（dlopen 后文件删除 so 仍保持在内存）

---

## 六、验证检查清单

```bash
# 1. strings 检查 — 敏感字符串不应明文出现
strings /data/local/tmp/libforgehook.so | grep -i "forgehook\|qimei\|tersafe"
# 期望: 无输出 或 只有 crypt_strings.h 内已知误报

# 2. maps 检查 — 注入段应显示 [anon]
su -c 'cat /proc/<PID>/maps | grep -i "forgehook\|qimei"'
# 期望: 无输出 (mremap 已将数据段变为 [anon])

# 3. hook 激活确认
su -c 'grep "v7.1 activated" /data/local/tmp/forge_hook.log'
# 期望: 必须有此行，否则 hooks 未激活 → 必须排查

# 4. 属性伪造验证
su -c 'getprop ro.build.fingerprint'
# 期望: samsung/beyond1qltezc/beyond1q:11/...

# 5. TCP 连通性
python runner/forge_controller.py status --serial <serial>
# 期望: {"status":"ok","game_running":...}

# 6. 守护日志（patch 应在恢复后立即重写）
su -c 'tail -f /data/local/tmp/forge_repair.log'
# 期望: 有 REPAIR 记录但不应该每隔100ms都有（说明tersafe在持续对抗）
```

---

## 七、文件清单

```
DeltaForge/
├── cloud-agent/
│   ├── deploy.sh              # 编译+部署脚本 v7.1
│   ├── check.sh               # 诊断脚本
│   ├── collect_logs.sh        # 崩溃日志采集
│   ├── df-hijack-root.sh      # (已弃用) hijack 模式脚本
│   └── native/
│       ├── forge.c            # 主控守护进程 v7.1
│       ├── libforgehook.c     # 进程内拦截库 v7.1
│       ├── crypt_strings.h    # 加密字符串头文件 (P0)
│       ├── injector.c         # ptrace 注入器
│       ├── forge_monitor.c    # 文件行为监控器
│       └── touch_injector.c   # /dev/uinput 触摸注入
├── runner/
│   ├── forge_controller.py   # PC 端控制器 v7.1 (opcode+SipHash)
│   ├── bot_runner.py         # 自动化 bot (崩溃恢复版)
│   └── config/
│       ├── forge_config.json  # 配置文件
│       └── map_routes.json    # 路线配置
├── phone-app/                 # Android 端 app (辅助)
├── tools/
│   └── crypt_gen.py          # 字符串加密生成器
├── 技术总结v7.md              # 技术讲解文档
├── FINAL_SUMMARY.md           # 本文件
└── README.md
```

---

## 八、commit 历史速查

```
cc92a65  feat: P5 — TCP opcode 无痕通信
2344607  feat: P4 — 属性查询流量混淆
b8b05a8  feat: P3 — mremap 匿名重映射
48174e2  feat: P2 — 编译期垃圾指令注入
7ce3343  feat: P1 — 每次启动随机化标识符
3e03a07  fix: v7.1 — hook 激活可靠性修复 (防封号)
fff5a5a  feat: v7.0 — 全面安全与稳定性升级
6fd8054  docs: 添加 v7.0 使用报告与技术讲解
14e00ed  fix: libforgehook.c duplicate variable + orphaned comment
...
```

---

> 仓库: https://github.com/wzy887011/DeltaForge
> 最新 commit: cc92a65
> 当前版本: v8.7
