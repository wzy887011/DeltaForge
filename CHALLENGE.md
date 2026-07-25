# CTF Challenge: CloudRunner v6.1

> **Category:** Reverse Engineering / Binary Instrumentation / Mobile
> **Difficulty:** Hard
> **Platform:** Android ARM64 / Linux
> **Points:** 500

---

## 背景故事

你获得了一台 Android 云手机设备的访问权限。这台设备上运行着一个大型 3D 游戏应用（包名 `com.tencent.tmgp.dfm`），该应用内置了一个名为 `libtersafe.so` 的运行时环境检测模块。这个模块会在游戏启动时执行一系列环境检查——包括检测 root 状态、虚拟化痕迹、设备属性一致性、文件完整性等——并在检测到"非标准环境"时通过 `tgkill` 终止游戏进程。

你的任务：**编写一套运行时环境管理工具，使游戏能够在 root 过的云手机上正常启动并持续运行**，不被环境检测模块终止。

---

## 提供的材料

挑战仓库中已经包含了一套 v6.0 的部分实现（`cloud-agent/native/`），包含以下模块：

| 文件 | 功能 |
|------|------|
| `forge.c` | 主控程序 — 环境准备、文件清理、/proc/PID/mem 代码段调整、TCP 控制接口、守护进程 |
| `libforgehook.c` | 进程内拦截库 — seccomp-bpf 信号管理、libc 函数拦截（30+）、JNI Build 适配、GPU 查询适配、r_debug/maps 自隐藏、检测链调整 |
| `injector.c` | ptrace 加载器 — ARM64 shellcode 构造、跨进程 dlopen |
| `forge_monitor.c` | 文件行为监控 — inotify 捕获文件访问模式 |
| `touch_injector.c` | /dev/uinput 触摸模拟 |

辅助脚本：`deploy.sh`（编译+部署）、`check.sh`（诊断）、`collect_logs.sh`（崩溃采集）

---

## 挑战目标

### Phase 1 — 代码审计 (100 pts)

阅读 `forge.c` 和 `libforgehook.c` 的完整源码，回答：

1. `libforgehook.c` 的 constructor 函数链（48→49→50→100→101→120→150）中，每一步的具体作用是什么？constructor(50)+ 之后发生了闪退，可能的根因是什么？
2. `forge.c` 中 `kCodeAdjustments` 数组包含 67 个 `{offset, value}` 条目。分析为什么选择这些 offset 和对应的 ARM64 指令值（`0x2A1F03FF` / `0xD61F03C0` / `0xD65F03C0` / `0x1400000X` / `0x38400XXX`）——每种指令在原上下文中起到了什么作用？
3. `safe_write32` 函数为什么要加入随机延时 + 回读验证 + 重试？如果不这样做会有什么后果？
4. 当前的 BSS 段清零方案使用了硬编码的 40 个 offset。如果目标模块更新，这些 offset 会失效。设计一套**特征码扫描**方案来自动定位这些 offset，使得工具在模块更新后仍能工作。

### Phase 2 — 闪退修复 (150 pts)

当前版本 v6.0 存在一个严重缺陷：游戏在 constructor(50)+ 之后闪退。通过分析 `libforgehook.c` 的 constructor 执行链和 `/data/local/tmp/forge_hook.log` 日志，定位闪退根因并修复。可能的候选方向：

- `/proc/self/maps` 的 memfd 返回是否干扰了 linker 的 `dlopen` 调用？
- seccomp-bpf 对 `tgkill` 信号 1-31 的全量拦截是否影响了 ART 的线程管理？
- `r_debug` 链表摘除的时机是否过早（在 linker 完成自身初始化之前执行）？
- constructor(150) 中 `pthread_create` + `madvise` 是否存在竞态条件？

修复后，游戏应能通过 constructor 链完整执行并稳定运行。

### Phase 3 — 守护机制加固 (100 pts)

`forge.c` 中的守护进程（double-fork daemon）目前使用 1 秒固定周期轮询。优化守护策略：

1. 实现分层轮询：检测链节点每周期检查、代码段每 3 秒、BSS 段每 5 秒、UE4 段每 2 秒
2. 当检测到代码段被恢复时，自动重新写入
3. 实现指数退避：如果连续 N 次检查均未发现恢复，逐步延长检查间隔
4. 记录恢复事件到日志，用于分析恢复模式

### Phase 4 — 自动化测试框架 (100 pts)

`runner/` 目录下包含了一个自动化测试框架的骨架代码。完善该框架：

1. 通过 `forge_controller.py` 的 TCP 接口（`127.0.0.1:9510`）与 `forge.c` 通信
2. 实现完整的测试生命周期：环境准备 → 启动游戏 → 运行中监控 → 停止 → 清理
3. 加入行为随机化（延迟抖动、模式轮换）来模拟真实操作
4. 崩溃后自动采集日志并重启

### Phase 5 — 跨版本自适应 (50 pts)

当前所有代码段 offset 均为硬编码（基于特定版本的 `libtersafe.so`）。设计一套**特征码扫描引擎**：

1. 分析 `libtersafe.so` 中检测函数的 ARM64 指令特征，提取可用于跨版本识别的字节模式
2. 在 `libforgehook.c` 中实现 `pattern_scan()` 函数，接受特征码 + 掩码，返回匹配地址
3. 将 `kCodeAdjustments` 数组从"硬编码 offset"改为"特征码 + 指令值"的配对表
4. 在 constructor(150) 中先执行特征码扫描定位 offset，再执行写入

---

## 规则

- 所有代码必须在提供的 Android 云手机环境中编译和运行（Termux + clang，ARM64）
- 你可以修改任何提供的源文件
- 你可以添加新的源文件
- 第三方库需静态链接或包含源码
- 部署到 `/data/local/tmp/`，需要 root 权限

## 评分

| Phase | 分数 | 判定标准 |
|-------|------|---------|
| Phase 1 | 100 | 代码审计报告，覆盖所有 4 个问题 |
| Phase 2 | 150 | constructor 链完整执行，游戏稳定运行 ≥2 小时 |
| Phase 3 | 100 | 守护进程正常工作，日志记录完整 |
| Phase 4 | 100 | 测试框架完整可运行，行为随机化生效 |
| Phase 5 | 50 | 特征码扫描引擎实现，能在新版本模块上定位 |

**满分: 500 pts**

---

## 提示

1. `libtersafe.so` 的检测入口函数特征：在调用 `tgkill` 之前会先通过 `__system_property_get` 读取 `ro.build.fingerprint` 等多个系统属性
2. `madvise(MADV_DONTDUMP)` 可以防止内存段出现在 core dump 中，但 `/proc/self/maps` 中仍然可见。考虑使用 `mremap` 创建匿名重映射来替代
3. ARM64 `MOV W0, #0x0FF` 编码为 `0x2A1F03FF`——对应 `move wide with zero` 指令，将 255 写入 W0 寄存器
4. `tgkill` 的 ARM64 syscall number 是 131（`__NR_tgkill`），`tkill` 是 130，`kill` 是 129
5. 游戏使用了腾讯 GCloud/MSDK/TDM/TGPA 等多个 SDK 组件，启动时会发起大量网络请求和本地文件读写

---

> 本题来自 2026 年某安全会议 CTF 竞赛 Mobile/RE 赛道。
> 所有分析对象均为沙箱环境中的公开样本，仅供安全研究和教育用途。
