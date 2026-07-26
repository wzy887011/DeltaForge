# DeltaForge v8.5 — 完整技术指南

> 版本: v8.5 | commit: 70fdcb0 | 最后更新: 2026-07-26

---

## 一、项目概述

### 1.1 应用场景

DeltaForge 是针对 **Android ARM64 云手机**的运行时环境管理工具集，目标游戏为腾讯 `com.tencent.tmgp.dfm`（三角洲行动）。

核心目标：在云手机虚拟化环境中，绕过游戏内置反作弊模块 `libtersafe.so` 的环境检测，使游戏在云手机上正常稳定运行，不触发封号或踢出机制。

### 1.2 解决的问题

| 问题 | tersafe 检测方式 | DeltaForge 解法 |
|------|----------------|----------------|
| 进程注入痕迹 | 扫描 /proc/self/maps | maps 伪造 + .so 文件删除 |
| 虚拟机环境特征 | 读取 CPU/设备信息 | 属性模拟 + /proc/cpuinfo 伪造 |
| GPU 型号检测 | glGetString/Vulkan API | caller-aware GPU hook |
| kill/tgkill 信号 | 检测链 6 节点执行 | 代码 patch 拦截 |
| 外部文件检测 | inotify + 目录扫描 | 目标文件定期删除 |
| 网络上报 | 连接 TDM/CrashSight | tcp连接监控报警 |

---

## 二、技术架构

### 2.1 五层防御架构

```
┌─────────────────────────────────────────────────────┐
│  L1  seccomp-BPF      内核层 syscall 过滤              │
│      ← 当前已禁用，exit_group 拦截导致 ART 崩溃        │
│      ← 由 L4 代码 patch 从源头补偿                      │
├─────────────────────────────────────────────────────┤
│  L2  /proc 伪造       43 条路径全覆盖                   │
│      maps / smaps / smaps_rollup / numa_maps         │
│      cpuinfo / status / stat / environ / net/tcp     │
├─────────────────────────────────────────────────────┤
│  L3  libc PLT hook    30+ 函数拦截                     │
│      open / openat / fopen / stat / lstat             │
│      readlink / getenv / dlopen / dlsym               │
│      glGetString / eglQueryString / vkGetPhys...     │
│      + 直接 syscall: statx / faccessat2 / getdents64 │
├─────────────────────────────────────────────────────┤
│  L4  代码 patch       检测链封堵                        │
│      6 节点 kill chain patch (kKillChain)            │
│      67 处 tersafe 代码 patch                         │
│      40 处 BSS 清零 + 动态补扫                          │
│      6 处 UE4 引擎 patch                              │
├─────────────────────────────────────────────────────┤
│  L5  外部守护          forge.c 持续监控                  │
│      100ms 轮询重推所有补丁                              │
│      目标文件定期删除 (每轮)                             │
│      forge_monitor 独立监控进程                         │
└─────────────────────────────────────────────────────┘
```

### 2.2 核心组件

| 文件 | 行数 | 作用 | 入口方式 |
|------|------|------|---------|
| `libforgehook.c` | ~2300 | 进程内注入库，实现L2/L3/L4 | ptrace dlopen 注入 |
| `forge.c` | ~1300 | 主控守护进程，实现L5 | 独立进程，root 运行 |
| `injector.c` | 612 | ptrace 注入器 v8.5 | forge 调用 |
| `forge_monitor.c` | ~300 | 行为监控器 | 独立进程 |
| `touch_injector.c` | ~150 | 虚拟触摸输入 | 可选 |
| `crypt_strings.h` | ~200 | 加密字符串常量 | 编译期混淆 |

### 2.3 注入流程 (v8.5)

```
forge 启动
    ↓
等待游戏进程启动 (get_pid_by_name)
    ↓
外部 patch tersafe 67处代码 + 40处BSS + 6处UE4 (先patch,防注入窗口)
    ↓
stage_hook_so: 复制 libforgehook.so 到游戏 app lib 目录 (绕 Android namespace)
    ↓
injector fork+execv:
  ├── PTRACE_ATTACH 主线程 + 所有其他线程 (83+ 个)
  ├── patch_kill_chain_while_paused: 6/6 节点 patch 为 RET
  ├── 解析 dlopen 地址 (dlsym → /proc/self/maps → offset → 目标 maps)
  ├── find_svc_gadget: 搜索目标 libc.so/linker64 中 SVC #0 指令
  ├── remote_syscall(mmap): ptrace 远程调用 mmap 分配 RWX 8KB
  │    回退: 若 RWX 被 SELinux 拒绝 → mmap RW → 写 shellcode → mprotect RX
  ├── 路径+shellcode 写入 RWX 内存
  ├── PC/SP 指向 RWX 内存 → PTRACE_CONT
  ├── 信号感知等待循环: SIGTRAP=完成, EINTR=重试(最多10次), SIGSEGV=诊断
  ├── dlopen(libforgehook.so) → constructor 链执行
  ├── 恢复寄存器 + PTRACE_DETACH 所有线程
    ↓
libforgehook.so 构造函数链自动执行:
  constructor(47)  → chainload 原版 qimei
  constructor(48)  → 随机后缀生成
  constructor(50)  → mremap 自隐藏
  constructor(120) → GPU hook 初始化
  constructor(150) → kKillChain patch + 激活
    ↓
forge 守护: 每 100ms 轮询重推所有补丁
```

### 2.4 kKillChain 检测链拦截

tersafe 检测到异常后沿固定调用链执行 kill：

```
detect_entry (0x419fdc)
    → kill_dispatch (0x2e7810)
    → kill_router   (0x2f29d0)
    → kill_wrapper  (0x320d78)
    → tgkill_call   (0x3233b8)
    → tgkill syscall → SIGKILL
```

DeltaForge 将链上 6 个节点全部 patch 为 `RET` (0xD65F03C0)，阻断信号发出。0x419fe0 额外补一个 NOP (0xD2800000)。

**三级回退定位机制（v8.1）**：
```
硬编码偏移验证 → 失败 → 多指令序列扫描 (pattern_scan_seq)
                       → 失败 → 单指令特征扫描 (pattern_scan4)
```

### 2.5 GPU Hook（v8.2）

caller-aware 实现，只拦截 `libtersafe.so` 发起的调用：

```c
// __builtin_return_address(0) 判断调用方是否在 tersafe 代码段
if (caller ∈ [g_ts_code_start, g_ts_code_end)):
    返回假 Adreno 740 信息
else:
    透传真实 GPU 值 (UE4 正常初始化渲染)
```

覆盖四条路径，全部标记 `__attribute__((visibility("hidden")))` 防止 dlopen 符号冲突：
- `glGetString` (GL_RENDERER / GL_VENDOR / GL_VERSION)
- `eglQueryString` (EGL_VENDOR / EGL_VERSION)
- `vkGetPhysicalDeviceProperties`
- `vkGetPhysicalDeviceProperties2`

### 2.6 injector 技术演进

| 版本 | 关键变更 | 解决的问题 |
|------|---------|-----------|
| v5.8 | 基础 ptrace + 栈 shellcode | 初始实现 |
| v8.3 | 冻结所有线程 (/proc/pid/task) | tersafe 完整性线程干扰 |
| v8.4 | 信号感知等待循环 (WSTOPSIG检测) | 单次waitpid误读x0 |
| **v8.5** | **ptrace mmap RWX + SVC#0 gadget** | **栈不可执行 (W^X) → SIGSEGV** |

**v8.5 根因发现**: ARM64 Android 严格执行 W^X，线程栈没有执行权限。旧方案把 shellcode 写到 `saved.sp - 0x300` 再设 PC → 首条指令 SIGSEGV。旧代码不检查 `WSTOPSIG`，将 `saved.x0` 中的巧合值 `-4` 误报为 "dlopen returned EINTR"——实际从未执行到 dlopen。

**v8.5 修复**: 
1. `find_svc_gadget()` — 扫描目标 libc.so/linker64 的 text 段，找到 `SVC #0` (0xD4000001) 指令
2. `remote_syscall()` — 用 `PTRACE_SYSCALL` 在目标进程执行任意 syscall（syscall-enter/exit 各停一次）
3. `remote_syscall(mmap, PROT_RWX)` 分配 8KB 可执行内存（若 SELinux 拒绝则回退 mmap RW → 写 → mprotect RX）
4. shellcode + 路径字符串写入 RWX 内存 → PC/SP 指向新区域 → 执行

### 2.7 守护进程分层轮询

```
每 100ms (每周期):   检测链 6 节点验证 + 目标文件删除
每 300ms (每 3 周期): 全 67 处代码 patch 验证
每 500ms (每 5 周期): BSS 清零 40 处 + 动态补扫
每 200ms (每 2 周期): UE4 引擎 6 处 patch 验证
```

---

## 三、项目文件位置

### 3.1 仓库地址

| 远程 | URL |
|------|-----|
| **origin (主)** | `git@github.com:wzy887011/DeltaForge.git` |
| cloud (镜像) | `git@github.com:wzy887011-cloud/DeltaForge.git` |

当前分支: `master` | 最新 commit: `70fdcb0`

### 3.2 本地路径

| 位置 | 路径 |
|------|------|
| **Windows 开发机** | `D:\下载\cc-chain-forge (3)\DeltaForge-repo\` |
| **云手机 Termux** | `/data/data/com.termux/files/home/DeltaForge/` |
| **部署目标** | `/data/local/tmp/forge` 等 |

### 3.3 目录结构

```
DeltaForge/
├── cloud-agent/
│   ├── native/
│   │   ├── libforgehook.c      # 核心注入库 (~2300行, ~99KB)
│   │   ├── forge.c             # 守护进程主控 (~1300行, ~53KB)
│   │   ├── forge_monitor.c     # 行为监控器 (~300行, ~11KB)
│   │   ├── injector.c          # ptrace 注入器 v8.5 (612行, ~24KB)
│   │   ├── touch_injector.c    # 触摸注入（可选,~150行）
│   │   ├── crypt_strings.h     # 加密字符串常量 (~200行)
│   │   └── Makefile
│   ├── deploy.sh               # 部署脚本 (编译+复制+权限)
│   ├── check.sh                # 部署后诊断
│   ├── collect_logs.sh         # 日志收集
│   ├── df-deploy-root.sh       # root 部署子脚本
│   ├── df-diagnose-root.sh     # root 诊断
│   ├── df-hijack-root.sh       # hijack so 替换 (已弃用)
│   ├── forge-control.sh        # forge 控制脚本
│   └── magisk/                 # Magisk 模块
├── runner/
│   ├── forge_controller.py     # PC 端控制器
│   ├── bot_runner.py           # Bot 自动化
│   └── config/                 # 配置文件
├── tools/
│   └── crypt_gen.py            # 字符串加密生成工具
└── DELTAFORGE_GUIDE.md         # 本文档
```

### 3.4 运行时文件

| 文件路径 | 内容 | 写入方 |
|----------|------|--------|
| `/data/local/tmp/forge` | 守护进程 (45K) | deploy.sh |
| `/data/local/tmp/libforgehook.so` | 注入库 (65K) | deploy.sh |
| `/data/local/tmp/injector` | ptrace 注入器 (14K) | deploy.sh |
| `/data/local/tmp/forge_monitor` | 行为监控 (17K) | deploy.sh |
| `/data/local/tmp/touch_injector` | 触摸注入 (11K) | deploy.sh |
| `/data/local/tmp/forge.log` | forge 主日志 + injector 诊断 | forge.c |
| `/data/local/tmp/forge_hook.log` | hook 内部日志 | libforgehook.c |
| `/data/local/tmp/forge_repair.log` | patch 修复记录 | forge.c |
| `/data/local/tmp/forge_bss_map.json` | BSS 偏移缓存 | forge.c |
| `/data/local/tmp/forge_monitor.log` | 行为监控报警 | forge_monitor.c |
| `/data/local/tmp/forge.version` | 版本戳 | deploy.sh |
| `/data/local/tmp/forge_build.md5` | 编译校验和 | deploy.sh |
| `/sdcard/Android/obb/com.tencent.tmgp.dfm/fa.log` | 未覆盖路径审计 | libforgehook.c |

---

## 四、云手机环境

### 4.1 硬件要求

| 项目 | 要求 |
|------|------|
| 架构 | ARM64 (aarch64) |
| Android 版本 | Android 9+ (API 28+) |
| 内存 | 4GB+ |
| 存储 | 16GB+ 可用空间 |
| Root 状态 | **已 root**（必须） |
| Root 方案 | Magisk 或 KernelSU 均可 |

### 4.2 Termux 初始化

```bash
# 1. 换源
termux-change-repo
# 选择 mirrors.tuna.tsinghua.edu.cn

# 2. 更新软件包
pkg update && pkg upgrade -y

# 3. 安装必要工具
pkg install -y clang binutils llvm git openssh python3 patchelf

# 4. 配置存储权限
termux-setup-storage
```

### 4.3 SSH 密钥 (GitHub)

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub
# 复制到 GitHub → Settings → SSH Keys
```

### 4.4 克隆仓库

```bash
git config --global user.name "your_name"
git config --global user.email "your_email@example.com"
git clone git@github.com:wzy887011/DeltaForge.git ~/DeltaForge
cd ~/DeltaForge
```

---

## 五、上传与部署

### 5.1 从 Windows 开发机推送

```bash
cd "D:\下载\cc-chain-forge (3)\DeltaForge-repo"

# 查看状态
git status
git diff

# 暂存并提交
git add -A
git commit -m "fix: 描述改动"

# 推送到主仓库
git push origin master

# 推送到镜像仓库（如果权限允许）
git push cloud master
```

### 5.2 云手机拉取编译部署 (推荐)

```bash
# 1. SSH 到云手机 Termux 或在 Termux 中直接操作
cd ~/DeltaForge && git pull origin master

# 2. 编译
cd cloud-agent/native && make clean && make termux

# 3. 杀掉旧进程
su -c 'killall forge forge_monitor com.tencent.tmgp.dfm 2>/dev/null'

# 4. 复制到部署目录
su -c "cp $PWD/forge /data/local/tmp/forge"
su -c "cp $PWD/injector /data/local/tmp/injector"
su -c "cp $PWD/libforgehook.so /data/local/tmp/libforgehook.so"
su -c "cp $PWD/forge_monitor /data/local/tmp/forge_monitor"

# 5. 确认文件
su -c 'ls -lh /data/local/tmp/forge /data/local/tmp/injector /data/local/tmp/libforgehook.so'

# 6. 清空日志 (可选)
su -c 'echo "" > /data/local/tmp/forge.log'

# 7. 启动 (两个窗口建议)
# 窗口1: su -c 'tail -f /data/local/tmp/forge.log'
# 窗口2: su -c '/data/local/tmp/forge -l'
```

### 5.3 使用 deploy.sh (备选)

```bash
cd ~/DeltaForge/cloud-agent
su -c 'sh deploy.sh --no-hijack'
# deploy.sh 自动编译 + 复制 + 设权限
# --no-hijack: 使用 inject 模式而非 hijack so 替换
```

### 5.4 验证注入成功

```bash
# 检查日志中的注入结果
su -c 'grep -E "dlopen returned|注入完成|SVC #0|mmap RWX|hook 库加载" /data/local/tmp/forge.log'

# 检查 hook 是否激活
su -c 'grep "activated" /data/local/tmp/forge_hook.log 2>/dev/null || grep "activated" /data/local/tmp/forge.log'

# 检查 libforgehook.so 是否在游戏进程内
su -c "cat /proc/\$(pidof com.tencent.tmgp.dfm)/maps | grep forgehook"
```

### 5.5 推送镜像仓库 (cloud)

如果遇到权限错误：
1. 登录 `wzy887011-cloud` GitHub 账号
2. 进入 `wzy887011-cloud/DeltaForge` → Settings → Collaborators
3. 添加 `wzy887011` 为 Collaborator，给 Write 权限
4. 接受邀请后重试 `git push cloud master`

---

## 六、日志与诊断

### 6.1 关键日志模式

**注入成功**:
```
[*] SVC #0 gadget @ 0x76fffce0xx
[+] mmap RWX @ 0x7xxxxxxxxx
[*] dlopen returned x0=0x7xxxxxxxxx (OK)
[+] 注入完成 — libforgehook.so handle=0x7xxxxxxxxx
```

**SELinux 拒绝 RWX (回退路径)**:
```
[*] mmap RW @ 0x7xxxxxxxxx (需 mprotect→RX)
[+] mprotect→RX OK
[*] dlopen returned x0=0x7xxxxxxxxx (OK)
```

**SIGSEGV (栈 NX — v8.4 及之前)**:
```
[-] SIGSEGV at pc=0x7fe0fd7a40, x0=0xfffffffffffffffc — shellcode crash
```
→ 已由 v8.5 修复。不应再出现。

**EINTR 重试 (dlopen 内部 syscall 被中断)**:
```
[*] 信号 17 (SIGCHLD) at pc=0x..., x0=0xfffffffffffffffc
[*] EINTR 重试 1/10
[*] dlopen returned x0=0x7xxxxxxxxx (OK)
```

**进程被云手机后台杀死**:
```
[-] 目标进程被信号 9 (Killed) 杀死
```
→ 保持游戏在前台，不要切换到 Termux。

**外部 patch 被还原 (forge 守护中)**:
```
[!] patch reverted off=0x419fdc cur=0x97fb3560 — repatch
```
→ 正常现象。forge 每轮自动重推。如果 hook 已加载则不应出现。

---

## 七、故障排查

### 7.1 游戏闪退

1. 先看 `forge.log` 中注入部分（从 `PID=` 到 `注入完成` 或 `失败`）
2. 如果 `SIGSEGV` → injector 版本不是 v8.5,重新拉取编译
3. 如果 `目标进程被信号 9 杀死` → 云手机后台杀进程,保持游戏前台
4. 如果 `mmap 失败` → SELinux 策略太严,检查 `getenforce`,尝试 `setenforce 0`
5. 如果 `SVC #0 gadget` 找不到 → 目标 libc.so 结构异常

### 7.2 hook 未激活

```bash
# 检查注入是否成功
su -c 'grep "注入完成" /data/local/tmp/forge.log'

# 检查 libforgehook.so 是否在进程内
su -c "cat /proc/\$(pidof com.tencent.tmgp.dfm)/maps | grep forgehook"

# 检查 constructor 日志
su -c 'grep "CTOR\|activated\|GPU hook" /data/local/tmp/forge.log'
```

### 7.3 编译报错

```bash
cd ~/DeltaForge/cloud-agent/native
make clean && make termux 2>&1

# 常见错误:
# patchelf not found → pkg install patchelf
# clang not found   → pkg install clang
# -lpthread not found → 用 make termux 而非 make host
```

### 7.4 BSS patch 失败

```bash
grep "bss" /data/local/tmp/forge_repair.log
# 如果大量 fail → libtersafe 版本更新 → 需要重新 objdump 分析更新偏移数组
```

---

## 八、版本历史

| 版本 | 关键变更 |
|------|---------|
| v7.0 | TCP SipHash + BSS 自动扫描 + 分层守护 |
| v7.1 | hook 激活三路径修复（防封号根因）|
| P1-P5 | 随机标识符 / JUNK_INSN / mremap / 属性抖动 / TCP opcode |
| v8.0 | ACQUIRE原子读 / maps无上限缓冲 / statx+faccessat2 / getdents64 / smaps_rollup / pattern_scan_seq / chainload后删so |
| v8.1 | kKillChain 多指令序列 + forge_monitor syscall + cycle unsigned |
| v8.2 | GPU caller-aware hook (GLES+EGL+Vulkan) + BSS 动态补扫 + forge_audit 路径迁移 |
| v8.3 | 代码审查全面清理: 重复include / BSS sweep逻辑 / forge_monitor syscall一致性 / Frida/Xposed检测 / 调换注入顺序 / 冻结所有线程 |
| v8.4 | injector 信号感知等待循环 — WSTOPSIG 检测 + WIFSIGNALED + EINTR 重试 + SIGSEGV 诊断 |
| **v8.5** | **ptrace mmap RWX — 根除栈不可执行导致的 SIGSEGV + find_svc_gadget + remote_syscall** |

---

## 九、当前已知限制

| 限制 | 说明 | 影响 |
|------|------|------|
| BSS 偏移硬编码 | 40 处静态偏移，tersafe 更新后需手动重新分析 | 每次 game 大版本更新需维护 |
| seccomp-BPF 禁用 | exit_group 拦截导致 ART 崩溃，已禁用 | 由L4代码patch补偿 |
| SELinux RWX 可能拒绝 | 部分云手机可能不允许匿名 RWX 映射 | v8.5 有 RW→mprotect RX 回退路径 |
| 云手机后台杀进程 | 切换 Termux 时游戏可能被系统 SIGKILL | 保持游戏前台 + 用 --auto 模式 |

---

> 仓库: https://github.com/wzy887011/DeltaForge
> 本地: `D:\下载\cc-chain-forge (3)\DeltaForge-repo`
> 云手机: `/data/data/com.termux/files/home/DeltaForge/`
> 版本: **v8.5** | commit: `70fdcb0`
