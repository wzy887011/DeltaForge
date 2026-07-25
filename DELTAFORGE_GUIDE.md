# DeltaForge v8.3 — 完整技术指南

> 版本: v8.3 | commit: c430a10 | 最后更新: 2026-07-25

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

| 文件 | 作用 | 入口方式 |
|------|------|---------|
| `libforgehook.so` | 进程内注入库，实现L2/L3/L4 | LD_PRELOAD 或 library hijack |
| `forge` | 主控守护进程，实现L5 | 独立进程，root 运行 |
| `injector` | ptrace 注入器 | forge 调用 |
| `forge_monitor` | 行为监控器 | 独立进程 |
| `touch_injector` | 虚拟触摸输入 | 可选 |

### 2.3 注入流程

```
forge 启动
    ↓
等待游戏进程启动 (get_pid_by_name)
    ↓
injector ptrace ATTACH 游戏进程
    ↓
注入 shellcode → 调用 dlopen(libforgehook.so)
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

DeltaForge 将链上 6 个节点全部 patch 为 `RET`，阻断信号发出。

**三级回退定位机制（v8.1）**：
```
硬编码偏移验证 → 失败 → 多指令序列扫描 (pattern_scan_seq)
                       → 失败 → 单指令特征扫描 (pattern_scan4)
```

### 2.5 GPU Hook（v8.2）

caller-aware 实现，只拦截 libtersafe.so 发起的调用：

```c
// __builtin_return_address(0) 判断调用方是否在 tersafe 代码段
if (caller ∈ [g_ts_code_start, g_ts_code_end)):
    返回假 Adreno 740 信息
else:
    透传真实 GPU 值 (UE4 正常初始化渲染)
```

覆盖三条路径：
- `glGetString` (GL_RENDERER / GL_VENDOR / GL_VERSION)
- `eglQueryString` (EGL_VENDOR / EGL_VERSION)
- `vkGetPhysicalDeviceProperties` + `vkGetPhysicalDeviceProperties2`

---

## 三、框架说明

### 3.1 目录结构

```
DeltaForge/
├── cloud-agent/
│   ├── native/
│   │   ├── libforgehook.c    # 核心注入库 (~2300行)
│   │   ├── forge.c           # 守护进程主控
│   │   ├── forge_monitor.c   # 行为监控器
│   │   ├── injector.c        # ptrace 注入器
│   │   ├── touch_injector.c  # 触摸注入（可选）
│   │   ├── crypt_strings.h   # 加密字符串常量
│   │   └── Makefile
│   └── deploy.sh             # 部署脚本
├── runner/
│   └── forge_controller.py  # PC 端控制器
├── tools/
│   └── crypt_gen.py          # 字符串加密工具
├── DELTAFORGE_GUIDE.md       # 本文档
└── PROJECT_STATUS_v8.1.md   # 进度追踪
```

### 3.2 字符串加密（v7.1 P0）

所有关键路径字符串通过 `crypt_strings.h` 编译期加密，防止 `strings` 命令或 IDA 直接检索。生成工具：

```bash
python3 tools/crypt_gen.py "字符串内容"
```

### 3.3 标识符随机化（v7.1 P1）

每次启动在 constructor(48) 生成 6 位 hex 随机后缀，附加到 memfd 名/日志文件名，防多次运行指纹识别。

### 3.4 守护进程分层轮询

```
每 100ms (每周期):   检测链 6 节点验证 + 目标文件删除
每 300ms (每 3 周期): 全 67 处代码 patch 验证
每 500ms (每 5 周期): BSS 清零 40 处 + 动态补扫
每 200ms (每 2 周期): UE4 引擎 6 处 patch 验证
```

---

## 四、云手机环境要求

### 4.1 硬件要求

| 项目 | 要求 |
|------|------|
| 架构 | ARM64 (aarch64) |
| Android 版本 | Android 9+ (API 28+) |
| 内存 | 4GB+ |
| 存储 | 16GB+ 可用空间 |
| Root 状态 | **已 root**（必须） |
| Root 方案 | Magisk 或 KernelSU 均可 |

### 4.2 软件要求

| 软件 | 用途 | 安装方式 |
|------|------|---------|
| Termux | 终端环境 | F-Droid 安装（不要用 Play Store 版） |
| clang | 编译工具链 | `pkg install clang` |
| binutils | objdump 等 | `pkg install binutils` |
| llvm | llvm-objdump | `pkg install llvm` |
| git | 代码同步 | `pkg install git` |
| openssh | SSH 密钥 | `pkg install openssh` |

---

## 五、环境配置步骤

### 5.1 Termux 初始化

```bash
# 1. 换源（避免官方源速度慢）
termux-change-repo
# 选择 mirrors.tuna.tsinghua.edu.cn

# 2. 更新软件包
pkg update && pkg upgrade -y

# 3. 安装必要工具
pkg install -y clang binutils llvm git openssh python3

# 4. 配置存储权限
termux-setup-storage
# 会弹出权限申请，允许即可
```

### 5.2 SSH 密钥配置（用于 GitHub 访问）

```bash
# 生成 SSH 密钥
ssh-keygen -t ed25519 -C "your_email@example.com"
# 一路回车使用默认路径

# 查看公钥
cat ~/.ssh/id_ed25519.pub
# 复制输出，添加到 GitHub → Settings → SSH Keys
```

### 5.3 克隆仓库

```bash
# 配置 git 用户信息
git config --global user.name "your_name"
git config --global user.email "your_email@example.com"

# 克隆项目
git clone git@github.com:wzy887011/DeltaForge.git ~/DeltaForge
cd ~/DeltaForge
```

### 5.4 编译

```bash
cd ~/DeltaForge/cloud-agent/native

# Termux 原生编译（设备上直接运行）
make termux

# 预期输出（无 warning 无 error）：
# -rwx------ 1 ... 44K forge
# -rwx------ 1 ... 62K libforgehook.so
# -rwx------ 1 ... 16K forge_monitor
# -rwx------ 1 ... 12K injector
# -rwx------ 1 ... 11K touch_injector
```

### 5.5 部署

```bash
cd ~/DeltaForge/cloud-agent

# 部署（inject 模式，推荐）
su -c 'sh deploy.sh --no-hijack'

# 创建审计日志目录（sdcard 路径）
su -c 'mkdir -p /sdcard/Android/obb/com.tencent.tmgp.dfm/'
su -c 'chmod 777 /sdcard/Android/obb/com.tencent.tmgp.dfm/'
```

---

## 六、上传操作（代码推送到云端）

### 6.1 推送主仓库

```bash
cd ~/DeltaForge

# 检查状态
git status

# 暂存并提交
git add -A
git commit -m "feat: 描述改动"

# 推送
git push origin master
```

### 6.2 推送镜像仓库（cloud）

如果遇到权限错误，在 GitHub 网页操作：

1. 登录 `wzy887011-cloud` 账号
2. 进入 `wzy887011-cloud/DeltaForge` → Settings → Collaborators
3. 添加 `wzy887011` 为 Collaborator，给 Write 权限
4. 接受邀请后：

```bash
git push cloud master
```

---

## 七、云手机日常操作

### 7.1 启动游戏（完整流程）

```bash
# 方式1：设备端完整启动
su -c '/data/local/tmp/forge -l'

# 等待日志出现 "activated"
su -c 'tail -f /data/local/tmp/forge_hook.log'

# 方式2：PC 端控制器（需 adb 连接）
cd runner && python3 forge_controller.py full
```

### 7.2 验证 hook 激活

```bash
# 检查激活状态
su -c 'grep -E "activated|GPU hook|CTOR" /data/local/tmp/forge_hook.log'

# 预期输出：
# [CTOR] 120 GPU hook ACTIVE (GLES+EGL+Vulkan caller-aware)
# [hooks] v7.1 activated
```

### 7.3 查看审计日志（覆盖缺口分析）

```bash
# 查看 libforgehook 记录的未覆盖路径
su -c 'cat /sdcard/Android/obb/com.tencent.tmgp.dfm/fa.log'
# [GAP][open] /path/that/was/not/intercepted
```

### 7.4 查看 forge_monitor 报警

```bash
su -c 'tail -f /data/local/tmp/forge_monitor.log'

# 重要报警类型：
# SUSPICIOUS_LIB: 检测到可疑注入库（frida/xposed等）
# GAME_IS_TRACED: 游戏进程被 ptrace 调试
# AC_REPORT_CONN: tersafe 正在上报检测数据
# COVERAGE_GAP:   forge_audit 发现未拦截路径
```

### 7.5 日常更新拉取

```bash
cd ~/DeltaForge
git pull origin master
cd cloud-agent/native
make termux
# 重新部署
su -c 'sh ../deploy.sh --no-hijack'
```

---

## 八、日志文件说明

| 文件路径 | 内容 | 写入方 |
|----------|------|--------|
| `/data/local/tmp/forge.log` | forge 守护进程主日志 | forge.c |
| `/data/local/tmp/forge_hook.log` | 注入库运行日志（hook激活、patch结果） | libforgehook.c |
| `/sdcard/forge_hook.log` | hook日志 fallback（内部路径失败时） | libforgehook.c |
| `/data/local/tmp/forge_repair.log` | patch 修复记录（某轮被还原后的repatch记录） | forge.c |
| `/data/local/tmp/forge_bss_map.json` | BSS 偏移缓存 | forge.c |
| `/data/local/tmp/forge_monitor.log` | 行为监控报警 | forge_monitor.c |
| `/sdcard/Android/obb/.../fa.log` | 未覆盖路径审计 | libforgehook.c |

---

## 九、故障排查

### 9.1 游戏黑屏

**原因**：GPU hook 返回了错误的 GPU 能力信息给 UE4

**检查**：
```bash
grep "GPU hook" /data/local/tmp/forge_hook.log
# 应该出现: GPU hook ACTIVE (GLES+EGL+Vulkan caller-aware)
# 而非: GPU hook SKIPPED
```

**解决**：确认 libGLESv2.so / libEGL.so / libvulkan.so 已加载：
```bash
su -c 'cat /proc/$(pidof com.tencent.tmgp.dfm)/maps | grep -E "GLES|EGL|vulkan"'
```

### 9.2 hook 未激活（无 "activated" 日志）

```bash
# 检查注入是否成功
su -c 'cat /data/local/tmp/forge_hook.log | head -20'

# 检查 libforgehook.so 是否在进程内
su -c 'cat /proc/$(pidof com.tencent.tmgp.dfm)/maps | grep forgehook'
```

### 9.3 编译报错

```bash
# 清理重编
cd ~/DeltaForge/cloud-agent/native
make clean
make termux 2>&1

# 常见错误及解决：
# error: __NR_openat undefined → pkg install linux-headers
# error: -lpthread not found  → 用 make termux 而非 make host
```

### 9.4 BSS patch 失败

```bash
grep "bss" /data/local/tmp/forge_repair.log
# 如果大量 fail，说明 libtersafe 版本更新
# 需要重新 objdump 分析更新 kTersafeBssOffsets 数组
```

---

## 十、版本历史

| 版本 | 关键变更 |
|------|---------|
| v7.0 | TCP SipHash + BSS 自动扫描 + 分层守护 |
| v7.1 | hook 激活三路径修复（防封号根因）|
| P1-P5 | 随机标识符 / JUNK_INSN / mremap / 属性抖动 / TCP opcode |
| v8.0 | ACQUIRE原子读 / maps无上限缓冲 / statx+faccessat2 / getdents64 / smaps_rollup / pattern_scan_seq / chainload后删so |
| v8.1 | kKillChain 多指令序列 + forge_monitor syscall + cycle unsigned |
| v8.2 | GPU caller-aware hook (GLES+EGL+Vulkan) + BSS 动态补扫 + forge_audit 路径迁移 |
| v8.3 | 代码审查全面清理: 重复include / BSS sweep逻辑 / forge_monitor syscall一致性 / Frida/Xposed检测 |

---

## 十一、当前已知限制

| 限制 | 说明 | 影响 |
|------|------|------|
| BSS 偏移硬编码 | 40 处静态偏移，tersafe 更新后需手动重新分析 | 每次 game 大版本更新需维护 |
| seccomp-BPF 禁用 | exit_group 拦截导致 ART 崩溃，已禁用 | 由L4代码patch补偿 |
| cloud 仓库推送权限 | 需配置 collaborator 权限 | 操作层面问题 |
| forge_monitor 100ms 轮询 | 可被行为分析频率检测 | 低优先级改进项 |

---

> 仓库: https://github.com/wzy887011/DeltaForge
> 本地: `D:\下载\cc-chain-forge (3)\DeltaForge-repo`
> 版本: **v8.3** | commit: `c430a10`
