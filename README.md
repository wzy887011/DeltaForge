# DeltaForge v8.7 — 游戏运行环境适配工具

> **CTF 挑战: [CloudRunner v6.1](./CHALLENGE.md)** — Reverse Engineering / Binary Instrumentation / Mobile | 500 pts
> 仓库: github.com/wzy887011/DeltaForge | 当前基线: v8.7
> 最后更新: 2026-07-28

---

## 当前进度

| 模块 | 状态 | 说明 |
|------|------|------|
| 全局属性画像 | 本地一致 | Samsung SM-G9730 / Android 11 / SM8150；等待云机 namespace 复测 |
| TerSafe code/BSS | 部分验证 | 75 个代码点具备采集原指令；40 个 BSS 仅有地址边界约束 |
| 进程 Hook | 部分验证 | qimei 代理链及 GPU Hook 有激活日志 |
| 直接 syscall | 残余项 | 当前游戏进程 `Seccomp: 0`，inline SVC 不受 libc Hook 覆盖 |
| UE4 静态 RVA | 已隔离 | 当前 Build ID 与旧 RVA 不匹配，v8.7 默认不写入 |
| 内核/容器画像 | 改进中 | Root bind overlay 覆盖现有节点；缺失驱动节点与命名空间仍需镜像支持 |

**下一步:** 在云机冷启动执行 `verify_identity.sh` 和 collector-r2，确认 mount namespace、75 个原指令和 Hook 激活证据。

---

## 项目概述

**目标:** 云手机适配运行环境，让游戏在 root/虚拟化环境下正常运行。

**原理:** Root 驱动的系统状态 overlay + 目标进程用户态 Hook + Build ID/原指令约束的 native 写入 + 外部守护。

---

## 五层环境管理架构

```
环境检测层                    适配层
═══════════════════════════════════════════════════
L1 网络层 (IP/DNS)        →  getaddrinfo(14域名)+connect(5IP段) 双拦截
L2 系统层 (属性/cpu/GPU)   →  33个假文件memfd + GPU接口 Hook
L3 Java层 (Build/Prop)    →  JNI覆写16字段+4原生方法 + __system_property_get 70+属性
L4 内核层 (/proc/sys探测)  →  只读 bind + 进程内文件 Hook；Seccomp 当前未启用
L5 运行时层 (检测+kill)    →  75处代码表 + 40处BSS表，UE4表为空

DeltaForge 五层:
  L1 seccomp-bpf       — 当前云机采集为 Seccomp:0，保留为待回归项
  L2 maps规范化         (constructor 104+150) — mremap + r_debug link_map处理
  L3 libc PLT 拦截      (加载瞬间) — 30+函数: 文件/属性/信号/链接器/网络/GPU
  L4 Hook激活           (constructor 200) — chainload/模块范围发现，不写目标代码
  L5 外部mem调整        (forge.c) — 75代码+40BSS，Build ID 与 expected 双校验
```

---

## 文件结构

```
DeltaForge/
├── cloud-agent/
│   ├── native/
│   │   ├── forge.c              # [主控] 属性适配·文件清理·/proc/PID/mem调整·TCP server
│   │   ├── libforgehook.c       # [核心] 加载库 — seccomp/libc拦截/JNI/GPU/网络
│   │   ├── injector.c           # [加载] ptrace加载器 (兜底)
│   │   ├── forge_monitor.c      # [监控] inotify文件行为监控
│   │   ├── touch_injector.c     # [触控] /dev/uinput触摸注入
│   │   └── Makefile             # [编译] NDK交叉编译(PC端)
│   ├── deploy.sh                # [部署] 一键编译+root部署+so更新
│   ├── check.sh                 # [诊断] 拉取全部关键状态
│   ├── collect_logs.sh          # [采集] 崩溃后日志集中采集
│   ├── df-hijack-root.sh        # [安装] library 替换 — libtdmqimei.so替换
│   └── df-diagnose-root.sh      # [诊断] root侧深度诊断
├── runner/
│   ├── bot_runner.py            # [自动] 自动化测试框架 (P3待实现)
│   └── forge_controller.py      # [控制] forge TCP client
├── README.md                    # 本文档
└── 项目状态文档.md               # 详细技术文档
```

---

## 各组件作用速查

### forge.c — 外部主控
- **角色:** 游戏进程外root进程, 负责环境准备/文件清理/外部调整/持续守护
- **命令:** `-l`(一键) `-d`(daemon) `-p`(准备) `-m`(仅调整) `-s`(状态) `-c`(清理) `-x`(属性)
- **TCP server:** `127.0.0.1:9510`, JSON行协议
- **守护:** double-fork, 1s周期, 分层验证(检测链每周期/代码每3s/BSS每5s/UE4每2s)
- **调整:** JSON 中 75 个 TerSafe 代码点 + 40 个 BSS；UE4 当前为 0；Build ID + expected 原指令双校验

### libforgehook.c — 进程内拦截核心
- **加载:** 默认由 injector 在 validated patch 完成后 ptrace `dlopen`；library hijack 仅在显式 `--hijack` 时启用
- **Constructor链:** 101→102→103→104→150→170→200；200 只激活 Hook、异步 chainload 和发现模块范围
- **Libc 拦截 (30+函数):** open/openat/fopen/access/stat/lstat/readlink/readlinkat → 文件路由; tgkill/kill/exit_group → 信号管理; dlopen/dladdr/dl_iterate_phdr → 链接器管理; opendir/readdir/readdir64 → 目录过滤; getenv → 环境变量管理; getaddrinfo/connect → 网络管理; __system_property_get → 属性适配
- **JNI 适配:** Build 16字段覆写 + SystemProperties 4原生方法
- **GPU 调整:** GLES/EGL/Vulkan 接口统一返回 Adreno 640 / Qualcomm
- **r_debug 摘除:** 从 linker 模块链表删除加载库条目
- **maps 过滤:** /proc/self/maps 动态过滤返回 memfd

### injector.c — ptrace加载器
- **用途:** validated patch 完成后加载 Hook 库
- **方法:** ptrace attach → ARM64 shellcode (movz/movk) → dlopen → detach
- **关键:** process_vm_writev 仅用于远程调用桩；不持有偏移表、不写 TerSafe/UE4 代码

### deploy.sh — 一键部署
- clang编译5个二进制 → su -c执行root子脚本 → cp到 /data/local/tmp/ → 自动查找替换路径更新so → MD5校验

### check.sh — 诊断脚本
- 检查: 替换状态/文件列表/constructor日志/audit日志/tombstone/进程maps

### collect_logs.sh — 崩溃采集
- 输出: /data/local/tmp/report_<ts>.txt (forge.log+monitor.log+hook.log+seccomp+tombstone+进程)

### df-hijack-root.sh — Library 替换安装
- 游戏安装目录下: mv libtdmqimei.so → libtdmqimei_real.so, cp libforgehook.so → libtdmqimei.so
- 适配 Android 8+ linker namespace (app只能dlopen自己namespace下的so)

---

## 部署环境要求

| 条件 | 说明 |
|------|------|
| Android 云手机 | 任何品牌 (Redfinger/多多云/雷电云 等) |
| ARM64 | 游戏和SO都是 arm64-v8a |
| Root | `su -c` 可用, uid=0 |
| Termux | 提供 clang 编译 (`pkg install clang`) |
| 网络 | git pull + 游戏连腾讯服务器 |

**不需要:** Magisk, SELinux Permissive, ADB

**编译 (Termux内):**
```bash
clang -pie -Os -Wall forge.c -o forge
clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
clang -pie -Os -Wall forge_monitor.c -o forge_monitor
clang -pie -Os -Wall injector.c -o injector -ldl
clang -pie -Os -Wall touch_injector.c -o touch_injector
```

注意: 不能用 `-static` (Termux 无静态 libc)。

---

## 日常操作

```bash
# 部署
cd ~/DeltaForge && git pull && sh cloud-agent/deploy.sh

# 首次安装 library 替换 (只需一次)
su -c 'sh /data/local/tmp/df-hijack-root.sh'

# 清日志 + 一键启动
su -c 'rm -f /data/local/tmp/forge_hook.log'
su -c '/data/local/tmp/forge -l'

# 看 constructor 执行链
su -c 'cat /data/local/tmp/forge_hook.log'

# 诊断
su -c 'sh /data/local/tmp/check.sh'

# 崩溃采集
su -c 'sh /data/local/tmp/collect_logs.sh'

# seccomp 状态 (游戏活着时)
su -c 'grep Seccomp /proc/$(pidof com.tencent.tmgp.dfm)/status'
```

**期望日志链 (全部正常时):**
```
[probe] libforgehook.so loaded
[r_debug] unlinked from linker list
[gpu] glGetString patched
[gpu] eglQueryString patched
[gpu] GPU driver spoof: Adreno 640
[hooks] v8.7 activated; patch ownership=forge
[hooks] target range discovered; code writes owned by forge
```

---

## 适配数据

设备 Samsung SM-G9730 | SoC Snapdragon 855 / SM8150 | GPU Adreno 640 | Android 11 SDK 30 | user build | release-keys

---

## 版本

| commit | 内容 |
|--------|------|
| `e367fef` | v5.6 — seccomp提前到ctor(49), 检测链6节点 |
| `643c85a` | v5.7 — BPF kill(129)+delete safety+guardian 1s |
| `f6fb0b0` | P0/P1 — exit_group/dl*/r_debug/GPU/net 拦截 |
| `adecec8` | v5.8 — maps filtering+full guardian+expanded filters |
| `35a27c5` | **v5.8.1** — 移除递归 dlsym 拦截修复栈溢出 |
