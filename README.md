# DeltaForge v5.8.1 — 三角洲行动云手机过检插件

> 仓库: github.com/wzy887011/DeltaForge | 分支: master | 最新: `35a27c5`
> 最后更新: 2026-07-24

---

## 当前进度

| 模块 | 状态 | 说明 |
|------|------|------|
| seccomp-bpf v4 | ✅ 已验证 | `r=0 errno=0 tsync=1 active=1` |
| dlsym 递归栈溢出 | ✅ 已修复 | `35a27c5` — 移除空壳 dlsym hook |
| constructor(48) probe | ✅ | 日志已出 |
| constructor(49) seccomp | ✅ | 日志已出 |
| constructor(50-150) | ❌ 待调试 | dlsym 修复后仍闪退, constructor 链中断 |
| 外部 /proc/PID/mem 113 补丁 | ✅ | 67+40+6 ok, 0 fail |
| 游戏稳定运行 | ❌ | 当前闪退 |

**下一步:** 排查 constructor(50)+ 崩溃点。候选: `/proc/self/maps` memfd 过滤干扰 linker dlopen, 或 BPF 全拦截 tgkill sig 1-31 影响 ART。

---

## 项目概述

**目标:** 云手机伪装为三星 Galaxy S10 真机，绕过腾讯 TerSafe/ACE 反作弊，运行三角洲行动不封号。

**原理:** 五层纵深防御 — seccomp-bpf(内核) → maps隐藏 → libc hooks(30+函数) → 代码补丁(119处) → 外部守护。

---

## 五层防御架构

```
TerSafe 检测层               DeltaForge 对抗层
═══════════════════════════════════════════════════
L1 网络层 (IP/DNS)        →  getaddrinfo(14域名)+connect(5IP段) 双hook
L2 系统层 (属性/cpu/GPU)   →  33个假文件memfd + GPU inline branch patch
L3 Java层 (Build/Prop)    →  JNI覆写16字段+4原生方法 + __system_property_get 70+属性
L4 内核层 (/proc/sys探测)  →  47+隐藏路径 + seccomp-bpf v4 (信号only)
L5 运行时层 (检测+kill)    →  119处补丁 + exit_group地址检测

DeltaForge 五层:
  L1 seccomp-bpf v4    (constructor 49) — kernel层信号拦截, 23条指令
  L2 maps自隐藏         (constructor 50+101) — madvise + r_debug link_map摘除
  L3 libc PLT hooks    (加载瞬间) — 30+函数: 文件/属性/信号/链接器/网络/GPU
  L4 运行时补丁         (constructor 150) — kill链6节点 inline patch
  L5 外部mem补丁        (forge.c) — /proc/PID/mem 119处 + 1s分层守护
```

---

## 文件结构

```
DeltaForge/
├── cloud-agent/
│   ├── native/
│   │   ├── forge.c              # [主控] 属性伪装·文件清理·/proc/PID/mem补丁·TCP server
│   │   ├── libforgehook.c       # [核心] 注入hook库 — seccomp/libc hooks/JNI/GPU/网络
│   │   ├── injector.c           # [注入] ptrace注入器 (兜底)
│   │   ├── forge_monitor.c      # [监控] inotify文件行为监控
│   │   ├── touch_injector.c     # [触控] /dev/uinput触摸注入
│   │   └── Makefile             # [编译] NDK交叉编译(PC端)
│   ├── deploy.sh                # [部署] 一键编译+root部署+hijack更新
│   ├── check.sh                 # [诊断] 拉取全部关键状态
│   ├── collect_logs.sh          # [采集] 崩溃后日志集中采集
│   ├── df-hijack-root.sh        # [安装] library hijack — libtdmqimei.so替换
│   └── df-diagnose-root.sh      # [诊断] root侧深度诊断
├── runner/
│   ├── bot_runner.py            # [自动] 跑刀引擎 (P3待实现)
│   └── forge_controller.py      # [控制] forge TCP client
├── README.md                    # 本文档
└── 项目状态文档.md               # 详细技术文档
```

---

## 各组件作用速查

### forge.c — 外部主控
- **角色:** 游戏进程外root进程, 负责环境准备/文件清理/外部补丁/持续守护
- **命令:** `-l`(一键) `-d`(daemon) `-p`(准备) `-m`(仅补丁) `-s`(状态) `-c`(清理) `-x`(属性)
- **TCP server:** `127.0.0.1:9510`, JSON行协议
- **守护:** double-fork, 1s周期, 分层验证(kill链每周期/代码每3s/BSS每5s/UE4每2s)
- **补丁:** 67 TerSafe代码 + 40 BSS + 6 UE4, safe_write32(随机延时+回读+重试)

### libforgehook.c — 进程内Hook核心
- **加载:** 替换游戏 libtdmqimei.so (library hijack), 游戏启动自动加载
- **Constructor链:** 48(probe)→49(seccomp)→50(maps hide)→100(chainload)→101(r_debug)→120(GPU)→150(kill链补丁)
- **Libc hooks (30+函数):** open/openat/fopen/access/stat/lstat/readlink/readlinkat → 文件路由; tgkill/kill/exit_group → 信号拦截; dlopen/dladdr/dl_iterate_phdr → 链接器隐藏; opendir/readdir/readdir64 → 目录过滤; getenv → 环境变量隐藏; getaddrinfo/connect → 网络封锁; __system_property_get → 属性伪装
- **JNI hooks:** Build 16字段覆写 + SystemProperties 4原生方法
- **GPU patch:** glGetString→Adreno 740, eglQueryString→Qualcomm (inline branch)
- **r_debug 摘除:** 从 linker 模块链表删除注入库条目
- **maps 过滤:** /proc/self/maps 动态过滤返回 memfd

### injector.c — ptrace注入器
- **用途:** hijack失败时的兜底方案, 或游戏运行后补注
- **方法:** ptrace attach → ARM64 shellcode (movz/movk) → dlopen → detach
- **关键:** process_vm_writev 跨进程写, 正确计算目标进程 dlopen 地址

### deploy.sh — 一键部署
- clang编译5个二进制 → su -c执行root子脚本 → cp到 /data/local/tmp/ → 自动查找hijack路径更新so → MD5校验

### check.sh — 诊断脚本
- 检查: hijack状态/文件列表/constructor日志/audit日志/tombstone/进程maps

### collect_logs.sh — 崩溃采集
- 输出: /data/local/tmp/report_<ts>.txt (forge.log+monitor.log+hook.log+seccomp+tombstone+进程)

### df-hijack-root.sh — Library Hijack安装
- 游戏安装目录下: mv libtdmqimei.so → libtdmqimei_real.so, cp libforgehook.so → libtdmqimei.so
- 绕 Android 8+ linker namespace (app只能dlopen自己namespace下的so)

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

# 首次安装 hijack (只需一次)
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
[seccomp] tgkill+tkill+kill blocked r=0 errno=0 tsync=1 active=1
[r_debug] unlinked from linker list
[gpu] glGetString patched
[gpu] eglQueryString patched
[gpu] GPU driver spoof: Adreno 740
[patch] waiting for libtersafe.so...
[patch] base=0x...
[patch] done: 6/6 ok
```

---

## 伪装数据

设备 Samsung SM-G9730 | SoC Snapdragon 8+ Gen1 | GPU Adreno 740 | Android 11 SDK 30 | user build | release-keys

---

## 版本

| commit | 内容 |
|--------|------|
| `e367fef` | v5.6 — seccomp提前到ctor(49), kill链6节点 |
| `643c85a` | v5.7 — BPF kill(129)+delete safety+guardian 1s |
| `f6fb0b0` | P0/P1 — exit_group/dl*/r_debug/GPU/net hooks |
| `adecec8` | v5.8 — maps filtering+full guardian+expanded filters |
| `35a27c5` | **v5.8.1** — 移除递归 dlsym hook 修复栈溢出 |
