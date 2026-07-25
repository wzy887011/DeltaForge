# DeltaForge v8.1 — 项目进度与框架总览

> 文档生成: 2026-07-25
> 仓库: [github.com/wzy887011/DeltaForge](https://github.com/wzy887011/DeltaForge)
> 镜像: [github.com/wzy887011-cloud/DeltaForge](https://github.com/wzy887011-cloud/DeltaForge)
> 本地路径: `D:\下载\cc-chain-forge (3)\DeltaForge-repo`
> 当前分支: `master` | 最新 commit: `df4e9dc`

---

## 一、仓库信息

| 项目 | 地址 |
|------|------|
| GitHub (主) | `https://github.com/wzy887011/DeltaForge` |
| GitHub (云镜像) | `https://github.com/wzy887011-cloud/DeltaForge` |
| 本地工作目录 | `D:\下载\cc-chain-forge (3)\DeltaForge-repo` |

当前分支 `master`，共 120+ commits，v3.0 → v8.1。

---

## 二、项目整体框架

DeltaForge 是针对 Android ARM64 云手机的**运行时环境管理工具集**，目标游戏 `com.tencent.tmgp.dfm`，绕过 `libtersafe.so` 反作弊模块。

### 五层架构

```
L1 seccomp-bpf          内核层信号管控 (23条BPF指令)
L2 /proc 伪造           内存映射自隐藏 + maps/smaps/smaps_rollup/numa_maps
L3 libc PLT hook        30+ 函数拦截 (文件/属性/信号/链接器/网络/GPU)
L4 代码 patch           检测链6节点 + 67处BSS清零 + UE4引擎
L5 外部守护             forge.c 通过 /proc/PID/mem 持续重写 + 分层轮询
```

### 核心文件

```
cloud-agent/native/
├── libforgehook.c      # 进程内注入库 v8.1 (~2250行)
├── forge.c             # 主控守护进程 v8.1
├── crypt_strings.h     # 加密字符串头文件
├── injector.c          # ptrace 远程注入器
├── forge_monitor.c     # 反作弊行为监控器 v8.1
├── touch_injector.c    # /dev/uinput 触摸注入
└── Makefile            # NDK 交叉编译 (v8.0: -DFORGEHOOK_VERSION=8)
```

---

## 三、版本演进

| 版本 | commit | 关键变更 |
|------|--------|---------|
| v6.0 | ... | BPF exit_group + GPU spoof + r_debug |
| v7.0 | fff5a5a | TCP SipHash + BSS自动扫描 + 分层守护 |
| v7.1 | 3e03a07 | hook激活三路径修复(防封号根因) |
| P1-P5 | cc92a65 | 随机标识符/JUNK_INSN/mremap/属性抖动/TCP opcode |
| v8.0 | c8dab13 | FIX-A~C + NEW-1~5 全部完成 |
| **v8.1** | **df4e9dc** | **kKillChain多指令序列 + forge_monitor syscall + cycle unsigned** |

---

## 四、v8.0 完整变更清单

### v8.0 已全部实施并提交 (commit c8dab13)

| 编号 | 功能 | 技术细节 | 防护目标 |
|------|------|---------|---------|
| FIX-A | g_hooks_ready ACQUIRE原子读 | `HOOKS_READY()` 宏包装 `__atomic_load_n(..., ACQUIRE)` | ARM64弱内存序下hook提前生效 |
| FIX-B | constructor(50) 动态扩容 | 64KB栈→mmap 128KB→4MB循环倍增 | 大游戏进程maps截断导致mremap不完整 |
| FIX-C | maps/smaps无上限缓冲 | 移除2MB硬限，无限倍增到读完为止 | 超大maps残留注入痕迹 |
| NEW-1 | statx + faccessat2 hook | `statx(291)`/`faccessat2(439)` 直接syscall拦截 | Android 5.10+/12+新syscall绕过 |
| NEW-2 | getdents64 memfd过滤 | 自定义 `lde64_t` + 压缩目录项 | 枚举/proc/self/fd发现memfd |
| NEW-3 | smaps_rollup + numa_maps覆盖 | `OVERRIDE_SMAPS_ROLLUP` + `OVERRIDE_NUMA_MAPS` 加入OVERRIDE_FILES | 内存布局分析+NUMA拓扑探测 |
| NEW-4 | pattern_scan_seq多指令扫描 | n指令+掩码数组+sig_delta偏移 | 跨版本自动重定位patch点(框架) |
| NEW-5 | chainload后删磁盘.so | `SYS_unlinkat` 在 `dlopen` 成功后立即删除 | 扫描/data/app/发现real .so |
| SIG | kKillChain sig_bytes填充 | 6个offset真实设备ARM64 dump数据 | tersafe版本更新后自动重定位 |

---

## 五、v8.1 变更清单 (commit df4e9dc)

### 已全部实施并提交

| 文件 | 改动 | 解决的问题 |
|------|------|-----------|
| `libforgehook.c` | kKillChain 结构扩展 seq_insns/seq_masks/seq_len/seq_delta 字段 | kKillChain sig_bytes 仅单指令，跨版本误命中率高 |
| `libforgehook.c` | resolve_patch_offset 升级为三级回退 | 硬编码→seq多指令→sig4单指令，定位成功率大幅提升 |
| `forge_monitor.c` | scan_net 替换为直接 syscall (openat/read/close) | 绕开 libc，减少 tersafe 通过 inotify 感知外部进程读 /proc 的面 |
| `forge.c` | cycle 计数器 int → unsigned int | 消除 signed overflow UB，防50天后未定义行为 |

### kKillChain 6节点序列特征详情

| 节点 | 序列锚点 | 掩码策略 | 稳定性 |
|------|---------|---------|--------|
| detect_entry | str w0,[sp,#0xc] + 2×BL | STR精确，BL仅匹配opcode(FC000000) | 中(STR栈偏移依赖ABI) |
| detect_entry+4 | BL + b+1 | BL掩码，b+1精确 | 高 |
| kill_dispatch | tbz w8,#0,+X + b+1 + BL | tbz掩偏移保留reg/bit，b+1精确 | 高 |
| kill_router | strb w8,[sp] + B + 2×BL | strb精确，B/BL掩码 | 中 |
| kill_wrapper | B + adrp x8 + ldr w1,[x8,?] + BL | adrp掩imm26，ldr掩imm12 | 高 |
| tgkill_call | stp Wt,?,[sp,?] + br x16 + ldrb post-idx | stp掩Rt2/imm7，br x16精确，ldrb掩reg+imm | 高(br x16为强锚点) |

---

## 六、使用方法

### 前置条件
- Android ARM64 云手机 (已root) + Termux

### 编译部署

```bash
# 在设备 Termux 内
cd ~/DeltaForge/cloud-agent/native

# 方式1：NDK 交叉编译 (推荐)
make NDK=$HOME/Android/Sdk/ndk/26.3.11579264

# 方式2：Termux 原生编译 (设备上直接运行)
make host
# 若 gcc 不可用，使用 clang：
CC=clang make host
```

### 推送代码到设备

```bash
adb push DeltaForge-repo/cloud-agent /data/local/tmp/
cd /data/local/tmp/cloud-agent/native && make host
```

### 启动游戏

```bash
# 设备端
su -c '/data/local/tmp/forge -l'

# 或 PC 端
cd runner && python forge_controller.py full
```

### 验证 hook 激活

```bash
su -c 'grep "activated" /data/local/tmp/forge_hook.log'
# 期望: "[hooks] v7.1 activated"
```

### 核心日志

| 文件 | 内容 |
|------|------|
| `/data/local/tmp/forge.log` | forge主进程日志 |
| `/data/local/tmp/forge_hook.log` | 注入库hook日志，含 `[scan] seq-match OK` / `sig4 fallback OK` |
| `/sdcard/forge_hook.log` | hook日志fallback |
| `/data/local/tmp/forge_repair.log` | patch修复记录 |
| `/data/local/tmp/forge_bss_map.json` | BSS偏移缓存 |

---

## 七、已知不足与后续计划

| 缺陷 | 优先级 | 状态 |
|------|--------|------|
| GPU hook 禁用 (云手机虚拟GPU不匹配) | 中 | 待实现：按调用方区分，仅对 libtersafe.so 调用伪造 glGetString |
| kKillChain Node1/Node4 seq含精确栈偏移 | 低 | 可进一步添加STR/STRB掩码提升ABI容忍度 |
| forge_monitor scan_net对inotify监控无根本解 | 低 | 可改为game进程内线程通过共享内存暴露net信息 |
| cycle int溢出已修复，cycle=0时三检查同时触发 | 低 | 行为变更微小，可接受 |

---

## 八、commit 历史速查

```
df4e9dc  feat: v8.1 — kKillChain多指令序列扫描 + forge_monitor syscall + cycle unsigned
c8dab13  feat: v8.0 — FIX-A~C + NEW-1~5 全部完成
fc1966e  feat: v8 — kKillChain sig_bytes 真实 ARM64 dump 填充
57ed60e  fix: P2 — add JUNK_INSN to forge.c
cc92a65  feat: P5 — TCP opcode 无痕通信
2344607  feat: P4 — 属性查询流量混淆
b8b05a8  feat: P3 — mremap 匿名重映射
48174e2  feat: P2 — 编译期垃圾指令注入
7ce3343  feat: P1 — 每次启动随机化标识符
3e03a07  fix: v7.1 — hook 激活可靠性修复 (防封号)
fff5a5a  feat: v7.0 — 全面安全与稳定性升级
```

---

> 仓库: [github.com/wzy887011/DeltaForge](https://github.com/wzy887011/DeltaForge)
> 本地: `D:\下载\cc-chain-forge (3)\DeltaForge-repo`
> 版本: **v8.1** | commit: `df4e9dc` | 分支: `master`
