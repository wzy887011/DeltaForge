# DeltaForge v8.0 — 项目进度与框架总览

> 文档生成: 2026-07-25
> 仓库: [github.com/wzy887011/DeltaForge](https://github.com/wzy887011/DeltaForge)
> 镜像: [github.com/wzy887011-cloud/DeltaForge](https://github.com/wzy887011-cloud/DeltaForge)
> 本地路径: `D:\下载\cc-chain-forge (3)\DeltaForge-repo`
> 当前分支: `master` | 最新 commit: `c8dab13`

---

## 一、仓库信息

| 项目 | 地址 |
|------|------|
| GitHub (主) | `https://github.com/wzy887011/DeltaForge` |
| GitHub (云镜像) | `https://github.com/wzy887011-cloud/DeltaForge` |
| 本地工作目录 | `D:\下载\cc-chain-forge (3)\DeltaForge-repo` |

当前分支 `master`，共 120+ commits，v3.0 → v8.0。

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
├── libforgehook.c      # 进程内注入库 v8.0 (~2180行)
├── forge.c             # 主控守护进程 v7.1
├── crypt_strings.h     # 加密字符串头文件
├── injector.c          # ptrace 远程注入器
├── forge_monitor.c     # 反作弊行为监控器
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
| **v8.0** | **c8dab13** | **FIX-A~C + NEW-1~5 全部完成** |

---

## 四、v8.0 完整变更清单

### 已全部实施并提交 (commit c8dab13)

| 编号 | 功能 | 技术细节 | 防护目标 |
|------|------|---------|---------|
| **FIX-A** | g_hooks_ready ACQUIRE原子读 | `HOOKS_READY()` 宏包装 `__atomic_load_n(..., ACQUIRE)` | ARM64弱内存序下hook提前生效 |
| **FIX-B** | constructor(50) 动态扩容 | 64KB栈→mmap 128KB→4MB循环倍增 | 大游戏进程maps截断导致mremap不完整 |
| **FIX-C** | maps/smaps无上限缓冲 | 移除2MB硬限，无限倍增到读完为止 | 超大maps残留注入痕迹 |
| **NEW-1** | statx + faccessat2 hook | `statx(291)`/`faccessat2(439)` 直接syscall拦截 | Android 5.10+/12+新syscall绕过 |
| **NEW-2** | getdents64 memfd过滤 | 自定义 `lde64_t` + 压缩目录项 | 枚举/proc/self/fd发现memfd |
| **NEW-3** | smaps_rollup + numa_maps覆盖 | `OVERRIDE_SMAPS_ROLLUP` + `OVERRIDE_NUMA_MAPS` 加入OVERRIDE_FILES | 内存布局分析+NUMA拓扑探测 |
| **NEW-4** | pattern_scan_seq多指令扫描 | n指令+掩码数组+sig_delta偏移 | 跨版本自动重定位patch点 |
| **NEW-5** | chainload后删磁盘.so | `SYS_unlinkat` 在 `dlopen` 成功后立即删除 | 扫描/data/app/发现real .so |
| **SIG** | kKillChain sig_bytes填充 | 6个offset真实设备ARM64 dump数据 | tersafe版本更新后自动重定位 |

### 仍存在的已知不足 (下个版本)

| 缺陷 | 优先级 |
|------|--------|
| GPU hook 禁用 (云手机虚拟GPU不匹配) | 中 |
| forge_monitor scan_net 读自身/proc被hook拦截 | 低 |
| cycle int 溢出 (守护连跑50天后) | 低 |
| kKillChain sig_bytes 仅当前版本有效，跨版本依赖pattern_scan_seq | 中 |

---

## 五、使用方法

### 前置条件
- Android ARM64 云手机 (已root) + Termux + NDK 26.3+

### 编译部署 (在云手机 Termux 内)

```bash
# 推送代码到设备
adb push DeltaForge-repo/cloud-agent /data/local/tmp/

# 进入 Termux，编译+部署
cd /data/local/tmp/cloud-agent
sh deploy.sh --no-hijack    # inject模式 (推荐)
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
| `/data/local/tmp/forge_hook.log` | 注入库hook日志 |
| `/sdcard/forge_hook.log` | hook日志fallback |
| `/data/local/tmp/forge_repair.log` | patch修复记录 |
| `/data/local/tmp/forge_bss_map.json` | BSS偏移缓存 |

---

## 六、commit 历史速查

```
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
> 版本: **v8.0** | commit: `c8dab13` | 分支: `master`
