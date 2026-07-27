# DeltaForge 项目汇总文档

**版本**: v8.8.3  |  **更新**: 2026-07-27  |  **仓库**: github.com:wzy887011/DeltaForge

---

## 目录

1. [项目概览](#1-项目概览)
2. [技术性细节](#2-技术性细节)
3. [云手机相关：服务及环境配置](#3-云手机相关服务及环境配置)
4. [项目进程：目前进度及未来规划](#4-项目进程目前进度及未来规划)
5. [代码管理：文件位置及推送方式](#5-代码管理文件位置及推送方式)
6. [云手机操作：命令行操作指南](#6-云手机操作命令行操作指南)

---

## 1. 项目概览

DeltaForge 是一套针对 **三角洲行动 (com.tencent.tmgp.dfm)** 的云手机反检测系统。目标是让 LXC 容器型云手机的应用层、属性层、内存层呈现与真实三星 SM-G9730 手机一致的设备环境，通过 TerSafe / GTI 双层安全检测。

**系统架构**：

```
[云手机]
  ├── Termux (编译环境)
  │   └── clang → forge / libforgehook.so / injector / forge_monitor
  │
  ├── /data/local/tmp/
  │   ├── forge          (主控守护进程)
  │   ├── libforgehook.so (LD_PRELOAD 注入库)
  │   ├── injector       (ptrace 注入器)
  │   ├── forge_monitor  (行为监控)
  │   └── forge_patches.json (偏移表，forge 启动时加载)
  │
  └── [游戏进程 com.tencent.tmgp.dfm]
      ├── LD_PRELOAD=libforgehook.so (Hook 层)
      └── forge ptrace 写入 TerSafe 内存 (Patch 层)
```

---

## 2. 技术性细节

### 2.1 检测对抗层次

| 层次 | 检测方 | 检测手段 | 我们的对策 |
|------|--------|----------|------------|
| L0 网络层 | 服务端 | 出口 IP ASN（数据中心 vs 移动运营商） | WireGuard / SOCKS5 代理（待配置） |
| L1 内核层 | TerSafe | 读 `/sys/devices/soc0/serial_number` | mount --bind 假值（LXC 无此路径，跳过） |
| L2 全局属性 | TerSafe/GTI | `getprop ro.serialno`、IMEI | resetprop 或 build.prop 直改（LXC fallback） |
| L3 身份文件 | 游戏 SDK | OAID/VAID 文件直读 | do_prepare() 随机替换 |
| L4 SSAID | TDM/QIMEI | settings_ssaid.xml per-app ID | abx2xml + sed 轮换（当前云机无该文件） |
| L5 游戏指纹缓存 | TDM/QIMEI | tdm_track.dat、login-identifier.txt 等 | 启动前 rm -rf 14+ 路径 |
| L6 TerSafe 运行时 | TerSafe | 反调试、反 hook、kKillChain 自杀 | ptrace + /proc/pid/mem 内存 patch（113处）|
| L7 进程属性 | TerSafe/GTI | __system_property_get、/proc、/sys | LD_PRELOAD libforgehook.so Hook |
| L8 LXC 容器特征 | GTI | /proc/self/mountinfo 含 lxcfs | 动态过滤行（v8.8.2+） |

### 2.2 TerSafe 绕过机制

TerSafe (`libtersafe.so`) 是腾讯自研反作弊 SDK，运行在游戏进程内，主要行为：

1. **版本绑定校验** (`verify_tersafe_version`)：检查 ELF build-id，防止偏移表版本错乱
2. **代码 patch**：67 处函数开头写 `MOV W0,#0xFF; RET`（`0x2A1F03FF`）或直接 `RET`
3. **BSS 段清零**：40 个已知偏移 + 动态扫描首 0x10000 字节，值为 1-0xFF 的 DWORD 清零
4. **kKillChain 禁用**：10 个自杀节点全部 patch 为 `RET`（`0xD65F03C0`）
5. **UE4 引擎检测**：6 处 UE4 detect 函数 patch 为 `RET`

**patch 流程**：
```
forge 启动
  → do_prepare()  [环境伪装]
  → start_game()  [am start 启动游戏]
  → wait_for_pid  [等待游戏进程出现]
  → ptrace ATTACH
  → freeze threads
  → verify_tersafe_version
  → patch tersafe code (67)
  → patch tersafe BSS (40 + sweep)
  → patch UE4 detect (6)
  → inject libforgehook.so via dlopen
  → ptrace DETACH
```

### 2.3 libforgehook.so Hook 机制

通过 `LD_PRELOAD` 注入游戏进程，拦截以下接口：

| Hook 函数 | 作用 |
|-----------|------|
| `__system_property_get` | 返回 HOOK_PROPS 表中的三星 SM-G9730 属性值 |
| `open()` / `openat()` / `fopen()` | 返回虚假 /proc 内容（cpuinfo、status、maps、mountinfo、cgroup等） |
| `getifaddrs()` | 替换 MAC 地址为 Samsung OUI（94:65:2d） |
| `ioctl(SIOCGIFHWADDR)` | 替换 MAC |
| `read()` on /proc | 过滤虚拟化特征字符串 |
| `access()` / `stat()` | HIDDEN 列表路径返回 ENOENT（隐藏 qemu/vbox/frida 文件）|
| `getdents64()` | 过滤 memfd 匿名文件 |

**HOOK_PROPS 设备画像**（Samsung Galaxy S10 SM-G9730）：

```
ro.product.manufacturer  = samsung
ro.product.model         = SM-G9730
ro.product.device        = beyond1q
ro.build.fingerprint     = samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys
ro.hardware.egl          = adreno        (v8.7 新增)
ro.soc.model             = SM8150        (Snapdragon 855)
ro.opengles.version      = 196610        (GLES 3.2)
ril.imei                 = 359825100468870
ro.serialno              = R58M74JXMWP
```

### 2.4 forge.c do_prepare() 执行顺序

```
do_prepare()
 ├── load_dyn_table()          从 forge_patches.json 加载动态偏移表
 ├── protect_devmode()
 ├── kill_suspicious_procs()
 ├── block_tdm_reporting()     iptables 阻断 TDM 上报
 ├── clean_virt_traces()       清理虚拟化痕迹
 ├── stop_game()
 ├── sleep(2)
 ├── clean_dfm_fingerprints()  [L5] 删除 14+ 个 DFM 指纹文件
 ├── clean_all_ac_files()
 ├── restore_dirs()
 ├── adapt_properties()        setprop 非 ro.* 属性
 ├── spoof_serial_bind()       [L1] mount --bind serial（LXC下跳过）
 ├── resetprop_identity()      [L2] resetprop 全局 IMEI/Serial
 │    └── 若无 resetprop → modify_props_lxc() [L2b] 直改 build.prop
 ├── spoof_oaid_vaid()         [L3] 随机写 OAID/VAID 文件
 ├── spoof_ssaid()             [L4] abx2xml 轮换 SSAID（文件不存在则跳过）
 └── settings put android_id  固定 Android ID
```

### 2.5 kKillChain 节点列表（当前）

| 节点 | 偏移 | 说明 |
|------|------|------|
| [0] | 0x419FDC | 与 TerSafe 自修复值相同，消除 GTI 翻转签名 |
| [1] | 0x419FE0 | |
| [2] | 0x2E7810 | |
| [3] | 0x2F29D0 | |
| [4] | 0x320D78 | |
| [5] | 0x3233B8 | |
| [6] | 0x36BC8C | tombstone_14 新发现 — 检测链入口 |
| [7] | 0x36BED8 | tombstone_14 中间节点 |
| [8] | 0x370D98 | tombstone_14 中间节点 |
| [9] | 0x371210 | tombstone_14 tgkill 自杀点（v8.8.3 修复）|

---

## 3. 云手机相关：服务及环境配置

### 3.1 底层架构

经 `lxcfs on /proc/meminfo type fuse.lxcfs` 确认：**当前云手机是 LXC 容器**，非物理机或 QEMU 虚拟机。

| 特性 | LXC 容器 | 物理手机 |
|------|----------|----------|
| 内核 | 共享宿主机内核 | 独立内核 |
| CPU/GPU | 宿主机透传或软渲染 | 真实 SoC |
| sysfs | 无 `/sys/devices/soc0/` | 有完整 SoC 路径 |
| TEE/TrustZone | 无 | 有 |
| 基带/SIM | 无真实基带 | 有 |
| Root 方式 | 天然 root（容器 UID 0）| Magisk/KernelSU |

### 3.2 已确认的环境信息

- **Android 版本**: Android 12 (SDK 32)
- **设备画像目标**: Samsung Galaxy S10 (SM-G9730, beyond1q, Android 11)
- **游戏 UID**: 10071
- **Termux 用户**: u0_a73
- **游戏包名**: com.tencent.tmgp.dfm
- **游戏进程**: 约1-2秒内启动，PID 动态分配
- **libtersafe.so BuildId**: d70d7926094ae39a46745c12ddcc1877641f82e8

### 3.3 环境必要条件

| 条件 | 是否满足 | 备注 |
|------|----------|------|
| Root 权限 | ✓ | 天然 LXC root |
| Termux | ✓ | 编译环境 |
| clang | ✓ | `pkg install clang` |
| patchelf | ✓ | `pkg install patchelf` |
| git | ✓ | `pkg install git` |
| resetprop | ✗ | LXC 无 Magisk，需手动部署 |
| abx2xml | ✗ | 无 settings_ssaid.xml，L4 跳过 |
| WireGuard | ✗ | L0 IP 层未配置 |

### 3.4 resetprop 安装（LXC 环境）

由于 LXC 容器无 Magisk，resetprop 需手动部署：

**方案A（PC 推送，推荐）**：
```bat
双击运行: DeltaForge-repo\runner\deploy_resetprop_pc.bat
# 自动下载 Magisk APK，提取 libmagisk64.so，push 到云机
```

**方案B（云机直接下载）**：
```bash
sh ~/DeltaForge/runner/get_resetprop.sh
# 需要 Termux 有网络，下载 ~13MB Magisk APK
```

**验证**：
```bash
su -c "/data/local/tmp/resetprop ro.serialno RTEST1234AB"
su -c "getprop ro.serialno"   # 返回 RTEST1234AB 表示成功
```

### 3.5 IP 层配置（L0，待完成）

当前云机出口是数据中心 ASN，服务端可识别。解决方案：

**PC 中继方式（PC 需在家庭/4G网络）**：
```bat
双击: runner\proxy_pc_setup.bat    # PC 端启动 gost SOCKS5 + adb reverse
```
```bash
# 云机端
su -c "sh /data/local/tmp/proxy_phone.sh start"    # HTTP 代理
su -c "sh /data/local/tmp/proxy_phone.sh status"   # 验证出口 IP
```

**WireGuard 方式（自有 VPS）**：
```bash
su -c "sh /data/local/tmp/setup_network.sh init <server_pubkey> <server_ip:port> <server_wg_ip>"
su -c "sh /data/local/tmp/setup_network.sh up"
su -c "sh /data/local/tmp/setup_network.sh check"  # 全链路泄漏检测
```

---

## 4. 项目进程：目前进度及未来规划

### 4.1 版本历史

| 版本 | Commit | 关键改动 |
|------|--------|---------|
| v8.5 | ccbe84c | TASK-01~08 全量实现：ELF 版本校验、双相轮询、UDS IPC、forge_monitor |
| v8.6 | 1d078cd | MAC/IMEI/Android ID 硬件 ID 欺骗 |
| v8.6 fix | 561a5a4 | ioctl overloadable + settings 替代 sqlite3 |
| v8.7 | f04ea65 | GPU属性补全（Adreno/SoC/GLES）+ serial 首次匹配修复 |
| v8.8 | 0b304c5 | L1-L5 深层标识伪装 + L0 网络层脚本 |
| v8.8.1 | 0523020 | 路径自适应 + resetprop standalone + PC/Phone 代理链 |
| v8.8.2 | 1251ba2 | mountinfo/cgroup LXC 过滤 + build.prop 直改 |
| v8.8.3 | e790978 | 编译错误修复 + mountinfo 行终止符 bug |
| v8.8.3+kc | c6c914c | kKillChain +4（tombstone_14 新检测路径）|

### 4.2 当前检测覆盖状态

| 层次 | 状态 | 说明 |
|------|------|------|
| L0 IP/ASN | 未配置 | 出口为数据中心 ASN，登录时服务端可见 |
| L1 内核 serial | 跳过 | LXC 无 soc0 sysfs 路径 |
| L2 全局属性 | 部分 | 无 resetprop → build.prop 直改（需remount成功）|
| L3 OAID/VAID | ✓ | 每次启动随机替换 |
| L4 SSAID | 跳过 | 云机无 settings_ssaid.xml（Android ID 已通过 L6 覆盖）|
| L5 DFM 指纹缓存 | ✓ | 14 项文件/目录清理 |
| L6 TerSafe patch | ✓ | 113 处 patch（67代码+40 BSS+6 UE4）|
| L7 HOOK_PROPS | ✓ | 进程内全覆盖（三星 SM-G9730 画像）|
| L8 LXC/mountinfo | ✓ | v8.8.2 动态过滤 lxcfs 行 |
| kKillChain | ✓ 10节点 | 含 tombstone_14 新发现的 4 个节点 |

### 4.3 已知问题

1. **游戏闪退（待验证 v8.8.3+kc）**：tombstone_14 显示 TerSafe 在 0x36BC8C 触发 tgkill，kKillChain 已补全，需重新测试
2. **全局属性未修改**：无 resetprop，libforgehook 只覆盖游戏进程内的属性读取
3. **forge.log 为空**：forge 未以正确方式启动（`-p2>&1` 无空格的 parse 问题）
4. **文件清理被禁用**：`clean_all_ac_files` 被游戏标记为 third-party plugin
5. **L0 IP**：数据中心出口未解决

### 4.4 未来规划（优先级排序）

| 优先级 | 任务 | 预计工作量 |
|--------|------|-----------|
| P0 | 重新测试 v8.8.3+kc，确认 kKillChain 修复是否解决闪退 | 立即 |
| P0 | 确认 build.prop remount 在 LXC 中是否成功（[L2b] 日志） | 立即 |
| P1 | 部署 resetprop，实现全局属性修改 | deploy_resetprop_pc.bat |
| P1 | L0 IP 配置（proxy_pc_setup.bat 或 WireGuard） | 半天 |
| P2 | tombstone_14 进一步分析（读 tombstone_14 而非 _00）| 1小时 |
| P2 | 传感器伪造（加速度计/陀螺仪非零）| 较复杂，需 HAL hook |
| P3 | bot_runner.py 替换为视觉模板匹配（PicColor 风格）| 较大 |
| P3 | Key Attestation 绕过 | 需 TrustZone，LXC 无解 |

---

## 5. 代码管理：文件位置及推送方式

### 5.1 仓库结构

```
DeltaForge-repo/
├── cloud-agent/
│   ├── native/                  核心 C 代码（ARM64 编译目标）
│   │   ├── forge.c              主控守护进程（1915 行）
│   │   ├── libforgehook.c       LD_PRELOAD 注入库（2527 行）
│   │   ├── injector.c           ptrace 注入器（625 行）
│   │   ├── forge_monitor.c      行为监控守护（325 行）
│   │   ├── touch_injector.c     触控注入辅助（153 行）
│   │   ├── patch_loader.c/h     JSON 偏移表解析（180+22 行）
│   │   ├── crypt_strings.h      字符串加密宏（168 行）
│   │   └── Makefile             编译规则（termux/host/NDK 三目标）
│   ├── magisk/                  Magisk 模块（可选）
│   ├── check.sh / deploy.sh     部署辅助脚本
│   └── df-*.sh                  诊断脚本
│
├── runner/
│   ├── forge_controller.py      forge IPC 控制器（274 行）
│   ├── bot_runner.py            自动化运行器（367 行）
│   ├── config/
│   │   ├── tersafe_patches.json 偏移表（71 节点，无需重编译更新）
│   │   └── forge_config.json    forge 配置
│   ├── setup_network.sh         L0 WireGuard 配置脚本
│   ├── proxy_pc_setup.bat       Windows PC SOCKS5 代理
│   ├── proxy_phone.sh           云机端代理配置
│   ├── get_resetprop.sh         云机自动下载 resetprop
│   ├── deploy_resetprop_pc.bat  PC 端推送 resetprop（推荐）
│   └── diagnose_device.sh       设备路径诊断
│
├── tools/
│   └── crypt_gen.py             加密字符串生成工具
│
└── DeltaForge_Project_Summary.md  本文档
```

### 5.2 关键文件说明

| 文件 | 修改频率 | 说明 |
|------|----------|------|
| `runner/config/tersafe_patches.json` | 高（每次 TerSafe 更新）| 无需重编译，仅更新此文件后重推 |
| `cloud-agent/native/forge.c` | 中 | 主控逻辑、L1-L5 伪装函数 |
| `cloud-agent/native/libforgehook.c` | 中 | Hook 表、HOOK_PROPS、/proc 过滤 |
| `cloud-agent/native/injector.c` | 低 | ptrace 注入逻辑，较稳定 |
| `runner/forge_controller.py` | 低 | Python IPC 客户端 |

### 5.3 本地 → GitHub 推送流程

```bash
# 在 Windows PC 上（DeltaForge-repo 目录）
cd "D:\下载\cc-chain-forge (3)\DeltaForge-repo"

# 1. 修改代码
# 2. 查看改动
git status
git diff

# 3. 暂存
git add cloud-agent/native/forge.c          # 精确暂存
git add runner/config/tersafe_patches.json

# 4. 提交（格式：type: description）
git commit -m "fix: 说明改动"
# 或
git commit -m "feat: 新功能描述"

# 5. 推送到 GitHub
git push origin master
```

**Commit 类型规范**：
- `feat:` 新功能
- `fix:` bug 修复
- `perf:` 性能优化
- `refactor:` 重构
- `docs:` 文档

### 5.4 tersafe_patches.json 更新（无需重编译）

偏移表与代码完全解耦，仅更新 JSON 文件即可：

```bash
# PC 上修改 runner/config/tersafe_patches.json
# 添加新的 kKillChain 节点或更新偏移
git add runner/config/tersafe_patches.json
git commit -m "fix: kKillChain +N — 新检测路径"
git push origin master

# 云机上
cd ~/DeltaForge && git pull origin master
su -c "cp runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"
# 重启 forge 即可生效，无需重编译
```

---

## 6. 云手机操作：命令行操作指南

### 6.1 日常工作流程（完整）

```bash
# === 第一步：拉取最新代码 ===
cd ~/DeltaForge && git pull origin master

# === 第二步：编译（有代码改动时）===
cd cloud-agent/native && make termux

# === 第三步：部署 ===
su -c "pkill forge; pkill forge_monitor" 2>/dev/null; sleep 1
su -c "cp $HOME/DeltaForge/cloud-agent/native/forge /data/local/tmp/forge && chmod 755 /data/local/tmp/forge"
su -c "cp $HOME/DeltaForge/cloud-agent/native/libforgehook.so /data/local/tmp/libforgehook.so && chmod 755 /data/local/tmp/libforgehook.so"
su -c "cp $HOME/DeltaForge/runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"

# === 第四步：测试（不启动游戏）===
su -c "/data/local/tmp/forge -p 2>&1"

# === 第五步：正式启动 ===
su -c "/data/local/tmp/forge -l > /data/local/tmp/forge.log 2>&1 &"
sleep 3
su -c "tail -f /data/local/tmp/forge.log"
```

### 6.2 常用单条命令

```bash
# 查看 forge 日志（最新30行）
su -c "tail -30 /data/local/tmp/forge.log"

# 检查游戏进程是否存活
su -c "pidof com.tencent.tmgp.dfm"

# 检查各层状态
su -c "getprop ro.serialno"                   # 序列号（应为 R 开头）
su -c "getprop ril.imei"                       # IMEI
su -c "settings get secure android_id"        # Android ID（应为 7a3f9b2c1d4e8f06）
su -c "cat /data/system/oaid_persistence_0"   # OAID
su -c "cat /data/local/tmp/.sn_bind"          # serial bind 内容

# 检查 resetprop 是否可用
su -c "/data/local/tmp/resetprop --version 2>&1 || echo 'not found'"

# 检查 libforgehook 注入状态
su -c "cat /proc/$(pidof com.tencent.tmgp.dfm)/maps | grep libforgehook"

# 运行设备诊断
su -c "sh /data/local/tmp/diagnose_device.sh 2>&1"

# 查看游戏 tombstone（崩溃分析）
su -c "ls -lt /data/tombstones/ | head -5"
su -c "cat /data/tombstones/tombstone_14 | head -60"
```

### 6.3 编译注意事项

| 问题 | 原因 | 解决 |
|------|------|------|
| `chmod755` 无空格 | shell 解析失败 | 必须写 `chmod 755`（有空格）|
| `-p2>&1` 无空格 | 参数解析错误，走默认 launch | 必须写 `-p 2>&1`（有空格）|
| `make termux` 失败后直接 cp | cp 了旧二进制 | 先确认编译成功再 cp |
| `pkill forge` 杀死 cp 所在 su | 同一条命令链中 kill 了自己 | 分两条 su -c 命令执行 |
| `ioctl overloadable` 编译错误 | Bionic 需要 `__attribute__((overloadable))` | 已在 v8.7 修复 |
| `modify_props_lxc undeclared` | 前向声明缺失 | 已在 v8.8.3 修复 |

### 6.4 forge 命令行参数

```bash
forge -l    # launch 模式：do_prepare + 启动游戏 + 注入（最常用）
forge -p    # prepare 模式：只执行 do_prepare，不启动游戏
forge -m    # patch 模式：只对已运行的游戏进程注入
forge -s    # status 模式：检查游戏是否在运行
forge -c    # clean 模式：清理 AC 文件
forge -d    # daemon 模式：启动 UDS 服务端（监听 IPC）
```

### 6.5 仓库拉取及编辑注意点

1. **git pull 必须在 Termux（非 su）环境执行**，否则 HOME 路径不对
2. **编译在 Termux 执行**，不用 su（clang 在 Termux 用户权限下可用）
3. **部署文件到 /data/local/tmp 需要 su**
4. **forge -l 和 forge -p 必须 su -c 执行**（需要 root 修改系统状态）
5. **forge.log 路径**：`/data/local/tmp/forge.log`，每次启动追加（`O_APPEND`）
6. **tersafe_patches.json 路径**：云机上是 `/data/local/tmp/forge_patches.json`
7. **libforgehook.so 路径**：`/data/local/tmp/libforgehook.so`（injector 硬编码此路径）

### 6.6 首次部署完整命令序列

```bash
# 安装 Termux 依赖（首次）
pkg update && pkg install git clang patchelf

# 克隆仓库
cd ~ && git clone https://github.com/wzy887011/DeltaForge.git

# 编译
cd ~/DeltaForge/cloud-agent/native && make termux

# 部署二进制
su -c "cp $HOME/DeltaForge/cloud-agent/native/forge /data/local/tmp/forge"
su -c "cp $HOME/DeltaForge/cloud-agent/native/libforgehook.so /data/local/tmp/libforgehook.so"
su -c "cp $HOME/DeltaForge/cloud-agent/native/injector /data/local/tmp/injector"
su -c "cp $HOME/DeltaForge/cloud-agent/native/forge_monitor /data/local/tmp/forge_monitor"
su -c "chmod 755 /data/local/tmp/forge /data/local/tmp/libforgehook.so"
su -c "chmod 755 /data/local/tmp/injector /data/local/tmp/forge_monitor"

# 部署偏移表
su -c "cp $HOME/DeltaForge/runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"

# 安装 resetprop（PC 端运行 deploy_resetprop_pc.bat，或）
sh ~/DeltaForge/runner/get_resetprop.sh

# 启动
su -c "/data/local/tmp/forge -l > /data/local/tmp/forge.log 2>&1 &"
sleep 5 && su -c "tail -20 /data/local/tmp/forge.log"
```

---

## 附录：快速参考卡

### 出问题时优先检查

```bash
# 1. 编译是否成功（ls -lh 看时间戳）
ls -lh ~/DeltaForge/cloud-agent/native/forge

# 2. 二进制是否最新（对比云机和 repo 的时间）
su -c "ls -lh /data/local/tmp/forge"

# 3. forge 日志
su -c "cat /data/local/tmp/forge.log"

# 4. 崩溃 tombstone
su -c "ls -lt /data/tombstones/ | head -3"
su -c "head -40 /data/tombstones/tombstone_XX"   # XX 为最新编号

# 5. 设备诊断
su -c "sh /data/local/tmp/diagnose_device.sh 2>&1 | head -50"
```

### 核心文件速查

| 用途 | 路径 |
|------|------|
| 主控程序 | `/data/local/tmp/forge` |
| Hook 库 | `/data/local/tmp/libforgehook.so` |
| 注入器 | `/data/local/tmp/injector` |
| 偏移表 | `/data/local/tmp/forge_patches.json` |
| forge 日志 | `/data/local/tmp/forge.log` |
| 诊断脚本 | `/data/local/tmp/diagnose_device.sh` |
| resetprop | `/data/local/tmp/resetprop`（需手动部署）|
| OAID | `/data/system/oaid_persistence_0` |
| VAID | `/data/system/vaid_persistence_platform` |
| Android ID | `settings get secure android_id` |
