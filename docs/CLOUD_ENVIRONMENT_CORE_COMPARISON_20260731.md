# 云手机与云真机底层环境审核报告

- 日期：2026-07-31
- 云手机证据 SHA-256：`85688b1bb2aefde8991698068cdbc82d9769214afce8b92fbbe5730823beb704`
- 云真机证据 SHA-256：`e3d92e966dc86c8ee1f38a437934eb48de0d3e04e963653dde63718627857172`
- 范围：硬件投影、内核、启动链、存储、namespace、SELinux、root、framework、HAL、传感器、显示、软件包和网络
- 排除：目标应用行为、游戏检测与账号风险

## 总结

两个环境都建立在 Rockchip RK3588S 云端实例之上。两端 `/proc/cpuinfo` 除序列号外完全一致，Device Tree 都明确包含 `rockchip,rk3588`。核心差异不是“一个物理真机、一个模拟器”，而是虚拟化与 Android 身份投影的实现层次不同。

云手机采用 AntDock 容器模型：overlay2 作为根文件系统，lxcfs 投影 `/proc`，`ntimespace` 管理网络 namespace，`s9su` 和脚本守护进程提供 root 控制。其 Android 属性仍泄露并混合多个 profile。

云真机采用更完整的 Android 系统镜像模型：只读 F2FS/dm-0 根分区、独立 `vg-vm_*` 数据卷、Android 15 framework、运行时 SELinux、每进程 mount namespace、system UID root provider 和专用控制 daemon。它仍是 RK3588 虚拟实例，但系统结构更接近量产 Android。

## 架构对比

| 层 | 云手机 | 云真机 |
|---|---|---|
| Device Tree | `Rockchip RK3588S AntDock V1.0 Board` | `Rockchip RK3588S MCI K003 LP4 V10 Board` |
| Compatible | `rockchip,rk3588s-antdock-v1.0`, `rockchip,rk3588` | `rockchip,rk3588` |
| CPU | 8 核 RK3588 拓扑 | 同一 CPU 拓扑，仅 serial 不同 |
| 内核 | Linux `5.10.198`, GCC 10.3, build `#42` | Linux `6.1.118-1.5.1`, Android Clang 12, PREEMPT |
| Android | Android 12 / API 32 | Android 15 / API 35 |
| 根文件系统 | overlay2，AntDock lower/upper/work layers | F2FS `/dev/block/dm-0`，只读、SELinux label |
| 数据存储 | NVMe + `vg_data-userdata` device mapper | eMMC 视图 + `vg-vm_2`/dm device mapper |
| `/proc` 投影 | `fuse.lxcfs` 覆盖 `/proc/meminfo` | 标准 procfs，无 lxcfs 记录 |
| 容器路径 | `/userdata/ant/overlay2`, `/ant/containers` | 不暴露 AntDock/LXC 路径 |
| 网络 namespace | `createns2 ntimespace`, `execns2`, `radio0@if4` | `wlan0@if175` 接入宿主 namespace |
| SELinux | runtime `Disabled` | runtime `Enforcing`，但 boot cmdline 声称 disabled |
| Verified Boot | cmdline orange | 属性 green、flash locked |
| Root 主体 | `s9su --master`, `script_guard` | `bpfdomain`, `sudo`, Magisk 28.1 `resetprop` |
| 系统控制面 | shell scripts、namespace helper、SSH/nc bridge | initd、system UID provider、Unix socket daemon、live SELinux patch |
| Framework 插件 | 未见同类 system UID root provider | `com.android.provider.root` / DexGuard `PluginModuleProvider` |
| 图形底层 | Rockchip DRM + Mali | RKNPU/Rockchip DRM + Mali |
| 显示模型 | 物理 720x1280@30，override 1080x2280@420 dpi | 720x1280，合成 20/30/60/90/120 Hz modes |
| 网络 | 172.17 容器网段、radio0、海量静态 10.x 路由 | 10.41.160.0/23，单 wlan0 veth，路由表较简洁 |

## 云手机底层结构

### 启动与容器

```text
init second_stage androidboot.hardware=ntimespace
  -> overlay2 rootfs
  -> lxcfs /proc/meminfo projection
  -> createns2 ntimespace
  -> ntimespace_router_ns / DHCP / hostapd
  -> s9su --master
  -> script_guard
  -> /system/bin/script.sh
  -> start-ssh / sshd
  -> nc listeners -> execns2
```

根 mountinfo 直接记录：

```text
overlay lowerdir=/userdata/ant/overlay2/...
upperdir=/userdata/ant/overlay2/.../diff
workdir=/userdata/ant/overlay2/.../work
fuse.lxcfs lxcfs
/ant/containers/CONTAINER_ID/hosts
```

这是一套典型的共享 RK3588 宿主 + LXC/overlay Android 容器方案。

### 存储

- 宿主视图：`nvme0n1`
- 多个 device mapper：`dm-0` 至 `dm-6`
- Android userdata：`/dev/mapper/vg_data-userdata`
- 根：overlay，可写 upper layer
- 容器 hostname、hosts、resolv.conf 从 `/ant/containers/CONTAINER_ID` 绑定

### 网络

- `wlan0`: `172.17.0.5/24`
- `radio0@if4`: `172.17.8.2/16`
- 默认路由分别指向 `172.17.0.1` 与 `172.17.8.1`
- 存在大量指向内部 10.x/223.x 地址的双路径静态路由
- `ntimespace` 负责 DHCP、hostapd、router namespace
- SSH 监听 22，另有 nc/execns2 bridge

### Root 与自动化

- `/system/xbin/s9su --master`
- `/system/xbin/script_guard`
- `/system/bin/script.sh`
- `/vendor/bin/createns2`
- `/vendor/bin/execns2`
- `/vendor/bin/start-ssh`
- `/vendor/bin/sshd`

采集时 `/data/local/tmp/frida-server-17.15.3`、mihomo、propspoof 和 DeltaForge 历史文件属于研究环境附加物，不归入云手机原生底层配置。

## 云真机底层结构

### 启动与系统镜像

```text
init
  -> F2FS /dev/block/dm-0 root
  -> Android 15 framework
  -> /system/bin/initd
     -> sudo root poweropt-service --live POLICY
     -> rkp_cert_processor
     -> bpfdomain --daemon
     -> console_agent
     -> traced_kprobes
     -> Dropbear
     -> crond
```

云真机没有在根 mountinfo 中暴露 overlay2/lxcfs。根分区为只读 F2FS，具有 SELinux label、discard、checkpoint merge 等标准 Android mount options。

### 存储

- 块设备视图：`mmcblk0` 与多个 dm logical partitions
- 根：F2FS `/dev/block/dm-0`
- 数据：ext4 `/dev/mapper/vg-vm_2`
- Android data mirror、profiles、CE/DE 目录均从同一 VM 数据卷映射
- 每个核心进程具有独立 mount namespace

该模型仍是 VM volume，而不是物理 UFS/eMMC 的完整原生布局，但比 AntDock overlay 容器更贴近 Android 动态分区与 app data namespace。

### Root 与 SELinux

- `/system/xbin/su -> bpfdomain`
- `/system/xbin/resetprop` 包含 Magisk 28.1 功能
- `/system/bin/poweropt-service` 支持 live SELinux policy patch
- `/system/bin/initd` 从 system/data 加载附加 SELinux policy
- runtime 为 Enforcing，system_server、zygote、应用均有标准 SELinux context
- boot cmdline 仍含 `androidboot.selinux=disabled`

### Framework 控制面

`com.android.provider.root` 具有 system UID、privileged/system app 标志，并向 DexGuard system service 暴露 `PluginModuleProvider`。JNI `liblocalSock.so` 读取 `prop.settings.ext.sock` 并建立 root manager socket。

两个伪装命名 daemon 的真实用途：

- `traced_kprobes`: `mount_script_socket` 命令执行服务，使用 `popen`
- `rkp_cert_processor`: `/data/misc/profiles/exec/sock`，使用 `accept/fork/dup2/execlp`

### 网络

- `wlan0@if175`: `10.41.160.48/23`
- 网关：`10.41.160.254`
- 接口 MTU 1450，表明通过宿主 veth/tunnel 接入
- 路由与 rule 数量显著少于云手机
- Dropbear 监听 22/62485，adbd 监听 5555

## 内核配置

完整标准化差异共 2,869 项。共同启用的关键能力：

```text
CONFIG_ARM64=y
CONFIG_ARCH_ROCKCHIP=y
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUPS=y
CONFIG_OVERLAY_FS=y
CONFIG_VETH=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_SELINUX=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_KPROBES=y
CONFIG_FTRACE=y
```

云手机内核还明确启用 `CONFIG_KVM=y` 和 `CONFIG_VIRTIO=y`。云真机 6.1 配置中 VirtIO PCI/MMIO/FS 均未启用，控制面更偏向定制 RK3588 内核与 device-mapper。

## 属性与硬件投影

### 云手机

核心 profile 同时包含：

```text
ro.hardware=ntimespace
ro.board.platform=rk3588
ro.product.brand=OPPO
ro.product.model=OPPO Find X2
ro.product.manufacturer=honor
ro.product.device=beyond1q
ro.product.board=msmnile
ro.build.fingerprint=samsung/beyond1qltezc/beyond1q:11/...
ro.build.version.release=12
ro.system_ext.build.fingerprint=ntimespace/rk3588_docker/...
ro.hardware.egl=mali
GL_VENDOR=Qualcomm
GL_RENDERER=Adreno (TM) 640
```

这说明配置来自多套模板叠加，没有形成单一设备 profile。

### 云真机

核心 profile 基本统一：

```text
ro.hardware=qcom
ro.boot.hardware=qcom
ro.product.brand=Xiaomi
ro.product.manufacturer=Xiaomi
ro.product.model=2505APX7BC
ro.product.device=bixi
ro.product.board=sun
ro.build.version.release=15
ro.build.version.sdk=35
ro.build.fingerprint=Xiaomi/bixi/bixi:15/...
ro.build.tags=release-keys
```

仍存在底层矛盾：`ro.hardware.egl=mali`、Device Tree RK3588、Rockchip DRM 和 RKNPU。

## HAL、显示与传感器

### 云手机

- HAL 清单 117 条标准化记录
- Bluetooth HAL 使用 `.sim`
- Gatekeeper 为 software service
- Power HAL 为 example implementation
- 传感器 profile 混合 Samsung、Qualcomm/QTI、STMicro、Bosch、AMS、AKM
- 物理显示层 720x1280@30 Hz，framework override 为 1080x2280@420 dpi

### 云真机

- HAL 清单 70 条标准化记录
- 传感器基础项以 Open Source Project 命名，并追加 Xiaomi/QTI 扩展
- 合成 20/30/60/90/120 Hz display modes
- 分辨率保持 720x1280，density 320
- DRM/RKNPU 仍来自 Rockchip

## 完整配置清单

完整输出位于 `diagnostics/environment-inventory-20260731/`：

| 文件 | 内容 |
|---|---|
| `cloud-phone-config-all.txt` | 云手机全部采集配置原文，逐文件附 bytes/SHA-256 |
| `cloud-real-phone-config-all.txt` | 云真机全部采集配置原文，逐文件附 bytes/SHA-256 |
| `cloud-phone-config.json` | 云手机原文、源文件元数据和标准化配置 |
| `cloud-real-phone-config.json` | 云真机原文、源文件元数据和标准化配置 |
| `environment-config-diff.json` | 全部结构化差异 |
| `environment-config-diff.md` | 全部可读差异表，不截断 |

输出文件 SHA-256：

```text
df2aa0e3a90803ed7aa550ed6c4ec4126869624b427aafb0019cc902ccd5e260  cloud-phone-config-all.txt
af397a5549ba38f789036de2342dd56849acc76afb6510c02d3df31fafb36c4a  cloud-phone-config.json
349a53285f5fffc6b755307931b7b5c4d780822a54c2ae4b36b2fb4d3423753b  cloud-real-phone-config-all.txt
7a0c743bfe510b3aad6500714ba5c440bc13c92f40d97b9eb9b86df681251c2b  cloud-real-phone-config.json
66c023485f835c8f66381eebe221dcede26d5910d2141228879aa90b6af6fdcd  environment-config-diff.json
14e32db32f6cf30bac482fe8afc2c13ac6513394215bf90ef70648877caa4418  environment-config-diff.md
```

当前标准化数量：

| 配置域 | 云手机 | 云真机 | 不同项 |
|---|---:|---:|---:|
| Properties | 716 | 856 | 815 |
| Kernel config | 6,193 | 5,223 | 2,869 |
| Init services | 94 | 87 | 64 |
| Processes | 112 | 117 | 145 |
| Mounts | 545 | 584 | 1,129 |
| Binder services | 212 | 257 | 262 |
| HAL records | 117 | 70 | 152 |
| Packages | 110 | 142 | 147 |
| Third-party packages | 9 | 5 | 12 |
| Network addresses | 13 | 22 | 26 |
| Network routes | 157 | 16 | 159 |
| Network rules | 81 | 12 | 75 |
| Network sockets | 22 | 11 | 31 |

云真机已通过 ADB shell domain 补齐 1,826 项 `device_config`、253 项 Android settings、91 项 features、20 项 shared libraries 和 21 项 overlay records。云手机旧归档未采集这些 Binder 配置；更新后的采集器已增加相同项目，需要重跑一次云手机清单才能形成完全对称的 framework 配置差异。
