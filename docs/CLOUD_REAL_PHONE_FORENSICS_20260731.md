# 云真机环境与伪装控制链逆向报告

- 日期：2026-07-31
- 目标：`127.0.0.1:32551` / `2505APX7BC` / Android 15 (API 35)
- 目标应用：`com.tencent.tmgp.dfm`
- 采集器：`cloud-agent/plugin_forensics_collect.sh`

## 结论

该环境不是通过普通 Magisk/Zygisk 模块把模拟器临时包装成真机，而是在系统镜像、init、属性区、SELinux、framework 插件和每进程命名空间多个层面共同投影设备身份。

上层暴露为 Xiaomi `bixi`、Qualcomm `SM8750`、verified boot green；底层设备树、DRM/NPU、CPU 和存储证据指向 Rockchip RK3588S、Mali/RKNPU 及虚拟机卷。目标应用进程中未发现明显 Frida、Zygisk 或 LSPosed 注入库，因此仅扫描应用 maps 无法识别该环境。

## 身份投影与底层矛盾

| 维度 | 对应用暴露的身份 | 底层证据 |
|---|---|---|
| 产品 | Xiaomi `bixi`, model `2505APX7BC` | Device Tree: `Rockchip RK3588S MCI K003 LP4 V10 Board` |
| SoC | `ro.hardware=qcom`, `ro.soc.model=SM8750` | `compatible=rockchip,rk3588`, `DRIVER=RKNPU` |
| GPU | Qualcomm 产品身份 | Mali/ARM gralloc、Valhall kbase，KGSL 节点缺失 |
| 启动状态 | verified boot green/locked | 自定义 root 控制面和替换系统文件存在 |
| SELinux | 运行时 `Enforcing` | cmdline: `androidboot.selinux=disabled`，另有 live policy patch 工具 |
| 存储 | Android 标准挂载视图 | `/dev/mapper/vg-vm_2`、每进程 mount namespace、tmpfs 路径投影 |

报告器稳定识别四项环境矛盾：

1. `hardware_vendor_mismatch`
2. `container_topology_visible`
3. `verified_boot_root_mismatch`
4. `selinux_state_mismatch`

## 启动与 root 控制链

`/system/etc/init/hw/init.rc` 注册：

```text
service initd /system/bin/initd
    class core
    user root
    group root shell log readproc
    seclabel u:r:shell:s0
    oneshot
```

`/system/bin/initd` 的实际启动链为：

```text
init
  -> /system/bin/initd
     -> /system/xbin/sudo root /system/bin/poweropt-service --live POLICY
     -> /system/xbin/sudo root /system/xbin/rkp_cert_processor
     -> /system/xbin/sudo root /system/xbin/bpfdomain --daemon
     -> /system/xbin/sudo root /system/bin/console_agent
     -> /system/xbin/sudo root /system/xbin/traced_kprobes
     -> dropbear SSH
     -> crond
```

关键点：

- `/system/xbin/su -> bpfdomain`。`bpfdomain` 是完整 su daemon，支持 PTY、UID/GID 切换、mount namespace 和 Unix socket 凭据。
- `resetprop` 字符串和功能表明它包含 Magisk `28.1(28100)` 代码，包括无 property_service 修改、namespace、模块与 Zygisk 相关路径。设备没有传统 `/data/adb/modules` 布局，但 Magisk 属性操作能力已被拆出并重命名部署。
- `poweropt-service` 是 live SELinux policy patch 工具，可直接读取和重新加载 `/sys/fs/selinux/policy`。
- `initd` 启动时读取 `/system/etc/selinux/asp_sepolicy.conf` 和可选的 `/data/etc/selinux/asp_sepolicy.conf`，逐条应用策略。
- `console_agent` 根据属性创建容器 TTY；Dropbear 和 cron 提供持续管理面。

## 两个伪装命名的执行守护进程

### `traced_kprobes`

该文件未表现出真实 kprobe/BPF 操作。动态导入和字符串显示它创建名为 `mount_script_socket` 的 Unix socket，接受客户端数据，并用 `popen` 执行收到的命令后回传输出。它还读取 peer socket 选项，名称 `SuperInitShGuard` 与 initd 中的 `start_super_init` 相互印证。

### `rkp_cert_processor`

该文件也不是远程密钥证明证书处理器。它创建：

```text
/data/misc/profiles/exec/sock
```

处理链为 `accept -> fork -> pipe -> dup2 -> execlp`，用于执行客户端命令并双向传输结果。运行时 socket 和进程均已观察到；真实角色与 initd 函数名 `start_container_exec` 一致。

这两个文件使用系统安全术语命名，但实现是平台控制通道。检测应依据导入、socket、进程关系和行为，而不是仅依赖文件名。

## Framework root 插件

包：`com.android.provider.root`

- `appId=1000`，共享 `android.uid.system`
- `SYSTEM | UPDATED_SYSTEM_APP | PRIVILEGED`
- 安装器：`com.android.provider.apt`，同为 UID 1000
- 导出 `com.android.dexguard.plugin.PluginModuleProvider`
- authority: `com.android.provider.root.plugin.root`
- action: `com.android.server.dexguard.action.PLUGIN_PROVIDER`
- 管理 Activity action: `android.intent.action.ROOT_MANAGE`

APK 中的 `RootModule`、`IPlugin`、`IDexGuardClient`、`PluginConfig` 和 root grant/deny 状态表明它是 system_server 的 DexGuard 插件模块。状态文件和 socket 包括：

```text
/data/misc/profiles/root/.grant.list
/data/misc/profiles/root/.root_status
/data/misc/profiles/root/.rms_socket
```

JNI 库 `liblocalSock.so` 读取 `prop.settings.ext.sock`，创建并绑定本地 socket，然后把 FD 交给 Java `LocalServerSocket`。当前属性值为 `/data/misc/profiles/root/.rms_socket`。这条链负责 root 授权和 UI/配置同步，不是目标游戏进程内注入。

## 样本哈希

| 文件 | SHA-256 |
|---|---|
| `bpfdomain` | `845b43388380c0dfabbf4932e72a62cb17f971766cb485631f989efb2e21e1e8` |
| `resetprop` | `a3d44626f8d8cc4200a2725964d5a464581af3475e72cb75eeb0257216ece436` |
| `traced_kprobes` | `163b4a0c342a60eea3aa186681e9debf2f3809476560af6a2fe9279eac98b1c8` |
| `rkp_cert_processor` | `c83bbb4092fa22fb095531a4a2b683865f8a8fb94e86239cb7979193c04aff1f` |
| `initd` | `b888e25ee02b8be06f8072fa4d57c7a60f8035ae842c55d8590f45503d4ec024` |
| `sudo` | `4cf859bc8db76b5082c209ca760d6878046a97cde155d20b15f3627f4b4798df` |
| `console_agent` | `0e6239c4d65c9072756f8afb479b3790f72b96caea3a62e54ce3a5a75e17df1f` |
| `poweropt-service` | `09dbbda175d8b65027904a04d1279d2ccb5e1ddedbc3c3119d99df3264ad1d9f` |
| `asp_sepolicy.conf` | `7dbb35577034b35c753e5d3b0d0cd3f8e10151d73a0be11a00870b9e26491d72` |
| `com.android.provider.root/base.apk` | `0eb5ff5efbe9b6beef5c449fe6571b84c697c178db304b057f59df2498c2538e` |

## 对 DeltaForge 的适用性

### 可直接加入本项目

1. 属性与底层硬件交叉验证：属性、Device Tree、DRM、NPU、GPU 节点、CPU topology 必须同时采集并建立矛盾评分。
2. verified boot、SELinux cmdline、运行时状态、live policy loader 和系统文件哈希的启动完整性关联。
3. 平台控制面检测：init rc、UID 0 守护进程、system UID provider、Unix socket、执行型导入和进程父子关系。
4. 每进程 namespace/mountinfo 差异检测，特别是 `/dev/mapper/vg-vm_*`、tmpfs 投影和应用数据路径覆盖。
5. 行为分类替代关键词分类：例如 `traced_kprobes` 应归入 privileged control plane，而不是仅凭名称判定 kernel hook。
6. 证据评分分层：目标安全库 `libtersafe.so/libTDataMaster.so` 保持低置信度，避免把游戏自身安全模块误报为伪装插件。

这些能力已加入采集器和报告器，并在该云真机上完成第二次实机回归。

### 需要系统镜像权限的部分

完整复刻该环境需要修改 product/system/vendor 镜像，并控制 init rc、平台签名或 system UID、SELinux live policy、属性区标签、framework plugin、HAL/硬件节点视图和 mount namespace。普通 APK、单个 native 插件或单纯 Zygisk 模块只能覆盖其中一部分，无法独立形成当前这种一致的系统级身份投影。

因此，DeltaForge 现阶段最可靠的提升方向是先完成跨层检测和差异报告；若后续构建自有系统镜像实验分支，再把属性投影、framework provider、namespace 和 HAL 层拆成独立模块验证。

## 回归结果

- 增强版归档 SHA-256：`e3d92e966dc86c8ee1f38a437934eb48de0d3e04e963653dde63718627857172`
- 报告候选：13
- 高置信候选：3
- 环境矛盾：4
- 测试：6 项通过
- Python 编译：通过
- POSIX shell 语法：通过
- 采集前游戏 PID：`39835`
- 采集后游戏 PID：`39835`
