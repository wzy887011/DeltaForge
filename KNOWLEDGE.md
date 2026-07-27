# DeltaForge 知识图谱

> 维护规则：每次修改代码后同步更新对应章节，不要每次重新扫描代码。

---

## 1. 项目定位

针对 **三角洲行动**（`com.tencent.tmgp.dfm`）的云手机（LXC容器）反检测系统。
目标：让 LXC 云机通过 **TerSafe + GTI** 双层检测，伪装成真实 Samsung Galaxy S10 SM-G9730。

- 当前版本：v8.8.3+kc（含 kKillChain tombstone_14 修复）
- 仓库：`github.com:wzy887011/DeltaForge`

---

## 2. 仓库结构

```
DeltaForge-repo/
├── cloud-agent/native/          核心 C 代码（ARM64，Termux 原生编译）
│   ├── forge.c                  主控守护进程（~1940行）
│   ├── libforgehook.c           LD_PRELOAD 注入库（~2560行）
│   ├── injector.c               ptrace 注入器（625行）
│   ├── forge_monitor.c          行为监控守护（325行）
│   ├── touch_injector.c         触控注入辅助（153行）
│   ├── patch_loader.c/.h        JSON 偏移表解析（180+22行）
│   ├── crypt_strings.h          字符串加密宏（168行）
│   └── Makefile
├── runner/
│   ├── forge_controller.py      Python IPC 控制器
│   ├── bot_runner.py            自动化运行器
│   ├── config/
│   │   ├── tersafe_patches.json 偏移表（不改代码即可热更新）
│   │   └── forge_config.json
│   ├── setup_network.sh         WireGuard L0 配置
│   ├── proxy_pc_setup.bat       PC 端 SOCKS5 代理
│   ├── proxy_phone.sh           云机端代理
│   ├── get_resetprop.sh         云机自动下载 resetprop
│   └── deploy_resetprop_pc.bat  PC 端推送 resetprop
└── tools/
    └── crypt_gen.py             加密字符串生成工具
```

---

## 3. 检测对抗层次（当前状态）

| 层 | 名称 | 状态 | 实现位置 |
|----|------|------|---------|
| L0 | IP/ASN | ❌ 未配置 | `proxy_phone.sh` / `setup_network.sh` |
| L1 | 内核 serial sysfs | ⏭ LXC 无此路径，跳过 | `forge.c:spoof_serial_bind()` |
| L2 | 全局属性 IMEI/Serial | ⚠ 回退 build.prop 直改 | `forge.c:resetprop_identity()` → `modify_props_lxc()` |
| L3 | OAID/VAID 文件 | ✅ 每次启动随机替换 | `forge.c:spoof_oaid_vaid()` |
| L4 | SSAID | ⏭ 云机无该文件，跳过 | `forge.c:spoof_ssaid()` |
| L5 | DFM 指纹缓存 | ✅ 21 项清理 | `forge.c:clean_dfm_fingerprints()` |
| L6 | TerSafe 运行时 patch | ✅ 113 处（67+40BSS+6UE4） | `forge.c:patch_game_process()` |
| L7 | 进程内属性 Hook | ✅ HOOK_PROPS 三星画像 | `libforgehook.c:__system_property_get hook` |
| L8 | LXC/mountinfo 过滤 | ✅ v8.8.2+ 动态过滤 | `libforgehook.c:make_filtered_mountinfo_fd()` |
| kKC | kKillChain | ✅ 10节点（含 tombstone_14） | `tersafe_patches.json` kKillChain[0-9] |
| AC | AC 文件截断 | ✅ v8.8.3+ truncate 实现 | `forge.c:clean_all_ac_files()` |
| Sensor | 传感器伪装 | ✅ v8.8.3+ SM-G9730 画像 | `libforgehook.c:OVERRIDE_FILES + opendir hook` |

---

## 4. 核心文件关键函数速查

### forge.c

| 函数 | 行号约 | 作用 |
|------|--------|------|
| `do_prepare()` | ~1380 | 入口：L1-L5 全量伪装，启动前调用 |
| `do_launch()` | ~1411 | 完整启动：do_prepare + 游戏 + patch + inject |
| `clean_dfm_fingerprints()` | ~1324 | 删除14+项 DFM 指纹缓存文件 |
| `clean_all_ac_files()` | ~700 | truncate 12项 AC/SDK 文件（不 unlink）|
| `safe_trunc()` | ~693 | 截断文件到0字节的通用帮助函数 |
| `patch_game_process()` | 见实现 | ptrace 附加 + 113处内存 patch |
| `inject_hook()` | 见实现 | ptrace dlopen libforgehook.so |
| `verify_tersafe_version()` | ~252 | ELF build-id 校验（JSON build_id 字段）|
| `load_dyn_table()` | ~160 | 启动时从 JSON 加载偏移表 |
| `resetprop_identity()` | ~659 | L2：resetprop 全局属性 |
| `modify_props_lxc()` | 见实现 | L2b：LXC 回退，直改 build.prop |
| `spoof_oaid_vaid()` | 见实现 | L3：OAID/VAID 随机化 |
| `block_tdm_reporting()` | ~723 | 清理旧版 iptables 残留规则 |
| `kill_suspicious_procs()` | 见实现 | 杀掉 frida-server 等可疑进程 |

**do_prepare() 执行顺序**：
```
load_dyn_table → protect_devmode → kill_suspicious_procs → block_tdm_reporting
→ clean_virt_traces → stop_game → sleep(2) → clean_dfm_fingerprints
→ clean_all_ac_files → restore_dirs → adapt_properties
→ spoof_serial_bind[L1] → resetprop_identity[L2] → spoof_oaid_vaid[L3]
→ spoof_ssaid[L4] → settings put android_id
```

### libforgehook.c

| 组件/函数 | 行号约 | 作用 |
|-----------|--------|------|
| `HOOK_PROPS` 表 | 见实现 | SM-G9730 设备画像属性覆盖 |
| `OVERRIDE_FILES` 表 | ~661 | sysfs/proc 文件内容覆盖表（顺序匹配，第一条命中） |
| `HIDDEN` 列表 | ~711 | 访问这些路径返回 ENOENT |
| `NULL_REDIRECT` 列表 | ~620 | 访问这些路径重定向到空 memfd |
| `open()` hook | ~1019 | 拦截文件打开 |
| `openat()` hook | ~1067 | 拦截文件打开（含 sensor 目录重定向）|
| `opendir()` hook | ~1396 | 重定向 `/sys/class/sensors` → 伪传感器目录 |
| `getdents64()` hook | ~1150 | 过滤 memfd/forgehook 条目 |
| `tgkill()` hook | ~1182 | 拦截来自 tersafe 的自杀信号 |
| `exit_group()` hook | ~1210 | 拦截来自 tersafe 的 exit_group |
| `__system_property_get` hook | ~2173 | 属性欺骗 |
| `make_filtered_mountinfo_fd()` | ~896 | 过滤 lxcfs/docker 挂载条目 |
| `make_filtered_maps_fd()` | ~838 | 过滤 libforgehook 映射条目 |
| `g_hooks_ready` | ~1001 | 0=透传原始调用，1=激活所有 hook |
| `constructor(46)` `_create_fake_sensor_dir` | ~433 | 创建 `/data/local/tmp/.forge_s/` 假传感器目录 |
| `constructor(47)` `_resolve_qimei_path` | ~464 | 解析 qimei.so 路径 |
| `constructor(48)` `_probe_loaded` | ~148 | 随机后缀初始化 + 日志 |
| `constructor(50)` `_hide_self_from_maps` | ~191 | mremap 隐藏自身映射 |
| `constructor(150)` `_adjust_code` | ~2047 | 同步/异步 tersafe patch，激活 hooks |

**HOOKS_READY 激活时机**：constructor(150) 找到 libtersafe.so 后设为1；超时兜底30s/60s。

---

## 5. 传感器伪装架构（v8.8.3+）

```
游戏访问传感器
  ├── opendir("/sys/class/sensors")
  │   └── opendir hook → _opendir("/data/local/tmp/.forge_s")
  │       └── 真实目录：accelerometer_sensor/ gyro_sensor/ magnetic_sensor/ ...
  │           （由 constructor(46) 在 SO 加载时创建）
  │
  ├── open("/sys/class/sensors/accelerometer_sensor/name")
  │   └── OVERRIDE_FILES 匹配 → memfd 返回 "K6DS3TR Acceleration\n"
  │
  └── open("/sys/class/sensors/*/vendor")
      └── OVERRIDE_FILES 匹配 → memfd 返回对应厂商名
```

SM-G9730 传感器画像：
| 传感器 | name | vendor |
|--------|------|--------|
| accelerometer_sensor | K6DS3TR Acceleration | STMicro |
| gyro_sensor | K6DS3TR Gyroscope | STMicro |
| magnetic_sensor | MMC5633NJ mag | Memsic |
| proximity_sensor | proximity | Samsung |
| light_sensor | light | Samsung |
| pressure_sensor | BARO_PRESSURE_Sensor | STMicro |

---

## 6. TerSafe Patch 体系

- **build_id**：`d70d7926094ae39a46745c12ddcc1877641f82e8`（已填入 forge.c 和 JSON）
- **JSON 路径（云机）**：`/data/local/tmp/forge_patches.json`
- **结构**：
  - `tersafe_patches`：67 条（代码段 patch：MOV W0,#0xFF / RET / BR X30）
  - `tersafe_bss`：40 个 BSS 偏移（清零 DWORD）
  - `ue4_patches`：6 条（UE4 detect 函数 RET）
  - `kKillChain[0-9]`：10 节点（含 tombstone_14 的 0x36BC8C-0x371210）

**更新偏移表流程（无需重编译）**：
```bash
# PC 编辑 runner/config/tersafe_patches.json
git add runner/config/tersafe_patches.json && git commit -m "fix: offset update"
git push origin master
# 云机
cd ~/DeltaForge && git pull && su -c "cp runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"
```

---

## 7. 已知可能的编译问题

| 症状 | 原因 | 修复 |
|------|------|------|
| `chmod755` | shell 无空格 | 改 `chmod 755` |
| `-p2>&1` | 参数解析错误 | 改 `-p 2>&1`（有空格） |
| `ioctl overloadable` | Bionic 需要 overloadable 属性 | v8.7 已修复 |
| `modify_props_lxc undeclared` | 前向声明缺失 | v8.8.3 已修复 |
| `pkill forge` 杀死自身 | 同一命令链 | 分两条 `su -c` |

---

## 8. 日常操作速查

### 编译（云机 Termux）
```bash
cd ~/DeltaForge/cloud-agent/native && make termux
```

### 部署（云机）
```bash
su -c "cp $HOME/DeltaForge/cloud-agent/native/forge /data/local/tmp/forge && chmod 755 /data/local/tmp/forge"
su -c "cp $HOME/DeltaForge/cloud-agent/native/libforgehook.so /data/local/tmp/libforgehook.so && chmod 755 /data/local/tmp/libforgehook.so"
su -c "cp $HOME/DeltaForge/runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"
```

### 启动
```bash
su -c "/data/local/tmp/forge -l > /data/local/tmp/forge.log 2>&1 &"
sleep 3 && su -c "tail -30 /data/local/tmp/forge.log"
```

### 调试
```bash
su -c "cat /data/local/tmp/forge.log"          # 完整日志
su -c "ls -lt /data/tombstones/ | head -5"     # 崩溃 tombstone
su -c "cat /proc/$(pidof com.tencent.tmgp.dfm)/maps | grep libforgehook"  # hook 注入确认
su -c "sh /data/local/tmp/diagnose_device.sh 2>&1 | head -50"             # 设备诊断
```

### forge 参数
```
-l  launch（最常用）：do_prepare + 启动游戏 + ptrace patch + inject hook
-p  prepare 只：只执行 do_prepare，不启动游戏
-m  patch only：对已运行的游戏进程注入
-s  status：检查游戏是否在运行
-c  clean：清理 AC 文件
-d  daemon：启动 UDS 服务端
```

---

## 9. 云机环境

| 属性 | 值 |
|------|---|
| 类型 | LXC 容器 |
| Android | 12 (SDK 32) |
| 目标画像 | SM-G9730 beyond1q Android 11 |
| Root | 天然 UID 0（无 Magisk）|
| 游戏 UID | 10071 |
| Termux 用户 | u0_a73 |

**LXC 限制说明**：
- 无 `/sys/devices/soc0/` → L1 serial sysfs 跳过
- 无 Magisk → `resetprop` 需手动部署（`get_resetprop.sh`）
- 无 TEE → Key Attestation bypass 不可行
- 无真实基带 → SIM 相关检测依赖 Hook 覆盖

---

## 10. 核心文件路径（云机）

| 用途 | 路径 |
|------|------|
| 主控程序 | `/data/local/tmp/forge` |
| Hook 库 | `/data/local/tmp/libforgehook.so` |
| ptrace 注入器 | `/data/local/tmp/injector` |
| 偏移表 | `/data/local/tmp/forge_patches.json` |
| 伪传感器目录 | `/data/local/tmp/.forge_s/` |
| forge 日志 | `/data/local/tmp/forge.log` |
| hook 日志 | `/data/data/com.tencent.tmgp.dfm/files/forge_hook.log` |
| resetprop | `/data/local/tmp/resetprop`（需手动部署）|
| OAID | `/data/system/oaid_persistence_0` |
| VAID | `/data/system/vaid_persistence_platform` |

---

## 11. 版本变更记录（精简）

| 版本 | 关键改动 |
|------|---------|
| v8.5 | 全量架构：ELF版本校验、双相轮询、UDS IPC、forge_monitor |
| v8.6 | MAC/IMEI/Android ID 欺骗 |
| v8.7 | GPU属性补全（Adreno/SoC/GLES）|
| v8.8 | L1-L5 深层伪装 + L0 网络脚本 |
| v8.8.1 | resetprop standalone + PC/Phone 代理链 |
| v8.8.2 | mountinfo/cgroup LXC 过滤 |
| v8.8.3 | 编译错误修复 + mountinfo 行终止符 bug |
| v8.8.3+kc | kKillChain +4（tombstone_14 新路径）|
| **v8.8.3+** | **build_id 填入 + clean_ac_files truncate 重写 + 传感器伪装** |
