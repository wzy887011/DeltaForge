# DeltaForge 操作手册 v1.0
**更新**: 2026-07-28 | **版本**: v8.9+kc15

---

## 1. 项目概览

### 1.1 目标
针对三角洲行动 (`com.tencent.tmgp.dfm`) 的云手机（LXC容器）反检测系统。让优达云云机通过 TerSafe / GTI 双层安全检测，伪装成真实三星 SM-G9730 设备。

### 1.2 技术栈

| 层次 | 技术 | 状态 |
|------|------|------|
| L0 IP/ASN | mihomo + 快代理 SOCKS5 + iptables路由 | ✅ 运行中 |
| L2 全局属性 | resetprop (Magisk独立版) | ✅ ok=65 fail=0 |
| L3 身份文件 | OAID/VAID/IMEI/Serial随机化 | ✅ |
| L5 DFM指纹 | forge do_prepare() 清理 | ✅ |
| L6 TerSafe patch | ptrace + /proc/pid/mem | ✅ 75 ok/0 fail |
| L7 进程内Hook | libforgehook.so LD_PRELOAD | ✅ 注入+隐藏 |
| L8 LXC特征 | mountinfo过滤 | ✅ |
| kKillChain | 15节点全patch | ✅ |

---

## 2. 文件位置

### 2.1 本地文件（Windows PC）

```
D:\下载\cc-chain-forge (3)\DeltaForge-repo\
├── cloud-agent/native/          # 核心 C 代码（ARM64编译目标）
│   ├── forge.c                  # 主控守护进程 v8.9
│   ├── libforgehook.c           # LD_PRELOAD Hook库
│   ├── injector.c               # ptrace 注入器（实栈修复版）
│   ├── forge_monitor.c          # 行为监控
│   └── Makefile
├── runner/
│   ├── config/
│   │   ├── tersafe_patches.json # 偏移表（75节点，无需重编译更新）
│   │   ├── forge_config.json
│   │   └── deltaforge_proxy.yaml # Clash代理配置（快代理）
│   ├── socks5_proxy.py          # PC端SOCKS5代理（带auth+限速）
│   ├── proxy_pc_setup.bat       # PC端代理启动脚本
│   └── get_resetprop.sh         # 云机resetprop安装脚本
├── tools/
│   └── crypt_gen.py
├── KNOWLEDGE.md                 # 项目知识图谱
├── OPERATIONS_GUIDE.md          # 本文档
└── DeltaForge_Project_Summary.md # 技术汇总
```

### 2.2 云仓库（GitHub）

```
仓库: https://github.com/wzy887011/DeltaForge
分支: master
关键文件 Raw URL 前缀: https://raw.githubusercontent.com/wzy887011/DeltaForge/master/
```

重要文件直链：
- 偏移表: `https://raw.githubusercontent.com/wzy887011/DeltaForge/master/runner/config/tersafe_patches.json`
- Clash配置: `https://raw.githubusercontent.com/wzy887011/DeltaForge/master/runner/config/deltaforge_proxy.yaml`

### 2.3 云手机（优达云 YD010037215036）文件

```
/data/local/tmp/
├── forge              # 主控二进制
├── libforgehook.so    # Hook库
├── injector           # 注入器
├── forge_monitor      # 监控
├── forge_patches.json # 偏移表（从tersafe_patches.json复制）
├── resetprop          # Magisk resetprop独立版
├── forge.log          # 运行日志
├── detect_now.log     # 检测监控日志
├── mihomo             # Clash-Meta代理二进制
├── clash-config.yaml  # mihomo配置
└── mihomo-home/       # mihomo工作目录

/data/data/com.termux/files/home/DeltaForge/  # 代码仓库（通过git clone）
```

---

## 3. 操作指南

### 3.1 PC端代码修改 → 推送云仓库

```cmd
# 在 D:\下载\cc-chain-forge (3)\DeltaForge-repo 目录
git status
git add runner/config/tersafe_patches.json  # 精确暂存，勿用 git add .
git commit -m "fix: 描述修改内容"
git push origin master
```

**常用改动无需重编译**（只需推送JSON）：
- 新增 kKillChain 节点：编辑 `runner/config/tersafe_patches.json`

**需要重编译的改动**：
- `forge.c` / `libforgehook.c` / `injector.c` 任何修改

---

### 3.2 云仓库 → 云手机（拉取+编译+部署）

```bash
# 云手机 Termux 执行（非root）
cd ~/DeltaForge && git pull origin master

# 有代码改动时编译（非root）
cd cloud-agent/native && make termux

# 部署二进制（需root）
su -c "cp $HOME/DeltaForge/cloud-agent/native/forge /data/local/tmp/forge && chmod 755 /data/local/tmp/forge"
su -c "cp $HOME/DeltaForge/cloud-agent/native/libforgehook.so /data/local/tmp/libforgehook.so && chmod 755 /data/local/tmp/libforgehook.so"

# 只更新偏移表（最常用，无需重编译）
su -c "cp $HOME/DeltaForge/runner/config/tersafe_patches.json /data/local/tmp/forge_patches.json"

# 验证新patch
su -c "cat /data/local/tmp/forge_patches.json | grep '新offset'"
```

---

### 3.3 启动完整环境（每次使用前）

**步骤一：启动L0代理（mihomo + 路由）**

```bash
# 进入root shell
su

# 确认mihomo在跑
pidof mihomo || nohup /data/local/tmp/mihomo -d /data/local/tmp/mihomo-home -f /data/local/tmp/clash-config.yaml > /data/local/tmp/mihomo.log 2>&1 &

# 等3秒后修复路由
sleep 3
ip route replace default dev Meta table wlan0

# 验证出口IP为国内
curl -sk --max-time 10 https://ip.sb  # 应返回国内IP，非183.60.246.234

exit  # 退出root
```

**步骤二：启动游戏**

```bash
su -c "/data/local/tmp/forge -l 2>&1 | tee /data/local/tmp/forge.log"
```

**步骤三：forge运行完后立即补回路由**

```bash
su -c "ip route replace default dev Meta table wlan0"
curl -sk --max-time 10 https://ip.sb  # 再次确认IP
```

---

### 3.4 查看云手机当前环境状态

```bash
# === 检查L0 IP ===
curl -sk --max-time 10 https://ip.sb

# === 检查系统级属性（L2）===
su -c "getprop ro.product.model"         # 应为 SM-G9730
su -c "getprop ro.product.manufacturer"  # 应为 samsung
su -c "getprop ril.imei"                 # 应为 359825XXXXXXXXX
su -c "getprop ro.serialno"              # 应为 R开头

# === 检查Android ID（L3）===
settings get secure android_id           # 应为 7a3f9b2c1d4e8f06

# === 检查forge patch状态 ===
su -c "tail -20 /data/local/tmp/forge.log"

# === 检查游戏进程 ===
su -c "pidof com.tencent.tmgp.dfm"

# === 检查代理路由 ===
su -c "ip route get 8.8.8.8"  # 应显示 dev Meta

# === 查看最近崩溃 ===
su -c "ls -lt /data/tombstones/ | head -3"
su -c "head -50 /data/tombstones/tombstone_最新编号"

# === 运行完整诊断 ===
su -c "sh /data/local/tmp/diagnose_device.sh 2>&1 | head -50"
```

---

## 4. 当前 kKillChain 节点（v8.9，15节点）

| # | Offset | 说明 |
|---|--------|------|
| 0 | 0x419FDC | 与TerSafe自修复值相同，消除翻转 |
| 1 | 0x419FE0 | |
| 2 | 0x2E7810 | |
| 3 | 0x2F29D0 | |
| 4 | 0x320D78 | |
| 5 | 0x3233B8 | |
| 6 | 0x36BC8C | tombstone_14 新检测链入口 |
| 7 | 0x36BED8 | tombstone_14 中间节点 |
| 8 | 0x370D98 | tombstone_14 中间节点 |
| 9 | 0x371210 | tombstone_14 tgkill自杀点 |
| 10 | 0x2bfae8 | dl_iterate_phdr扫描入口（tombstone_17）|
| 11 | 0x1e7600 | dl_iterate_phdr调用方（tombstone_17）|
| 12 | 0x51d7f8 | Thread-12 watchdog最近帧（tombstone_20）|
| 13 | 0x20db64 | Thread-12 watchdog调用方（tombstone_20）|
| 14 | 0x50E370 | RET |

---

## 5. 常见问题排查

| 问题 | 排查步骤 |
|------|----------|
| forge.log 为空 | 用 `tee` 而非后台 `&` 启动 |
| IP仍是183.60.246.234 | `ip route replace default dev Meta table wlan0` |
| 游戏闪退 | `ls -lt /data/tombstones/ | head -3` 查最新tombstone |
| patch数量不对 | 确认 `/data/local/tmp/forge_patches.json` 已更新 |
| mihomo没跑 | `pidof mihomo` 检查，无则重新启动 |
| 路由forge后消失 | forge每次运行后需重执行 `ip route replace default dev Meta table wlan0` |
