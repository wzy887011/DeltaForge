# DeltaForge 操作手册 v1.0
**更新**: 2026-07-28 | **版本**: v8.7

网络控制入口：

```bash
su -c '/data/local/tmp/mihomo_control.sh apply'
su -c '/data/local/tmp/mihomo_control.sh refresh'
su -c '/data/local/tmp/mihomo_control.sh status'
su -c '/data/local/tmp/mihomo_control.sh rollback'
```

控制器会先备份私有配置，验证 YAML，维护 Puffer 当前 IPv4 地址经真实
`wlan0` 网关的精确 `/32` 路由，并将配置权限收敛为 `0600`。

---

## 1. 项目概览

### 1.1 目标
针对三角洲行动 (`com.tencent.tmgp.dfm`) 的云手机（LXC容器）反检测系统。让优达云云机通过 TerSafe / GTI 双层安全检测，伪装成真实三星 SM-G9730 设备。

### 1.2 技术栈

| 层次 | 技术 | 状态 |
|------|------|------|
| L0 IP/ASN | mihomo + 快代理 SOCKS5 + iptables路由 | ✅ 运行中 |
| L1 全局节点 | Root read-only bind overlay | 部分覆盖，受宿主内核限制 |
| L2 全局属性 | resetprop (Magisk独立版) | 已验证 Samsung/SM-G9730 |
| L3 身份文件 | OAID/VAID/IMEI/Serial随机化 | ✅ |
| L5 DFM指纹 | forge do_prepare() 清理 | ✅ |
| L6 TerSafe patch | ptrace + /proc/pid/mem | 72 个稳定代码点已验证，写前双重校验 |
| L7 进程内Hook | validated patch 后 ptrace `dlopen` | qimei 代理链已激活；直接 SVC 仍为残余面 |
| UE4 RVA | 静态表 | 已隔离，等待当前 Build ID 重新提取 |
| L8 LXC特征 | mountinfo过滤 | ✅ |
| 写入所有权 | forge + JSON 单一真源 | Hook/Injector 无独立偏移表 |

---

## 2. 文件位置

### 2.1 本地文件（Windows PC）

```
D:\下载\cc-chain-forge (3)\DeltaForge-repo\
├── cloud-agent/native/          # 核心 C 代码（ARM64编译目标）
│   ├── forge.c                  # 主控守护进程 v8.7
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
- 在当前 Build ID 下更新已验证代码点：编辑 `runner/config/tersafe_patches.json`

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

## 4. 当前写入表（v8.7）

唯一真源为 `runner/config/tersafe_patches.json`：75 个 TerSafe 代码点、40 个
BSS 地址、0 个 UE4 点。每个代码点必须包含 `expected`，并且整个表在任何写入
前完成 Build ID、数量、范围、对齐、重复项和原指令预检。

高频维护子集为 `0x419FDC`、`0x419FE0`、`0x2E7810`、`0x2F29D0`、
`0x320D78`、`0x3233B8`；它们仍从上述 72 项中查找，不是第二套表。
Hook 与 injector 均不执行签名扫描或目标代码写入。

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

---

## 6. v8.7 分层覆盖与回滚

当前覆盖由三部分组成：Root 启动器、全局属性/只读 bind overlay、游戏进程内
Hook。Root 权限负责部署和挂载；`libforgehook.so` 只影响目标进程。外部 Root
进程读取 `/proc` 或 `/sys` 时，只有已 bind 的全局节点会改变，其余仍返回宿主值。

目标模块写入只有一条链：`forge` 加载 JSON、验证 Build ID 和 expected opcode、
完成写入后再调用 injector 加载 Hook。默认不设置 `wrap.PKG`；Hook 与 injector
均不维护独立偏移表，也不直接改写 TerSafe/UE4 指令。

```sh
# 应用系统节点 overlay（原始节点不改写）
su -c '/data/local/tmp/system_identity_overlay.sh apply'

# 查看当前 overlay
su -c '/data/local/tmp/system_identity_overlay.sh status'

# 启动游戏后做分层验收
su -c '/data/local/tmp/verify_identity.sh'

# 回滚 bind mount、显示覆盖和属性快照
su -c '/data/local/tmp/system_identity_overlay.sh rollback'
```

UE4 Build ID `8187ddb9edbc9d5201201ffd7b008df3bfe533db` 的旧 RVA 已隔离。
在重新生成 RVA 和 expected opcode 之前，日志出现 `UE4 patch table quarantined`
属于预期状态。
