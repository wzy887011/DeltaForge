# 快代理隧道 + mihomo 透明代理部署文档

> 本文档面向在 Android 云手机（LXC容器/root权限）环境中部署透明 SOCKS5 代理的场景。
> 目标：将所有出站流量的出口 IP 替换为国内运营商 IP，绕过游戏反作弊的数据中心 IP 检测。

---

## 1. 代理服务信息（快代理 隧道代理Pro）

| 参数 | 值 |
|------|----|
| 服务商 | 快代理 (kuaidaili.com) |
| 产品类型 | 隧道代理Pro |
| HOST（主） | q360.kdltpspro.com |
| HOST（备）| q361.kdltpspro.com |
| 端口（HTTP+SOCKS5） | 15818 |
| 解析后IP | 115.231.184.39 |
| 用户名 | t18521305213132 |
| 密码 | vrs981gj |
| 地区 | 中国大陆混播 |
| 换IP周期 | 每次请求换IP |
| 带宽峰值 | 7.5Mbps（电信/联通）|
| 协议 | HTTP 和 SOCKS5 均支持 |

### 快速验证（任何有 curl 的环境）
```bash
# SOCKS5 验证
curl -x socks5h://t18521305213132:vrs981gj@q360.kdltpspro.com:15818 \
     -sk --max-time 10 http://baidu.com -o /dev/null -w "%{http_code}"
# 期望返回：301

# 查看出口IP
curl -x socks5h://t18521305213132:vrs981gj@115.231.184.39:15818 \
     -sk --max-time 10 https://ip.sb
# 期望：国内运营商IP（36.148.x.x 或 218.91.x.x 等）
```

> **注意**：访问境外服务（如 ip.sb HTTPS）可能返回错误，但访问国内目标（baidu.com）正常。
> 使用 IP 地址（115.231.184.39）而非域名，避免 DNS 劫持环路。

---

## 2. 部署环境要求

- Android 12 (SDK 32) LXC 云手机，具备 Root 权限
- Termux 已安装（编译/脚本执行环境）
- 设备可访问 GitHub
- `/dev/net/tun` 存在且可读写：`crw-rw-rw- 1 root root 10, 200`
- 网络接口：`wlan0`（主），`radio0`（备）

---

## 3. 组件安装

### 3.1 下载 mihomo（clash-meta）ARM64 二进制

```bash
# 在 Termux 用户权限下执行
cd ~/
curl -L -o clash.gz \
  https://github.com/MetaCubeX/mihomo/releases/download/v1.18.5/mihomo-linux-arm64-v1.18.5.gz

# 以 root 权限解压部署
su -c "zcat /data/data/com.termux/files/home/clash.gz > /data/local/tmp/mihomo && chmod 755 /data/local/tmp/mihomo"

# 验证
su -c "/data/local/tmp/mihomo -v"
# 期望：mihomo Meta v1.18.5 linux arm64...
```

### 3.2 创建配置文件

```bash
# 在 Termux 用户权限下写入配置
cat > ~/clash-config.yaml << 'EOF'
mixed-port: 7890
interface-name: wlan0
allow-lan: true
mode: rule
log-level: info

tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: false
  dns-hijack:
    - any:53

dns:
  enable: true
  ipv6: false
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxies:
  - name: KDL
    type: socks5
    server: 115.231.184.39
    port: 15818
    username: t18521305213132
    password: vrs981gj

rules:
  - MATCH,KDL
EOF

# 复制到 root 可访问路径
su -c "cp /data/data/com.termux/files/home/clash-config.yaml /data/local/tmp/clash-config.yaml"
```

### 3.3 创建 mihomo 工作目录

```bash
su -c "mkdir -p /data/local/tmp/mihomo-home"
```

---

## 4. 启动透明代理

### 4.1 启动 mihomo

```bash
su -c "kill \$(pidof mihomo) 2>/dev/null; sleep 1"
su -c "nohup /data/local/tmp/mihomo -d /data/local/tmp/mihomo-home \
  -f /data/local/tmp/clash-config.yaml \
  > /data/local/tmp/mihomo.log 2>&1 &"
sleep 4

# 验证启动
su -c "pidof mihomo"                        # 应有进程号
su -c "ip link show | grep Meta"            # 应显示 Meta TUN 接口
su -c "cat /data/local/tmp/mihomo.log | tail -5"
# 关键日志：[TUN] Tun adapter listening at: Meta([198.18.0.1/30],...)
```

### 4.2 修复路由（关键步骤）

**背景**：Android 的策略路由通过 `wlan0` 路由表分发流量，该表的 default 路由指向原始网关。
需要将其改为指向 Meta TUN 接口，同时为代理服务器和 DNS 保留直连路由（防止环路）。

```bash
su

# 将 wlan0 表的默认路由改为 Meta TUN
ip route replace default dev Meta table wlan0

# 代理服务器直连（防路由环路）
ip route add 115.231.184.39 via 172.17.0.1 dev wlan0 table wlan0 2>/dev/null || true

# DNS 直连（防 DNS 解析环路）
ip route add 223.5.5.5 via 172.17.0.1 dev wlan0 table wlan0 2>/dev/null || true
ip route add 119.29.29.29 via 172.17.0.1 dev wlan0 table wlan0 2>/dev/null || true

exit
```

### 4.3 验证出口 IP

```bash
curl -sk --max-time 15 https://ip.sb
# 期望：国内运营商IP，非原始云机 IP（183.60.246.234）

# 确认路由路径
su -c "ip route get 8.8.8.8"
# 期望：8.8.8.8 dev Meta table wlan0 src 198.18.0.1
```

---

## 5. 注意事项

### ⚠️ 路由持久化问题
每次重启 mihomo 或某些系统操作后，wlan0 路由表可能被重置。
需重新执行：
```bash
su -c "ip route replace default dev Meta table wlan0"
```

### ⚠️ 仅支持 TCP
快代理 SOCKS5 隧道代理仅支持 TCP 流量（UDP 游戏数据需额外处理）。

### ⚠️ natapp 方案（已废弃）
若无法直连快代理，可通过 natapp VIP 隧道中转（`d7c6fa4a9b166a29.natapp.cc:8870`），
但 natapp 免费版会拦截HTTP流量，建议直连。

### ⚠️ 换IP周期
快代理设置为"每次请求换IP"，游戏长连接期间出口IP固定不变，重连后可能变换。

---

## 6. 完整脚本（一键启动）

保存为 `/data/local/tmp/start_proxy.sh`：

```bash
#!/system/bin/sh

MIHOMO=/data/local/tmp/mihomo
CONFIG=/data/local/tmp/clash-config.yaml
HOME_DIR=/data/local/tmp/mihomo-home
LOG=/data/local/tmp/mihomo.log
PROXY_IP=115.231.184.39
GW=172.17.0.1

# 停止旧进程
kill $(pidof mihomo) 2>/dev/null
sleep 1

# 启动
nohup $MIHOMO -d $HOME_DIR -f $CONFIG > $LOG 2>&1 &
sleep 4

# 修复路由
ip route replace default dev Meta table wlan0
ip route add $PROXY_IP via $GW dev wlan0 table wlan0 2>/dev/null || true
ip route add 223.5.5.5 via $GW dev wlan0 table wlan0 2>/dev/null || true
ip route add 119.29.29.29 via $GW dev wlan0 table wlan0 2>/dev/null || true

# 验证
echo "出口IP:"
curl -sk --max-time 10 https://ip.sb
echo ""
echo "路由确认:"
ip route get 8.8.8.8
```

```bash
# 使用
su -c "sh /data/local/tmp/start_proxy.sh"
```
