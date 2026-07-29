# DeltaForge IP 伪装技术详解

**版本**: v8.9 | **更新**: 2026-07-28

---

## 总览：为什么需要 IP 伪装

云手机（优达云 LXC 容器）的真实出口 IP 是 `183.60.246.234`，归属为数据中心 ASN。三角洲行动的反作弊系统（TerSafe/GTI）通过以下路径检测 IP：

| 检测方 | 检测方式 | 位置 |
|--------|----------|------|
| 服务端 | 连接来源 IP ASN（数据中心 vs 运营商） | 登录/游戏服务器 |
| 客户端 TerSafe | `/proc/net/tcp` 读取本地 socket 地址 | 游戏进程内 |
| 客户端 GTI | 网络接口信息（MAC、IP）| 游戏进程内 |

**不处理 IP 的后果**：游戏在4秒内 native_crash（SIGKILL）。

---

## 方法一：L0 网络层 — 路由级出口 IP 替换

### 原理
将云机所有 TCP 流量通过透明代理重新路由，使服务端看到的来源 IP 变为国内运营商 IP（`36.148.234.134` 或 `218.91.4.91` 等快代理池 IP）。

### 技术链路

```
游戏进程
  ↓ TCP连接（出向）
iptables/Policy Routing（wlan0 table → default via Meta）
  ↓ 路由到 TUN 接口 Meta
mihomo（clash-meta）gVisor 用户态协议栈
  ↓ SOCKS5 连接（直接路由，绕过TUN）
快代理服务器 115.231.184.39:15818
  ↓ 代理出站
腾讯游戏服务器（看到的来源IP：快代理国内IP）
```

### 关键组件

#### A. mihomo（clash-meta）透明代理

**二进制位置**: `/data/local/tmp/mihomo`
**配置文件**: `/data/local/tmp/clash-config.yaml`

```yaml
mixed-port: 7890           # 本地混合代理端口
interface-name: wlan0      # 出站接口
mode: rule

tun:
  enable: true
  stack: gvisor             # 用户态协议栈，不依赖内核TUN模块
  auto-route: true          # 自动添加路由规则
  auto-detect-interface: false
  dns-hijack:
    - any:53                # 劫持所有DNS查询

dns:
  enable: true
  nameserver:
    - 223.5.5.5             # 阿里DNS（走代理解析）
    - 119.29.29.29          # DNSPod（走代理解析）

proxies:
  - name: KDL
    type: socks5
    server: 115.231.184.39  # 快代理IP（硬编码，绕过DNS劫持环路）
    port: 15818
    username: t18521305213132
    password: vrs981gj
```

**TUN 接口创建**：
```
10: Meta: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 9000
    link/none
    inet 198.18.0.1/30
```

mihomo 在 `/dev/net/tun` 上创建 Meta 虚拟网络设备，gVisor 栈在用户态处理所有 TCP/UDP 数据包，无需内核 tun 模块支持。

#### B. Android 策略路由修改

云机 Android 使用多路由表系统。流量查找顺序：
1. 表`local`（优先级0）
2. 表`main` 特定路由（优先级50）
3. mihomo 添加的 TUN 规则（优先级9000-9002）
4. 表`wlan0`（优先级23000/29000）← **实际流量走这里**

**问题**：Android 系统的 `goto 9010` 规则（优先级9001）跳过了 mihomo 的 9002 规则，所有流量最终落入 `wlan0` 表。

**修复**：直接修改 `wlan0` 路由表的 default 路由：

```bash
# 将 wlan0 表的默认路由指向 Meta TUN
ip route replace default dev Meta table wlan0

# 同时保留代理服务器和DNS的直连路由（绕过TUN避免环路）
ip route add 115.231.184.39 via 172.17.0.1 dev wlan0 table wlan0  # 代理直连
ip route add 223.5.5.5 via 172.17.0.1 dev wlan0 table wlan0       # DNS直连
ip route add 119.29.29.29 via 172.17.0.1 dev wlan0 table wlan0    # DNS直连
```

**验证**：
```bash
ip route get 8.8.8.8
# 输出：8.8.8.8 dev Meta table wlan0 src 198.18.0.1 uid 0 ← 走Meta
ip route get 115.231.184.39
# 输出：115.231.184.39 via 172.17.0.1 dev wlan0 ← 直连
```

#### C. DNS 劫持

当流量进入 Meta TUN 后，mihomo 拦截所有 UDP/TCP 53 端口的 DNS 查询。
游戏的域名解析（如 `login.game.qq.com`）由 mihomo 内部 DNS 服务器完成，
解析结果通过代理服务器获取，最终响应返回给游戏进程。

**效果**：游戏连接到的游戏服务器时，TCP 连接的来源 IP = 快代理出口 IP（国内运营商 IP）。

---

## 方法二：L7 进程内 Hook — `/proc/net/tcp` 伪装

### 原理
libforgehook.so 通过 LD_PRELOAD 注入游戏进程，拦截 `open()`/`read()` 系统调用，当游戏读取 `/proc/net/tcp` 时返回伪造内容。

### 实现（libforgehook.c）

```c
// OVERRIDE_FILES 表中的条目
{"/proc/net/tcp",   OVERRIDE_NET_TCP,   sizeof(OVERRIDE_NET_TCP)-1},
{"/proc/net/tcp6",  OVERRIDE_NET_TCP6,  sizeof(OVERRIDE_NET_TCP6)-1},
{"/proc/net/udp",   OVERRIDE_NET_UDP,   sizeof(OVERRIDE_NET_UDP)-1},
{"/proc/net/udp6",  OVERRIDE_NET_UDP6,  sizeof(OVERRIDE_NET_UDP6)-1},
```

**OVERRIDE_NET_TCP 内容**（伪造成正常手机网络状态）：
```
  sl  local_address rem_address   st tx_queue rx_queue
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000  # lo:53
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000  # lo:631
```

**Hook 实现**：

```c
// open() Hook
int open(const char *p, int flags, ...) {
    INIT();
    if (!HOOKS_READY()) return _open(p, flags, m);
    
    const override_file_t *f = match(p);  // 匹配 /proc/net/tcp 等路径
    if (f) {
        // 创建 memfd，写入伪造内容
        int fd = override_fd(f->data, f->len);
        return fd;
    }
    return _open(p, flags, m);
}
```

---

## 方法三：L7 进程内 Hook — MAC 地址伪装

### 原理
TerSafe/GTI 通过 MAC 地址判断网络接口类型（数据中心 vs 手机 WiFi）。libforgehook.so 拦截 MAC 地址查询，返回三星官方 OUI 前缀的假 MAC。

### 实现

#### getifaddrs() Hook
```c
int getifaddrs(struct ifaddrs **ifap) {
    int ret = _getifaddrs(ifap);
    if (ret != 0) return ret;
    
    for (struct ifaddrs *ifa = *ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            // 替换 MAC 前3字节为 Samsung OUI: 94:65:2d
            sll->sll_addr[0] = 0x94;
            sll->sll_addr[1] = 0x65;
            sll->sll_addr[2] = 0x2d;
        }
    }
    return 0;
}
```

#### ioctl(SIOCGIFHWADDR) Hook
```c
int ioctl(int fd, unsigned long request, ...) {
    int ret = _ioctl(fd, request, arg);
    if (request == SIOCGIFHWADDR) {
        struct ifreq *ifr = (struct ifreq *)arg;
        ifr->ifr_hwaddr.sa_data[0] = 0x94;  // Samsung OUI
        ifr->ifr_hwaddr.sa_data[1] = 0x65;
        ifr->ifr_hwaddr.sa_data[2] = 0x2d;
    }
    return ret;
}
```

**SM-G9730 目标 MAC 前缀**: `94:65:2d` (Samsung Electronics)

---

## 方法四：L2 系统级属性 — resetprop 全局覆写

### 原理
通过 Magisk resetprop 工具（绕过 Android property_service）直接修改系统内存中的属性值，使所有进程（包括系统服务）看到的都是三星设备属性。

### 覆写的 IP/网络相关属性

```bash
resetprop ril.imei 359825103631591           # IMEI（电信设备标识）
resetprop ro.serialno RNHLL1U9M2Q            # 设备序列号
resetprop ro.product.model SM-G9730          # 设备型号
resetprop ro.product.manufacturer samsung    # 制造商
resetprop ro.build.fingerprint "samsung/beyond1qltezc/beyond1q:11/..."
resetprop ro.soc.model SM8150               # SoC型号（Snapdragon 855）
resetprop ro.hardware.egl adreno            # GPU（Adreno）
```

### forge 执行结果
```
[+] Property emulation complete — resetprop=/data/local/tmp/resetprop ok=65 fail=0
```

65 个属性在系统级成功修改，fail=0。

---

## 方法五：L3 设备 ID 文件替换 — OAID/VAID 随机化

### 原理
游戏 SDK 直接读取文件系统上的设备 ID 文件（不走 API，绕过 Hook）。forge 在游戏启动前用随机生成的值替换这些文件。

### 覆写的文件

```bash
/data/system/oaid_persistence_0    # OAID（开放匿名设备标识符）
/data/system/vaid_persistence_platform  # VAID（虚拟匿名设备标识符）
```

**随机生成示例**：
```
OAID: 88ee772277559900
VAID: aa883322bbcc3377
```

### Android ID 固定
```bash
settings put secure android_id 7a3f9b2c1d4e8f06
```

---

## 六层覆盖效果对比

| 检测点 | 原始值 | 伪装后 | 方法 |
|--------|--------|--------|------|
| 服务端看到的来源IP | 183.60.246.234（数据中心）| 36.148.234.134（联通住宅）| mihomo+快代理 |
| /proc/net/tcp | 真实连接地址 | 伪造正常手机状态 | libforgehook Hook |
| MAC 地址 | 云机虚拟MAC | 94:65:2d:XX Samsung MAC | libforgehook Hook |
| IMEI | 云机虚假IMEI | 359825XXXXXXXXX 三星IMEI | resetprop |
| 设备型号 | 云机型号 | SM-G9730 | resetprop |
| OAID/VAID | 固定云机ID | 随机新ID | forge文件替换 |

---

## 注意事项

### 路由持久化问题
forge 每次运行 `block_tdm_reporting()` 会触发 mihomo 路由监控重置，导致 `wlan0` 表 default 路由恢复为原始值。**每次 forge 运行后需要执行**：

```bash
su -c "ip route replace default dev Meta table wlan0"
```

### 代理服务器直连必要性
如果代理服务器（115.231.184.39）的流量也走 Meta TUN，会形成环路：
```
mihomo 尝试连接代理 → 流量进入 Meta → mihomo 再次拦截 → 死循环
```
因此必须为代理服务器 IP 和 DNS 服务器 IP 保留直连路由。

### LD_PRELOAD 时机
通过 `wrap.com.tencent.tmgp.dfm` 属性（resetprop 设置）实现系统级 LD_PRELOAD，在游戏进程 fork 后、main() 执行前加载 libforgehook.so，确保 Hook 覆盖游戏所有网络调用。
