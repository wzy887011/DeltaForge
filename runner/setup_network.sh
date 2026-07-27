#!/system/bin/sh
# ==============================================================
# setup_network.sh — DeltaForge v8.8 L0 网络层配置
# 目标：将云机出口从数据中心 ASN 替换为移动运营商 ASN
#
# 使用前提：
#   1. Root 权限
#   2. WireGuard 内核模块（或 userspace 实现）
#   3. 具有移动/住宅出口的 WireGuard 服务端
#
# 用法：
#   setup_network.sh init   <server_pubkey> <server_endpoint> <server_allowed_ip>
#   setup_network.sh up     # 启动隧道
#   setup_network.sh down   # 停止隧道
#   setup_network.sh status # 检查当前出口
#   setup_network.sh check  # 检测 IPv4/IPv6/DNS 出口一致性
# ==============================================================

set -e

WG_IFACE="wg0"
WG_DIR="/data/local/tmp/wg"
WG_CONF="$WG_DIR/wg0.conf"
PRIV_KEY_FILE="$WG_DIR/priv.key"
PUB_KEY_FILE="$WG_DIR/pub.key"
DNS_FILE="$WG_DIR/dns_servers"
# 与 SM-G9730 profile 一致的 DNS（中国电信 DNS）
DEFAULT_DNS="114.114.114.114,114.114.115.115"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo "${GREEN}[+]${NC} $*"; }
warn()  { echo "${YELLOW}[!]${NC} $*"; }
error() { echo "${RED}[-]${NC} $*"; }

# ============================================================
# 依赖检查
# ============================================================
check_deps() {
    local missing=""
    for bin in wg ip iptables; do
        command -v "$bin" >/dev/null 2>&1 || missing="$missing $bin"
    done
    if [ -n "$missing" ]; then
        error "缺少依赖:$missing"
        info  "安装方式（Termux root）："
        info  "  pkg install wireguard-tools iproute2"
        return 1
    fi
    # 检查 WireGuard 内核模块
    if ! ip link add dev wg_test type wireguard 2>/dev/null; then
        warn "WireGuard 内核模块未加载，尝试 userspace 模式"
        # 尝试 wireguard-go
        if ! command -v wireguard-go >/dev/null 2>&1; then
            error "wireguard-go 也不可用。"
            info  "选项 A: 刷入支持 WireGuard 的内核（推荐）"
            info  "选项 B: pkg install wireguard-go"
            return 1
        fi
    else
        ip link del wg_test 2>/dev/null || true
    fi
    return 0
}

# ============================================================
# init: 生成密钥对 + 写入配置
# 参数: <server_pubkey> <server_endpoint:port> <server_wg_ip>
# ============================================================
cmd_init() {
    if [ "$#" -lt 3 ]; then
        error "用法: setup_network.sh init <server_pubkey> <server_endpoint:port> <server_wg_ip>"
        error "示例: setup_network.sh init abc123... 1.2.3.4:51820 10.0.0.1"
        return 1
    fi
    SERVER_PUBKEY="$1"
    SERVER_ENDPOINT="$2"
    SERVER_WG_IP="$3"

    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"

    # 生成密钥对
    wg genkey | tee "$PRIV_KEY_FILE" | wg pubkey > "$PUB_KEY_FILE"
    chmod 600 "$PRIV_KEY_FILE"
    PRIV_KEY=$(cat "$PRIV_KEY_FILE")
    PUB_KEY=$(cat "$PUB_KEY_FILE")

    # 分配客户端 IP（使用随机末位避免冲突）
    LAST_OCTET=$(( $(cat /proc/sys/kernel/random/uuid | tr -d '-' | cut -c1-4 | tr a-f 9-9 | head -c 3) % 200 + 10 ))
    CLIENT_WG_IP="10.66.66.${LAST_OCTET}/32"

    info "客户端公钥: $PUB_KEY"
    info "请在服务端添加此 peer："
    echo ""
    echo "[Peer]"
    echo "PublicKey = $PUB_KEY"
    echo "AllowedIPs = ${CLIENT_WG_IP%/*}/32"
    echo ""

    # 写入配置
    cat > "$WG_CONF" << EOF
[Interface]
PrivateKey = $PRIV_KEY
Address = $CLIENT_WG_IP
DNS = $DEFAULT_DNS
MTU = 1380

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"
    info "配置已写入: $WG_CONF"
    info "服务端 WireGuard IP: $SERVER_WG_IP"
    info "执行 'setup_network.sh up' 启动隧道"
}

# ============================================================
# up: 启动 WireGuard 隧道 + 路由
# ============================================================
cmd_up() {
    if [ ! -f "$WG_CONF" ]; then
        error "配置不存在，请先执行 init"; return 1
    fi

    # 停止旧实例
    cmd_down 2>/dev/null || true

    # 创建接口
    ip link add dev "$WG_IFACE" type wireguard 2>/dev/null || {
        # 回退到 userspace
        wireguard-go "$WG_IFACE" 2>/dev/null &
        sleep 1
    }

    # 加载配置
    wg setconf "$WG_IFACE" "$WG_CONF"

    # 获取分配的客户端 IP
    CLIENT_IP=$(grep '^Address' "$WG_CONF" | awk '{print $3}' | cut -d/ -f1)
    ip addr add "$(grep '^Address' "$WG_CONF" | awk '{print $3}')" dev "$WG_IFACE" 2>/dev/null || true
    ip link set up dev "$WG_IFACE"

    # ===保留当前默认路由用于 WireGuard endpoint 的直接访问 ===
    SERVER_EP=$(grep '^Endpoint' "$WG_CONF" | awk '{print $3}' | cut -d: -f1)
    ORIG_GW=$(ip route show default | awk '/default/ {print $3}' | head -1)
    ORIG_DEV=$(ip route show default | awk '/default/ {print $5}' | head -1)

    # 为服务端地址添加直接路由（绕过新路由表，防止环路）
    if [ -n "$SERVER_EP" ] && [ -n "$ORIG_GW" ]; then
        ip route add "$SERVER_EP/32" via "$ORIG_GW" dev "$ORIG_DEV" 2>/dev/null || true
    fi

    # 删除默认路由，添加通过 wg0 的默认路由
    ip route del default 2>/dev/null || true
    ip route add default dev "$WG_IFACE" 2>/dev/null

    # IPv6：如果不想泄漏，直接禁用
    if ip -6 route | grep -q default; then
        ip -6 route del default 2>/dev/null || true
        warn "IPv6 默认路由已删除（防泄漏）"
    fi

    # DNS 配置 — 修改 resolv.conf
    DNS=$(grep '^DNS' "$WG_CONF" | awk '{print $3}')
    if [ -n "$DNS" ]; then
        # 使用第一个 DNS
        DNS1=$(echo "$DNS" | cut -d, -f1)
        echo "nameserver $DNS1" > /data/local/tmp/wg_resolv.conf
        mount --bind /data/local/tmp/wg_resolv.conf /etc/resolv.conf 2>/dev/null || \
            setprop net.dns1 "$DNS1" 2>/dev/null || true
        info "DNS → $DNS1"
    fi

    info "WireGuard 隧道已启动"
    wg show "$WG_IFACE"
}

# ============================================================
# down: 停止隧道，恢复原始路由
# ============================================================
cmd_down() {
    ip link set down dev "$WG_IFACE" 2>/dev/null || true
    ip link del dev "$WG_IFACE" 2>/dev/null || true
    pkill wireguard-go 2>/dev/null || true
    # 恢复 DNS
    umount /etc/resolv.conf 2>/dev/null || true
    info "WireGuard 隧道已停止"
}

# ============================================================
# status: 显示当前出口 IP 与 ASN
# ============================================================
cmd_status() {
    info "=== 网络出口检测 ==="
    # IPv4 出口
    info "IPv4 出口:"
    curl -4 -s --max-time 8 "https://ipinfo.io/json" 2>/dev/null | \
        grep -E '"ip"|"org"|"city"|"country"' || \
        curl -4 -s --max-time 8 "http://ip-api.com/line/?fields=query,isp,country,city" 2>/dev/null || \
        echo "  (无法获取 IPv4 信息)"

    # IPv6 出口
    info "IPv6 出口:"
    curl -6 -s --max-time 5 "https://ipinfo.io/json" 2>/dev/null | \
        grep '"ip"' || echo "  (IPv6 不可用或已禁用)"

    # DNS 检测
    info "DNS resolver:"
    nslookup google.com 2>/dev/null | grep "Server:" || \
        getprop net.dns1 2>/dev/null || echo "  (无法检测 DNS)"

    # WireGuard 状态
    if ip link show "$WG_IFACE" 2>/dev/null | grep -q UP; then
        info "WireGuard: 运行中"
        wg show "$WG_IFACE" 2>/dev/null
    else
        warn "WireGuard: 未运行"
    fi
}

# ============================================================
# check: 全链路泄漏检测 (基于 IP研究文档 §5)
# ============================================================
cmd_check() {
    info "=== 全链路泄漏检测 ==="
    FAIL=0

    # 1. IPv4 出口
    IPV4=$(curl -4 -s --max-time 8 "https://api.ipify.org" 2>/dev/null)
    [ -n "$IPV4" ] && info "IPv4: $IPV4" || { warn "IPv4: 不可达"; FAIL=1; }

    # 2. IPv6 泄漏检测
    IPV6=$(curl -6 -s --max-time 5 "https://api6.ipify.org" 2>/dev/null)
    if [ -n "$IPV6" ]; then
        warn "IPv6 泄漏: $IPV6 — 建议禁用: ip -6 route del default"
        FAIL=1
    else
        info "IPv6: 已禁用或不可达（良好）"
    fi

    # 3. DNS 泄漏检测
    DNS_IP=$(nslookup myip.opendns.com resolver1.opendns.com 2>/dev/null | \
             awk '/Address:/ && !/resolver/ {print $2}' | head -1)
    if [ -n "$DNS_IP" ] && [ "$DNS_IP" = "$IPV4" ]; then
        info "DNS: 通过隧道（良好）"
    elif [ -n "$DNS_IP" ]; then
        warn "DNS 解析来自: $DNS_IP（可能泄漏，与出口 $IPV4 不一致）"
        FAIL=1
    fi

    # 4. ASN 归属判断
    ASN_INFO=$(curl -4 -s --max-time 8 "https://ipinfo.io/${IPV4}/org" 2>/dev/null)
    info "ASN 归属: $ASN_INFO"
    # 检查是否还是数据中心 ASN
    echo "$ASN_INFO" | grep -qiE "alibaba|tencent|huawei|aws|azure|google|digitalocean|vultr|linode|hetzner" && {
        warn "出口仍为数据中心 ASN — 服务端需使用移动/住宅出口"
        FAIL=1
    } || info "ASN 类型: 可能为移动/住宅（需人工确认）"

    [ "$FAIL" = "0" ] && info "=== 检测通过 ===" || warn "=== 存在泄漏，请修复后重新检测 ==="
}

# ============================================================
# 主入口
# ============================================================
CMD="${1:-status}"
shift 2>/dev/null || true

case "$CMD" in
    init)   check_deps && cmd_init "$@" ;;
    up)     check_deps && cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    check)  cmd_check ;;
    *)
        echo "用法: $0 {init|up|down|status|check}"
        echo ""
        echo "  init <server_pubkey> <server_endpoint> <server_wg_ip>"
        echo "       初始化 WireGuard 配置（需要先在服务端添加 peer）"
        echo "  up   启动隧道"
        echo "  down 停止隧道"
        echo "  status 显示当前出口 IP/ASN"
        echo "  check  全链路泄漏检测（IPv4/IPv6/DNS/ASN）"
        echo ""
        echo "服务端搭建（Linux VPS，移动/住宅出口）："
        echo "  apt install wireguard"
        echo "  wg genkey | tee server_priv | wg pubkey > server_pub"
        echo "  配置 /etc/wireguard/wg0.conf，开启 ip forwarding"
        exit 1
        ;;
esac
