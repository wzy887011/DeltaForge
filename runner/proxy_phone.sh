#!/system/bin/sh
# proxy_phone.sh — 云机端代理配置
# 将云机出口流量通过 PC 端 SOCKS5（由 proxy_pc_setup.bat 提供）
#
# 用法（云机上，root）:
#   start   — 启用代理
#   stop    — 关闭代理
#   status  — 检查出口 IP
#   tun     — 全流量透明代理（需要 sockstun 二进制）

set -e
SOCKS_HOST="127.0.0.1"
SOCKS_PORT="1080"
TUN_IFACE="tun99"
SOCKSTUN_BIN="/data/local/tmp/sockstun"
SOCKSTUN_URL="https://github.com/heiher/sockstun/releases/latest/download/sockstun-android-arm64"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo "${GREEN}[+]${NC} $*"; }
warn()  { echo "${YELLOW}[!]${NC} $*"; }
error() { echo "${RED}[-]${NC} $*"; }

# ============================================================
# 方案 A（默认）: 系统全局 HTTP/HTTPS 代理
# 覆盖范围: HTTP/HTTPS 应用层流量（含游戏登录验证）
# ============================================================
cmd_start_http() {
    info "配置系统全局代理 ${SOCKS_HOST}:${SOCKS_PORT}..."
    # 等效于 Settings → Wifi → 代理
    settings put global http_proxy "${SOCKS_HOST}:${SOCKS_PORT}" 2>/dev/null
    settings put global global_http_proxy_host "${SOCKS_HOST}" 2>/dev/null
    settings put global global_http_proxy_port "${SOCKS_PORT}" 2>/dev/null
    # 让系统感知变化
    am broadcast -a android.intent.action.PROXY_CHANGE 2>/dev/null || true
    info "HTTP/HTTPS 代理已设置"
    sleep 1
    cmd_status
}

cmd_stop_http() {
    settings delete global http_proxy 2>/dev/null || true
    settings delete global global_http_proxy_host 2>/dev/null || true
    settings delete global global_http_proxy_port 2>/dev/null || true
    am broadcast -a android.intent.action.PROXY_CHANGE 2>/dev/null || true
    info "全局 HTTP 代理已关闭"
}

# ============================================================
# 方案 B: 全流量透明代理（sockstun + TUN）
# 覆盖范围: TCP+UDP 所有流量（含 QUIC/游戏数据包）
# ============================================================
cmd_start_tun() {
    # 确认 sockstun 存在
    if [ ! -x "$SOCKSTUN_BIN" ]; then
        warn "sockstun 未找到，尝试下载..."
        if command -v curl >/dev/null 2>&1; then
            curl -L -o "$SOCKSTUN_BIN" "$SOCKSTUN_URL" --max-time 60 && \
                chmod 755 "$SOCKSTUN_BIN" && info "sockstun 已下载"
        else
            error "需要 curl 下载 sockstun: pkg install curl"
            error "或手动下载: $SOCKSTUN_URL"
            return 1
        fi
    fi

    # 停止旧实例
    pkill sockstun 2>/dev/null || true
    ip link del "$TUN_IFACE" 2>/dev/null || true
    sleep 1

    # 保存原始默认路由（用于 SOCKS 服务器的直接通信）
    ORIG_GW=$(ip route show default | awk '/default/ {print $3}' | head -1)
    ORIG_DEV=$(ip route show default | awk '/default/ {print $5}' | head -1)

    # 启动 sockstun（创建 TUN 并接入 SOCKS5）
    "$SOCKSTUN_BIN" \
        --tun-name "$TUN_IFACE" \
        --tun-addr 198.18.0.1/15 \
        --socks5-server "${SOCKS_HOST}:${SOCKS_PORT}" &
    SOCKSTUN_PID=$!
    sleep 2

    if ! ip link show "$TUN_IFACE" 2>/dev/null | grep -q UP; then
        error "TUN 接口未就绪，请检查 sockstun 输出"
        return 1
    fi

    # 为 SOCKS 服务器地址保留直接路由（防路由环）
    [ -n "$ORIG_GW" ] && ip route add "${SOCKS_HOST}/32" via "$ORIG_GW" dev "$ORIG_DEV" 2>/dev/null || true

    # 所有流量走 TUN
    ip route del default 2>/dev/null || true
    ip route add default dev "$TUN_IFACE" metric 10

    # DNS 指向 114（与 SM-G9730 profile 一致，路由走 TUN）
    setprop net.dns1 114.114.114.114 2>/dev/null || true
    setprop net.dns2 114.114.115.115 2>/dev/null || true

    info "TUN 透明代理已启动（PID=$SOCKSTUN_PID）"
    sleep 2
    cmd_status
}

cmd_stop_tun() {
    pkill sockstun 2>/dev/null || true
    ip route del default dev "$TUN_IFACE" 2>/dev/null || true
    ip link del "$TUN_IFACE" 2>/dev/null || true
    # 恢复原路由（DHCP 重新获取）
    am broadcast -a android.net.conn.CONNECTIVITY_CHANGE 2>/dev/null || true
    info "TUN 代理已停止"
}

# ============================================================
# 状态检测
# ============================================================
cmd_status() {
    info "=== 当前出口 IP ==="
    IPV4=$(curl -4 -s --max-time 8 "https://api.ipify.org" 2>/dev/null)
    [ -n "$IPV4" ] && info "IPv4: $IPV4" || warn "IPv4: 不可达"
    ASN=$(curl -4 -s --max-time 6 "https://ipinfo.io/${IPV4}/org" 2>/dev/null)
    [ -n "$ASN" ] && info "ASN: $ASN"
    # 检测是否还是数据中心
    echo "$ASN" | grep -qiE "alibaba|tencent|huawei cloud|aws|azure|digitalocean" && \
        warn "出口仍为数据中心 ASN — 代理未生效或 PC 端也在数据中心" || \
        info "ASN 检查通过"
    HTTP_PROXY=$(settings get global http_proxy 2>/dev/null)
    [ "$HTTP_PROXY" != "null" ] && [ -n "$HTTP_PROXY" ] && \
        info "HTTP 代理: $HTTP_PROXY" || info "HTTP 代理: 未设置"
    ip link show "$TUN_IFACE" 2>/dev/null | grep -q UP && \
        info "TUN 代理: 运行中" || info "TUN 代理: 未运行"
}

CMD="${1:-start}"
case "$CMD" in
    start)   cmd_start_http ;;
    stop)    cmd_stop_http; cmd_stop_tun ;;
    tun)     cmd_start_tun ;;
    status)  cmd_status ;;
    *)
        echo "用法: $0 {start|stop|tun|status}"
        echo ""
        echo "  start  — 方案A: 系统 HTTP/HTTPS 代理（快速，无需额外工具）"
        echo "  tun    — 方案B: 全流量透明代理（需要 sockstun，覆盖 UDP）"
        echo "  stop   — 关闭所有代理"
        echo "  status — 检测当前出口 IP/ASN"
        echo ""
        echo "完整流程："
        echo "  1. PC 运行 proxy_pc_setup.bat"
        echo "  2. 云机运行: adb reverse tcp:1080 tcp:1080  (已在 bat 里自动执行)"
        echo "  3. 云机运行: su -c 'sh /data/local/tmp/proxy_phone.sh start'"
        echo "  4. 验证:     su -c 'sh /data/local/tmp/proxy_phone.sh status'"
        ;;
esac
