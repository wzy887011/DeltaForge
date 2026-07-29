#!/system/bin/sh
# DeltaForge v8.7 network controller for the device-side Mihomo TUN.
set -u

ACTION="${1:-status}"
TMP=/data/local/tmp
MIHOMO="$TMP/mihomo"
CONFIG="$TMP/clash-config.yaml"
HOME_DIR="$TMP/mihomo-home"
LOG="$TMP/mihomo.log"
BACKUP_DIR="$TMP/forge_network_backup"
MANAGED_ROUTES="$BACKUP_DIR/puffer.routes"
IFACE=wlan0
ROUTE_TABLE=wlan0
PUFFER_DOMAIN=puffer.500638030-11-1.gcloudsvcs.com
PUFFER_RULE="DOMAIN,$PUFFER_DOMAIN,DIRECT"
TERMUX_BIN=/data/data/com.termux/files/usr/bin

log() { printf '[network] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" = 0 ] || die "root required"

mkdir -p "$BACKUP_DIR" || die "cannot create $BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

snapshot_state() {
    stamp="$(date +%Y%m%d_%H%M%S)"
    [ -f "$CONFIG" ] || die "missing $CONFIG"
    cp -p "$CONFIG" "$BACKUP_DIR/config.before.$stamp" \
        || die "cannot back up Mihomo config"
    {
        echo '=== IP RULE ==='
        ip rule show
        echo '=== ROUTE TABLE ==='
        ip route show table "$ROUTE_TABLE"
    } > "$BACKUP_DIR/routes.before.$stamp"
    log "snapshot=$BACKUP_DIR/config.before.$stamp"
}

test_config() {
    "$MIHOMO" -t -d "$HOME_DIR" -f "$CONFIG" >/dev/null 2>&1 \
        || die "Mihomo config test failed"
}

ensure_puffer_rule() {
    grep -Fq "$PUFFER_RULE" "$CONFIG" && { chmod 0600 "$CONFIG"; return 0; }
    work="$CONFIG.work.$$"
    awk -v rule="$PUFFER_RULE" '
        /^[[:space:]]*-[[:space:]]*MATCH,/ && !inserted {
            print "  - " rule
            inserted=1
        }
        { print }
        END { if (!inserted) exit 2 }
    ' "$CONFIG" > "$work" || { rm -f "$work"; die "MATCH rule not found"; }
    mv "$work" "$CONFIG" || die "cannot replace config"
    chmod 0600 "$CONFIG"
    test_config
    log "installed rule=$PUFFER_RULE"
}

resolve_puffer() {
    python_bin="$TERMUX_BIN/python"
    if [ -x "$python_bin" ]; then
        "$python_bin" - "$PUFFER_DOMAIN" <<'PY'
import socket
import sys

addresses = {
    item[4][0]
    for item in socket.getaddrinfo(sys.argv[1], 8085, socket.AF_INET, socket.SOCK_STREAM)
}
for address in sorted(addresses, key=lambda value: tuple(map(int, value.split(".")))):
    print(address)
PY
        return
    fi
    if command -v getent >/dev/null 2>&1; then
        getent ahostsv4 "$PUFFER_DOMAIN" | awk '{print $1}' | sort -u
        return
    fi
    grep -oE 'dial tcp [0-9]+(\.[0-9]+){3}:8085' "$LOG" 2>/dev/null \
        | awk '{sub(/:8085$/, "", $3); print $3}' | sort -u
}

find_gateway() {
    ip route show table "$ROUTE_TABLE" | awk -v dev="$IFACE" '
        $2 == "via" && $5 == dev && $3 !~ /^198\.18\./ { print $3; exit }
    '
}

remove_managed_routes() {
    [ -f "$MANAGED_ROUTES" ] || return 0
    while IFS= read -r address; do
        [ -n "$address" ] && ip route del "$address/32" table "$ROUTE_TABLE" 2>/dev/null || true
    done < "$MANAGED_ROUTES"
    : > "$MANAGED_ROUTES"
}

sync_puffer_routes() {
    gateway="$(find_gateway)"
    [ -n "$gateway" ] || die "real $IFACE gateway not found"
    addresses="$(resolve_puffer)"
    [ -n "$addresses" ] || die "Puffer DNS returned no IPv4 addresses"

    remove_managed_routes
    : > "$MANAGED_ROUTES"
    for address in $addresses; do
        case "$address" in
            *[!0-9.]*|'') die "invalid resolved IPv4 address=$address" ;;
        esac
        ip route replace "$address/32" via "$gateway" dev "$IFACE" table "$ROUTE_TABLE" \
            || die "route install failed address=$address"
        printf '%s\n' "$address" >> "$MANAGED_ROUTES"
        log "route $address/32 via $gateway dev $IFACE table $ROUTE_TABLE"
    done
    chmod 0600 "$MANAGED_ROUTES"
}

stop_mihomo() {
    pid="$(pidof mihomo 2>/dev/null | awk '{print $1}')"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    count=0
    while [ "$count" -lt 20 ] && pidof mihomo >/dev/null 2>&1; do
        sleep 1
        count=$((count + 1))
    done
    pidof mihomo >/dev/null 2>&1 && die "Mihomo did not stop"
}

start_mihomo() {
    test_config
    if command -v setsid >/dev/null 2>&1; then
        setsid "$MIHOMO" -d "$HOME_DIR" -f "$CONFIG" </dev/null >>"$LOG" 2>&1 &
    elif [ -x "$TERMUX_BIN/setsid" ]; then
        "$TERMUX_BIN/setsid" "$MIHOMO" -d "$HOME_DIR" -f "$CONFIG" </dev/null >>"$LOG" 2>&1 &
    else
        nohup "$MIHOMO" -d "$HOME_DIR" -f "$CONFIG" </dev/null >>"$LOG" 2>&1 &
    fi
    count=0
    while [ "$count" -lt 15 ] && ! pidof mihomo >/dev/null 2>&1; do
        sleep 1
        count=$((count + 1))
    done
    pid="$(pidof mihomo 2>/dev/null | awk '{print $1}')"
    [ -n "$pid" ] || { tail -n 80 "$LOG" 2>/dev/null; die "Mihomo start failed"; }
    log "mihomo pid=$pid"
}

show_status() {
    log "mihomo_pid=$(pidof mihomo 2>/dev/null)"
    ip link show Meta 2>/dev/null || log 'Meta interface absent'
    log "config_rule=$(grep -Fc "$PUFFER_RULE" "$CONFIG" 2>/dev/null || true)"
    if [ -f "$MANAGED_ROUTES" ]; then
        while IFS= read -r address; do
            [ -n "$address" ] && ip route show table "$ROUTE_TABLE" "$address/32"
        done < "$MANAGED_ROUTES"
    fi
    mode="$(stat -c %a "$CONFIG" 2>/dev/null || printf unknown)"
    log "config_mode=$mode"
}

rollback() {
    latest="$(ls -1t "$BACKUP_DIR"/config.before.* 2>/dev/null | head -n 1)"
    [ -n "$latest" ] || die "no network config backup found"
    stop_mihomo
    remove_managed_routes
    cp -p "$latest" "$CONFIG" || die "config restore failed"
    chmod 0600 "$CONFIG"
    start_mihomo
    log "restored=$latest"
}

case "$ACTION" in
    apply|start)
        snapshot_state
        ensure_puffer_rule
        stop_mihomo
        start_mihomo
        sync_puffer_routes
        show_status
        ;;
    refresh)
        sync_puffer_routes
        show_status
        ;;
    stop)
        snapshot_state
        stop_mihomo
        ;;
    rollback)
        rollback
        show_status
        ;;
    status)
        show_status
        ;;
    *)
        die "usage: $0 [apply|start|refresh|stop|rollback|status]"
        ;;
esac
