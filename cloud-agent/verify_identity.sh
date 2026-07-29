#!/system/bin/sh
# Read-only layer report. Run as root after launch.
set -u
PKG="com.tencent.tmgp.dfm"
pass=0; warn=0; fail=0
PID="$(pidof "$PKG" 2>/dev/null | awk '{print $1}')"
NSENTER_KIND=""
NSENTER_BIN=""
ok() { pass=$((pass+1)); printf '[PASS] %s\n' "$*"; }
note() { warn=$((warn+1)); printf '[WARN] %s\n' "$*"; }
bad() { fail=$((fail+1)); printf '[FAIL] %s\n' "$*"; }

[ "$(id -u)" = 0 ] && ok 'verification runs with UID 0' \
    || bad 'verification is not running as root'

for prop in \
    debug.hwui.show_layers_updates \
    debug.hwui.show_dirty_regions \
    debug.hwui.show_overdraw \
    debug.hwui.profile \
    debug.sf.showupdates; do
    value="$(getprop "$prop" 2>/dev/null)"
    case "$value" in
        ''|false|0) ok "$prop disabled" ;;
        *) bad "$prop=$value enables Android graphics diagnostics" ;;
    esac
done

if [ -n "$PID" ]; then
    if command -v nsenter >/dev/null 2>&1; then
        NSENTER_KIND="direct"
        NSENTER_BIN="$(command -v nsenter)"
    elif command -v busybox >/dev/null 2>&1; then
        NSENTER_KIND="busybox"
        NSENTER_BIN="$(command -v busybox)"
    fi
fi

ns_cat() {
    [ -n "$PID" ] || return 1
    case "$NSENTER_KIND" in
        direct) "$NSENTER_BIN" -t "$PID" -m -- /system/bin/cat "$1" 2>/dev/null ;;
        busybox) "$NSENTER_BIN" nsenter -t "$PID" -m -- /system/bin/cat "$1" 2>/dev/null ;;
        *) return 127 ;;
    esac
}

check_prop() {
    key="$1"; expected="$2"; actual="$(getprop "$key" 2>/dev/null)"
    [ "$actual" = "$expected" ] && ok "$key=$actual" || bad "$key=$actual expected=$expected"
}

check_prop ro.product.model SM-G9730
check_prop ro.product.device beyond1q
check_prop ro.hardware qcom
check_prop ro.board.platform msmnile
check_prop ro.soc.model SM8150
for partition in odm product system system_ext vendor; do
    check_prop "ro.product.$partition.model" SM-G9730
    check_prop "ro.product.$partition.device" beyond1q
done

grep -q 'Qualcomm Technologies, Inc SM8150' /proc/cpuinfo 2>/dev/null \
    && ok '/proc/cpuinfo profile' || bad '/proc/cpuinfo still exposes host CPU'
grep -qi 'rockchip\|rk3588\|antdock' /sys/firmware/devicetree/base/model 2>/dev/null \
    && bad 'device tree exposes Rockchip' || ok 'device tree model'
grep -qi 'chenrl\|prod-fsfn' /proc/version 2>/dev/null \
    && bad 'kernel build host exposed' || ok 'kernel version text overlay'
proc_release="$(cat /proc/sys/kernel/osrelease 2>/dev/null)"
uname_release="$(uname -r 2>/dev/null)"
[ "$proc_release" = '4.14.190-perf+' ] \
    && ok 'proc kernel release overlay' || bad "proc kernel release=$proc_release"
[ "$uname_release" = '4.14.190-perf+' ] \
    && ok 'uname kernel release' || bad "uname exposes host kernel=$uname_release"
grep -aq 'qcom,sm8150' /sys/firmware/devicetree/base/compatible 2>/dev/null \
    && ok 'device tree compatible profile' || bad 'device tree compatible exposes host or is absent'

wm size 2>/dev/null | grep -q 'Override size: 1080x2280' \
    && ok 'logical display 1080x2280' || note 'logical display override missing'

if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
    ok 'SELinux read node reports enforcing'
else
    bad 'SELinux read node does not report enforcing'
fi
selinux_runtime="$(getenforce 2>/dev/null || printf Unknown)"
[ "$selinux_runtime" = Enforcing ] \
    && ok 'SELinux policy behavior is enforcing' \
    || bad "SELinux policy behavior remains $selinux_runtime (read-node overlay does not change policy)"

MOUNTINFO="/proc/self/mountinfo"
[ -n "$PID" ] && MOUNTINFO="/proc/$PID/mountinfo"
grep -qE 'overlay|lxcfs|/userdata/ant/overlay' "$MOUNTINFO" 2>/dev/null \
    && bad 'container mount topology visible outside game hook' || ok 'mount topology'
ps -A 2>/dev/null | grep -qE 'rockchip\.hardware|/system/xbin/s9su|script_guard' \
    && bad 'Rockchip/root infrastructure visible in process list' || ok 'process list infrastructure'
getprop 2>/dev/null | grep -qiE 'rockchip|rk3588|antdock' \
    && bad 'Rockchip properties remain visible' || ok 'property set has no Rockchip marker'
root_artifacts=""
for path in /system/xbin/s9su /system/bin/su /system/xbin/su /data/adb/ksu /data/adb/magisk; do
    [ -e "$path" ] && root_artifacts="$root_artifacts $path"
done
[ -z "$root_artifacts" ] \
    && ok 'common root artifact paths absent' || bad "root artifact paths:$root_artifacts"
[ -d /sys/class/kgsl/kgsl-3d0 ] \
    && ok 'Qualcomm KGSL tree exists' || note 'KGSL tree absent; only game-process file hooks synthesize it'

if pidof mihomo >/dev/null 2>&1; then
    note 'Mihomo root process exists; host/root observers can identify the proxy layer'
else
    note 'Mihomo process absent; L0 proxy is not active'
fi
if ip link show Meta >/dev/null 2>&1; then
    note 'Meta TUN exists; game-process interface hooks must normalize it'
else
    note 'Meta TUN absent; L0 proxy routing is not active'
fi
if [ -f /data/local/tmp/clash-config.yaml ]; then
    config_mode="$(stat -c %a /data/local/tmp/clash-config.yaml 2>/dev/null)"
    [ "$config_mode" = 600 ] \
        && ok 'Mihomo credential config mode=600' \
        || bad "Mihomo credential config mode=${config_mode:-unknown} expected=600"
fi
if [ -s /data/local/tmp/forge_network_backup/puffer.routes ]; then
    route_missing=0
    while IFS= read -r address; do
        ip route show table wlan0 "$address/32" 2>/dev/null | grep -q "via .* dev wlan0" \
            || route_missing=$((route_missing + 1))
    done < /data/local/tmp/forge_network_backup/puffer.routes
    [ "$route_missing" -eq 0 ] \
        && ok 'Puffer DIRECT host routes installed' \
        || bad "Puffer DIRECT host routes missing=$route_missing"
else
    note 'managed Puffer route state absent'
fi

if [ -n "$PID" ]; then
    ok "game pid=$PID"
    if [ -n "$NSENTER_KIND" ]; then
        ns_cat /proc/cpuinfo | grep -q 'Qualcomm Technologies, Inc SM8150' \
            && ok 'cpuinfo overlay visible in game mount namespace' \
            || bad 'cpuinfo overlay missing from game mount namespace'
        [ "$(ns_cat /proc/sys/kernel/osrelease)" = '4.14.190-perf+' ] \
            && ok 'osrelease overlay visible in game mount namespace' \
            || bad 'osrelease overlay missing from game mount namespace'
        ns_cat /sys/firmware/devicetree/base/compatible | grep -aq 'qcom,sm8150' \
            && ok 'device-tree compatible visible in game mount namespace' \
            || bad 'device-tree compatible missing from game mount namespace'
        [ "$(ns_cat /sys/fs/selinux/enforce)" = 1 ] \
            && ok 'SELinux read-node overlay visible in game mount namespace' \
            || bad 'SELinux read-node overlay missing from game mount namespace'
    else
        note 'nsenter unavailable; game mount namespace overlay not directly verified'
    fi
    grep -q 'libforgehook.so' "/proc/$PID/maps" 2>/dev/null \
        && ok 'hook library mapped' \
        || note 'hook mapping name absent; require activation log because constructor may normalize maps'
    seccomp="$(sed -n 's/^Seccomp:[[:space:]]*//p' "/proc/$PID/status" 2>/dev/null)"
    [ "$seccomp" = 2 ] && ok 'seccomp direct-syscall layer active' \
        || note "Seccomp=${seccomp:-unknown}; inline SVC can bypass libc hooks"
else
    note 'game process not running'
fi

hook_evidence=0
for f in /data/data/$PKG/files/forge_hook.log /data/local/tmp/forge_hook.log /sdcard/forge_hook.log; do
    if grep -qE 'GPU hook ACTIVE|hooks.*activated' "$f" 2>/dev/null; then
        ok "hook activation evidence: $f"; hook_evidence=1; break
    fi
done
[ "$hook_evidence" = 1 ] || note 'no current hook activation line found'

printf '[SUMMARY] pass=%d warn=%d fail=%d\n' "$pass" "$warn" "$fail"
[ "$fail" -eq 0 ]
