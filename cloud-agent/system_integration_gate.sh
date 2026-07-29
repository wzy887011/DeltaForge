#!/system/bin/sh
# DeltaForge v8.7 read-only system integration gate.
set -u

PKG=com.tencent.tmgp.dfm
OUT=${1:-/data/local/tmp/deltaforge_system_gate.txt}
PID="$(pidof "$PKG" 2>/dev/null | awk '{print $1}')"
pass=0
warn=0
fail=0

ok() { pass=$((pass + 1)); printf '[PASS] %s\n' "$*"; }
note() { warn=$((warn + 1)); printf '[WARN] %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf '[FAIL] %s\n' "$*"; }

run_gate() {
    printf 'DeltaForge system integration gate\n'
    printf 'timestamp=%s\n' "$(date -Ins 2>/dev/null || date)"
    printf 'game_pid=%s\n' "${PID:-not-running}"

    [ "$(id -u)" = 0 ] && ok 'gate runs as root' || bad 'gate is not root'
    [ "$(getenforce 2>/dev/null)" = Enforcing ] \
        && ok 'SELinux behavior is enforcing' \
        || bad "SELinux behavior=$(getenforce 2>/dev/null || printf Unknown)"
    [ "$(uname -r 2>/dev/null)" = '4.14.190-perf+' ] \
        && ok 'kernel release matches profile' \
        || bad "host uname=$(uname -r 2>/dev/null)"

    grep -qE 'overlay|lxcfs|/userdata/ant/overlay|/lxc/' /proc/self/mountinfo 2>/dev/null \
        && bad 'container mount topology visible in root namespace' \
        || ok 'root mount topology has no known container marker'
    grep -qiE 'rockchip|rk3588|antdock' /proc/device-tree/model /sys/firmware/devicetree/base/model 2>/dev/null \
        && bad 'Rockchip host model visible' || ok 'device-tree model has no Rockchip marker'
    getprop 2>/dev/null | grep -qiE 'rockchip|rk3588|antdock' \
        && bad 'Rockchip property visible' || ok 'property set has no Rockchip marker'
    ps -A 2>/dev/null | grep -qE 'rockchip\.hardware|/system/xbin/s9su|script_guard' \
        && bad 'host/root infrastructure visible in process list' \
        || ok 'process list has no known Rockchip/root infrastructure marker'

    root_paths=""
    for path in /system/xbin/s9su /system/bin/su /system/xbin/su /data/adb/ksu /data/adb/magisk; do
        [ -e "$path" ] && root_paths="$root_paths $path"
    done
    [ -z "$root_paths" ] && ok 'common root paths absent' || bad "root paths:$root_paths"

    wm size 2>/dev/null | grep -q 'Override size: 1080x2280' \
        && ok 'logical display profile active' || note 'logical display profile missing'
    for prop in debug.hwui.show_layers_updates debug.hwui.show_dirty_regions \
        debug.hwui.show_overdraw debug.hwui.profile debug.sf.showupdates; do
        value="$(getprop "$prop" 2>/dev/null)"
        case "$value" in ''|0|false) : ;; *) bad "graphics diagnostic enabled $prop=$value" ;; esac
    done

    if [ -n "$PID" ]; then
        ok "game process running pid=$PID"
        grep -qE 'overlay|lxcfs|/userdata/ant/overlay|/lxc/' "/proc/$PID/mountinfo" 2>/dev/null \
            && bad 'container mount topology visible in game namespace' \
            || ok 'game mount topology has no known container marker'
        grep -q 'libforgehook.so' "/proc/$PID/maps" 2>/dev/null \
            && note 'external root observer sees hook pathname' \
            || ok 'external maps view has no hook pathname'
        grep -qE 'hooks.*activated' /data/data/$PKG/files/forge_hook.log 2>/dev/null \
            && ok 'hook activation evidence present' || bad 'hook activation evidence absent'
    else
        note 'game process absent; namespace and hook checks skipped'
    fi

    pidof mihomo >/dev/null 2>&1 && note 'Mihomo root process visible' || note 'Mihomo absent'
    ip link show Meta >/dev/null 2>&1 && note 'Meta TUN visible to root observer' || note 'Meta TUN absent'

    printf '[SUMMARY] pass=%d warn=%d fail=%d\n' "$pass" "$warn" "$fail"
    [ "$fail" -eq 0 ]
}

mkdir -p "$(dirname "$OUT")"
if run_gate >"$OUT" 2>&1; then rc=0; else rc=$?; fi
cat "$OUT"
exit "$rc"
