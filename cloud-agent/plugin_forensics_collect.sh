#!/system/bin/sh
# DeltaForge whole-device plugin forensics collector.
# It writes only to its own output directory and does not alter Android state.

set -u

VERSION="1"
TARGET_PACKAGE="com.tencent.tmgp.dfm"
OUT_ROOT="/sdcard/Download"

usage() {
    echo "usage: $0 [--package PACKAGE] [--out DIRECTORY]"
}

die() {
    echo "[plugin-audit] ERROR: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --package)
            [ "$#" -ge 2 ] || die "--package requires a value"
            TARGET_PACKAGE="$2"
            shift 2
            ;;
        --out)
            [ "$#" -ge 2 ] || die "--out requires a value"
            OUT_ROOT="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

case "$TARGET_PACKAGE" in
    ''|*[!A-Za-z0-9._-]*) die "invalid package name: $TARGET_PACKAGE" ;;
esac

[ "$(id -u 2>/dev/null)" = "0" ] || die "run through su -c"

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || date +%s)"
BASE="deltaforge-plugin-audit-$STAMP"
WORK="$OUT_ROOT/$BASE"
if [ -e "$WORK" ]; then
    BASE="$BASE-$$"
    WORK="$OUT_ROOT/$BASE"
fi

mkdir -p "$WORK/commands" "$WORK/processes" "$WORK/modules/text" \
    || die "cannot create $WORK"
ERRORS="$WORK/errors.tsv"
CANDIDATES="$WORK/candidates.tsv"
MANIFEST="$WORK/manifest.tsv"

printf 'layer\tname\trc\tstderr\n' > "$ERRORS"
printf 'path\ttype\tsize\tuid\tgid\tmode\tsha256\tbuild_id\tindicators\tsource\n' \
    > "$CANDIDATES"
printf 'key\tvalue\n' > "$MANIFEST"

field() {
    printf '%s' "$1" | tr '\t\r\n' '   '
}

manifest() {
    printf '%s\t%s\n' "$(field "$1")" "$(field "$2")" >> "$MANIFEST"
}

record_error() {
    err_text="$(sed -n '1p' "$4" 2>/dev/null)"
    printf '%s\t%s\t%s\t%s\n' \
        "$(field "$1")" "$(field "$2")" "$3" "$(field "$err_text")" >> "$ERRORS"
}

capture() {
    layer="$1"
    name="$2"
    shift 2
    dir="$WORK/commands/$layer"
    out="$dir/$name.stdout.txt"
    err="$dir/$name.stderr.txt"
    mkdir -p "$dir"
    "$@" > "$out" 2> "$err"
    rc=$?
    [ "$rc" -eq 0 ] || record_error "$layer" "$name" "$rc" "$err"
    return 0
}

capture_sh() {
    layer="$1"
    name="$2"
    code="$3"
    capture "$layer" "$name" /system/bin/sh -c "$code"
}

safe_name() {
    printf '%s' "$1" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-180
}

file_build_id() {
    path="$1"
    if command -v readelf >/dev/null 2>&1; then
        readelf -n "$path" 2>/dev/null | sed -n 's/.*Build ID: *//p' | head -n 1
    elif command -v llvm-readelf >/dev/null 2>&1; then
        llvm-readelf -n "$path" 2>/dev/null | sed -n 's/.*Build ID: *//p' | head -n 1
    fi
}

add_candidate() {
    path="$1"
    indicators="$2"
    source="$3"
    [ -e "$path" ] || return 0

    meta="$(stat -c '%F|%s|%u|%g|%a' "$path" 2>/dev/null)"
    kind="$(printf '%s' "$meta" | cut -d'|' -f1)"
    size="$(printf '%s' "$meta" | cut -d'|' -f2)"
    uid="$(printf '%s' "$meta" | cut -d'|' -f3)"
    gid="$(printf '%s' "$meta" | cut -d'|' -f4)"
    mode="$(printf '%s' "$meta" | cut -d'|' -f5)"
    digest=""
    build_id=""
    if [ -f "$path" ]; then
        digest="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
        build_id="$(file_build_id "$path")"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(field "$path")" "$(field "$kind")" "$(field "$size")" \
        "$(field "$uid")" "$(field "$gid")" "$(field "$mode")" \
        "$(field "$digest")" "$(field "$build_id")" \
        "$(field "$indicators")" "$(field "$source")" >> "$CANDIDATES"
}

save_module_text() {
    path="$1"
    [ -r "$path" ] || return 0
    name="$(safe_name "$path")"
    sed -n '1,4000p' "$path" > "$WORK/modules/text/$name.txt" 2>/dev/null || true
}

snapshot_pid() {
    label="$1"
    pid="$2"
    case "$pid" in ''|*[!0-9]*) return 0 ;; esac
    [ -d "/proc/$pid" ] || return 0

    dir="$WORK/processes/$label"
    mkdir -p "$dir"
    printf '%s\n' "$pid" > "$dir/pid.txt"
    cat "/proc/$pid/status" > "$dir/status.txt" 2> "$dir/status.stderr.txt" || true
    tr '\000' ' ' < "/proc/$pid/cmdline" > "$dir/cmdline.txt" 2>/dev/null || true
    tr '\000' '\n' < "/proc/$pid/environ" > "$dir/environ.txt" 2>/dev/null || true
    cat "/proc/$pid/maps" > "$dir/maps.txt" 2> "$dir/maps.stderr.txt" || true
    cat "/proc/$pid/mountinfo" > "$dir/mountinfo.txt" 2> "$dir/mountinfo.stderr.txt" || true
    cat "/proc/$pid/smaps_rollup" > "$dir/smaps_rollup.txt" 2>/dev/null || true
    cat "/proc/$pid/attr/current" > "$dir/selinux_context.txt" 2>/dev/null || true
    ls -la "/proc/$pid/ns" > "$dir/namespaces.txt" 2> "$dir/namespaces.stderr.txt" || true
    ls -la "/proc/$pid/fd" > "$dir/fds.txt" 2> "$dir/fds.stderr.txt" || true
    readlink "/proc/$pid/exe" > "$dir/exe.txt" 2>/dev/null || true
}

discover_root_modules() {
    for root in /data/adb/modules /data/adb/modules_update /data/adb/ksu/modules \
        /data/adb/ap/modules /data/adb/zygisk /data/adb/riru \
        /data/adb/service.d /data/adb/post-fs-data.d /data/adb/boot-completed.d; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 8 -type f 2>/dev/null | while IFS= read -r path; do
            lower="$(printf '%s' "$path" | tr 'A-Z' 'a-z')"
            indicators="root_module"
            case "$root" in */service.d|*/post-fs-data.d|*/boot-completed.d) indicators="boot_script" ;; esac
            case "$lower" in *zygisk*) indicators="$indicators,zygisk" ;; esac
            case "$lower" in *riru*) indicators="$indicators,riru" ;; esac
            case "$lower" in *lsposed*|*xposed*) indicators="$indicators,xposed" ;; esac
            case "$lower" in *susfs*) indicators="$indicators,susfs" ;; esac
            case "$lower" in *prop*|*spoof*|*mask*|*hide*) indicators="$indicators,identity" ;; esac
            add_candidate "$path" "$indicators" "root_modules"
            case "${path##*/}" in
                module.prop|system.prop|service.sh|post-fs-data.sh|sepolicy.rule|action.sh)
                    save_module_text "$path"
                    ;;
            esac
        done
    done
}

discover_keyword_candidates() {
    for root in /data/local/tmp /data/app /system/bin /system/xbin /vendor/bin \
        /vendor/lib64 /system/lib64 /product/bin /system_ext/bin \
        /system/etc/selinux; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 4 -type f 2>/dev/null \
            | grep -Ei '/(magisk|ksu|kernelsu|apatch|zygisk|riru|lsposed|xposed|frida|susfs|resetprop|bpfdomain|traced_kprobes|rkp_cert_processor|initd|console_agent|poweropt-service|asp_sepolicy|provider\.root|dexguard|localSock|props|spoof|mask|hide|yunzhenji|zhenji|cloudphone|mihomo|clash|qimei|tersafe|tdatamaster|turing|hawk)' \
            | while IFS= read -r path; do
                add_candidate "$path" "keyword_match" "filesystem_scan"
            done
    done
}

discover_platform_control_plane() {
    for path in /system/xbin/su /system/xbin/sudo /system/xbin/bpfdomain \
        /system/xbin/resetprop /system/xbin/traced_kprobes \
        /system/xbin/rkp_cert_processor /system/bin/initd \
        /system/bin/console_agent /system/bin/poweropt-service \
        /system/etc/selinux/asp_sepolicy.conf; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        add_candidate "$path" "platform_control_plane" "platform_root_stack"
    done

    pm path com.android.provider.root 2>/dev/null \
        | sed -n 's/^package://p' \
        | while IFS= read -r path; do
            add_candidate "$path" "privileged_root_provider" "platform_root_stack"
        done
}

discover_loaded_candidates() {
    for maps in "$WORK"/processes/*/maps.txt; do
        [ -f "$maps" ] || continue
        label="$(basename "$(dirname "$maps")")"
        sed -n 's#^.* \(/.*\)$#\1#p' "$maps" \
            | sed 's/ (deleted)$//' \
            | sort -u \
            | grep -Ei '(^|/)(lib)?(magisk|ksu(d)?|kernelsu|apatch|zygisk|riru|lsposed|xposed|frida|susfs|resetprop|bpfdomain|traced_kprobes|rkp_cert_processor|console_agent|poweropt-service|localSock|[^/]*(provider\.root|dexguard|spoof|mask|hide|forge|qimei|tersafe|tdatamaster|turing|hawk)[^/]*)(/|$)' \
            | while IFS= read -r path; do
                add_candidate "$path" "loaded_mapping" "process_$label"
            done
    done
}

manifest schema "$VERSION"
manifest package "$TARGET_PACKAGE"
manifest started_at "$(date -Ins 2>/dev/null || date)"
manifest collector_pid "$$"
manifest uid "$(id 2>/dev/null)"

for tool in sh su getprop resetprop magisk ksud apd readelf llvm-readelf strace bpftool \
    tar sha256sum lshal dumpsys service ip ss netstat iptables-save ip6tables-save nft; do
    tool_path="$(command -v "$tool" 2>/dev/null || true)"
    manifest "tool.$tool" "${tool_path:-absent}"
done

# layer: boot_kernel
capture boot_kernel id id
capture boot_kernel uname uname -a
capture boot_kernel selinux getenforce
capture boot_kernel cmdline cat /proc/cmdline
capture boot_kernel version cat /proc/version
capture boot_kernel modules cat /proc/modules
capture boot_kernel module_tree find /sys/module -maxdepth 2 -type f
capture_sh boot_kernel kernel_config 'if [ -r /proc/config.gz ]; then zcat /proc/config.gz; elif [ -r /boot/config-$(uname -r) ]; then cat /boot/config-$(uname -r); else exit 2; fi'
capture_sh boot_kernel selinux_policy 'if [ -r /sys/fs/selinux/policy ]; then ls -lZ /sys/fs/selinux/policy; sha256sum /sys/fs/selinux/policy; else exit 2; fi'
capture_sh boot_kernel device_tree 'for f in /sys/firmware/devicetree/base/model /sys/firmware/devicetree/base/compatible /proc/device-tree/model /proc/device-tree/compatible; do if [ -r "$f" ]; then echo "=== $f ==="; tr "\000" "\n" < "$f"; fi; done'
capture_sh boot_kernel block_partitions 'ls -la /dev/block/by-name /dev/block/bootdevice/by-name 2>/dev/null; cat /proc/partitions'
capture_sh boot_kernel bpf_inventory 'ls -laR /sys/fs/bpf 2>/dev/null; if command -v bpftool >/dev/null 2>&1; then bpftool prog show; bpftool map show; bpftool link show; fi'
capture_sh boot_kernel kernel_log_markers 'dmesg 2>/dev/null | grep -Ei "susfs|magisk|kernelsu|apatch|zygisk|kprobe|ftrace|hook|overlay|lxc|rk3588|rockchip|sm8150|kgsl|keymint|tee"'

# layer: root_framework
capture root_framework processes ps -A -o USER,PID,PPID,NAME,ARGS
capture root_framework processes_context ps -AZ
capture_sh root_framework proc_walk 'for d in /proc/[0-9]*; do p=${d##*/}; [ -r "$d/status" ] || continue; name=$(sed -n "s/^Name:[[:space:]]*//p" "$d/status"); ppid=$(sed -n "s/^PPid:[[:space:]]*//p" "$d/status"); tracer=$(sed -n "s/^TracerPid:[[:space:]]*//p" "$d/status"); cmd=$(tr "\000" " " < "$d/cmdline" 2>/dev/null); exe=$(readlink "$d/exe" 2>/dev/null); printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$p" "$ppid" "$tracer" "$name" "$exe" "$cmd"; done'
capture_sh root_framework framework_versions 'for c in magisk ksud apd su resetprop; do echo "=== $c ==="; command -v "$c" 2>/dev/null; "$c" -V 2>/dev/null || "$c" --version 2>/dev/null || true; done'
capture_sh root_framework resetprop_view 'if command -v resetprop >/dev/null 2>&1; then resetprop; else exit 2; fi'
capture_sh root_framework adb_inventory 'for d in /data/adb /data/adb/modules /data/adb/modules_update /data/adb/ksu /data/adb/ap; do echo "=== $d ==="; ls -laZ "$d" 2>/dev/null; done'
capture_sh root_framework boot_scripts 'for d in /data/adb/service.d /data/adb/post-fs-data.d /data/adb/boot-completed.d; do echo "=== $d ==="; find "$d" -maxdepth 3 -type f -exec ls -laZ {} \; 2>/dev/null; done'
capture_sh root_framework core_tool_hashes 'for f in /system/bin/getprop /system/bin/toybox /system/bin/sh /system/bin/linker64 /apex/com.android.runtime/bin/linker64 /apex/com.android.runtime/lib64/bionic/libc.so /system/lib64/libc.so; do [ -e "$f" ] || continue; ls -laZ "$f"; sha256sum "$f"; if command -v readelf >/dev/null 2>&1; then readelf -n "$f" 2>/dev/null | grep "Build ID"; fi; done'
capture_sh root_framework manager_packages 'pm list packages -f -U 2>/dev/null | grep -Ei "magisk|kernelsu|apatch|lsposed|xposed|riru|zygisk|shamiko|hide|props|spoof|mask|frida|susfs|provider\.root|dexguard"'
capture_sh root_framework platform_control_plane 'for f in /system/xbin/su /system/xbin/sudo /system/xbin/bpfdomain /system/xbin/resetprop /system/xbin/traced_kprobes /system/xbin/rkp_cert_processor /system/bin/initd /system/bin/console_agent /system/bin/poweropt-service /system/bin/dropbear /system/bin/dropbear_service /system/etc/selinux/asp_sepolicy.conf /data/etc/selinux/asp_sepolicy.conf /data/isRoot; do [ -e "$f" ] || [ -L "$f" ] || continue; echo "=== $f ==="; ls -laZ "$f"; readlink -f "$f" 2>/dev/null; sha256sum "$f" 2>/dev/null; done'
capture_sh root_framework platform_control_processes 'ps -AZ | grep -Ei "bpfdomain|traced_kprobes|rkp_cert_processor|initd|console_agent|provider\.root|dropbear|crond"'
capture_sh root_framework platform_control_sockets 'cat /proc/net/unix 2>/dev/null | grep -Ei "profiles|rms_socket|mount_script_socket|root|bpf|kprobe|exec/sock|hook"; find /data/misc/profiles -maxdepth 4 \( -type s -o -type f \) -exec ls -laZ {} \; 2>/dev/null'
capture_sh root_framework root_provider 'pm path com.android.provider.root; dumpsys package com.android.provider.root'

# layer: init_services
capture init_services init_properties getprop
capture init_services binder_services service list
capture init_services hal_inventory lshal
capture init_services processes ps -A -o USER,PID,PPID,NAME,ARGS
capture_sh init_services rc_candidates 'find /system/etc/init /vendor/etc/init /odm/etc/init /product/etc/init /system_ext/etc/init -type f 2>/dev/null | while read f; do grep -HnEi "magisk|ksu|apatch|zygisk|riru|xposed|susfs|resetprop|bpfdomain|traced_kprobes|rkp_cert_processor|initd|console_agent|poweropt-service|provider\.root|dexguard|rms_socket|spoof|mask|hide|rockchip|antdock|yunzhenji|zhenji|cloudphone" "$f" 2>/dev/null; done'

# layer: identity_projection
capture identity_projection getprop getprop
capture identity_projection cpuinfo cat /proc/cpuinfo
capture identity_projection mounts cat /proc/mounts
capture identity_projection display dumpsys display
capture identity_projection surfaceflinger dumpsys SurfaceFlinger
capture identity_projection sensors dumpsys sensorservice
capture identity_projection media_codec dumpsys media.codec
capture identity_projection drm dumpsys drm.drmManager
capture identity_projection android_id settings get secure android_id
capture identity_projection global_proxy settings get global http_proxy
capture identity_projection private_dns settings get global private_dns_mode
capture_sh identity_projection hardware_nodes 'for f in /sys/devices/soc0/family /sys/devices/soc0/machine /sys/class/kgsl/kgsl-3d0/gpu_model /sys/class/drm/card0/device/uevent /sys/fs/selinux/enforce; do echo "=== $f ==="; cat "$f" 2>/dev/null || echo unavailable; done; ls -la /dev/kgsl-3d0 /dev/dri 2>/dev/null'
capture_sh identity_projection thermal_power 'find /sys/class/thermal /sys/class/power_supply /sys/class/devfreq -maxdepth 3 -type f 2>/dev/null | sort | head -n 5000'
capture_sh identity_projection property_area 'find /dev/__properties__ -maxdepth 2 -type f 2>/dev/null | sort | while read f; do ls -laZ "$f"; sha256sum "$f"; done; ls -laZ /data/property 2>/dev/null'

# layer: namespace_projection
capture namespace_projection root_mountinfo cat /proc/self/mountinfo
capture namespace_projection root_mounts cat /proc/mounts
capture namespace_projection root_namespaces ls -la /proc/self/ns
capture_sh namespace_projection overlay_markers 'cat /proc/self/mountinfo | grep -Ei "overlay|lxc|docker|container|ant/overlay|magisk|modules|mirror|worker"'

# layer: runtime_injection
TARGET_PID="$(pidof "$TARGET_PACKAGE" 2>/dev/null | awk '{print $1}')"
ZYGOTE64_PID="$(pidof zygote64 2>/dev/null | awk '{print $1}')"
ZYGOTE_PID="$(pidof zygote 2>/dev/null | awk '{print $1}')"
SYSTEM_SERVER_PID="$(pidof system_server 2>/dev/null | awk '{print $1}')"
manifest target_pid "${TARGET_PID:-not-running}"
manifest zygote64_pid "${ZYGOTE64_PID:-not-running}"
manifest system_server_pid "${SYSTEM_SERVER_PID:-not-running}"
snapshot_pid target "$TARGET_PID"
snapshot_pid zygote64 "$ZYGOTE64_PID"
snapshot_pid zygote "$ZYGOTE_PID"
snapshot_pid system_server "$SYSTEM_SERVER_PID"
capture_sh runtime_injection executable_anonymous 'for p in '"${TARGET_PID:-0} ${ZYGOTE64_PID:-0} ${ZYGOTE_PID:-0} ${SYSTEM_SERVER_PID:-0}"'; do [ -r "/proc/$p/maps" ] || continue; echo "=== pid=$p ==="; grep -E "r.xp.*(memfd:|/dev/ashmem|\[anon:|deleted)|rwxp" "/proc/$p/maps"; done'
capture_sh runtime_injection suspicious_logs 'logcat -d -b all -t 4000 2>/dev/null | grep -Ei "magisk|kernelsu|apatch|zygisk|riru|lsposed|xposed|susfs|resetprop|bpfdomain|traced_kprobes|rkp_cert_processor|provider\.root|dexguard|rms_socket|mount_script_socket|spoof|mask|hide|frida|qimei|tersafe|tdatamaster|turing|hawk"'

# layer: packages_artifacts
capture packages_artifacts packages_all pm list packages -f -U
capture packages_artifacts packages_third_party pm list packages -f -U -3
capture packages_artifacts overlays cmd overlay list --user 0
capture packages_artifacts instrumentation pm list instrumentation
capture packages_artifacts target_package dumpsys package "$TARGET_PACKAGE"
capture packages_artifacts target_paths pm path "$TARGET_PACKAGE"

# layer: network_projection
capture network_projection address ip address show
capture network_projection links ip -details link show
capture network_projection routes ip route show table all
capture network_projection rules ip rule show
capture network_projection sockets ss -lntup
capture network_projection iptables iptables-save
capture network_projection ip6tables ip6tables-save
capture network_projection nft_rules nft list ruleset
capture_sh network_projection network_properties 'getprop | grep -Ei "dns|proxy|vpn|tun|wlan|ethernet|netd|network"'
capture_sh network_projection network_processes 'ps -A -o USER,PID,PPID,NAME,ARGS | grep -Ei "mihomo|clash|sing-box|v2ray|tun2socks|redsocks|proxy|vpn"'

discover_root_modules
discover_keyword_candidates
discover_platform_control_plane
discover_loaded_candidates

find "$WORK" -type f ! -name file_hashes.tsv -exec sha256sum {} \; 2>/dev/null \
    | sort > "$WORK/file_hashes.tsv"
manifest completed_at "$(date -Ins 2>/dev/null || date)"

ARCHIVE="$OUT_ROOT/$BASE.tar.gz"
(cd "$OUT_ROOT" && tar -czf "$ARCHIVE" "$BASE") || die "archive creation failed"
ARCHIVE_SHA="$(sha256sum "$ARCHIVE" 2>/dev/null | awk '{print $1}')"

echo "[plugin-audit] complete"
echo "EVIDENCE_DIR=$WORK"
echo "ARCHIVE=$ARCHIVE"
echo "SHA256=$ARCHIVE_SHA"
