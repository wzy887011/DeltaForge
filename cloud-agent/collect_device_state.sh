#!/data/data/com.termux/files/usr/bin/bash

# Read-only DeltaForge device-state collector for Termux.
set +e

TERMUX_PREFIX=/data/data/com.termux/files/usr
TERMUX_HOME=/data/data/com.termux/files/home
PATH="$TERMUX_PREFIX/bin:/system/bin:/system/xbin:/vendor/bin:/product/bin:$PATH"
export PATH

SELF="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
if [ "$(id -u)" != "0" ]; then
    exec su -c "$TERMUX_PREFIX/bin/bash '$SELF'"
fi

umask 022
PKG=com.tencent.tmgp.dfm
REPO="$TERMUX_HOME/DeltaForge"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="/data/local/tmp/deltaforge_diag_$TS"
REPORT="$OUT/report.txt"
mkdir -p "$OUT"

exec 3>&1 4>&2
exec >"$REPORT" 2>&1

section() {
    printf '\n===== %s =====\n' "$1"
}

run() {
    printf '\n$'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

copy_tail() {
    local src="$1" dst="$2" lines="${3:-5000}"
    if [ -f "$src" ]; then
        tail -n "$lines" "$src" >"$OUT/$dst" 2>&1
    fi
}

READELF=""
for candidate in llvm-readelf readelf; do
    if have "$candidate"; then
        READELF="$(command -v "$candidate")"
        break
    fi
done

inspect_file() {
    local f="$1" b
    [ -e "$f" ] || return 0
    b="$(basename "$f")"
    printf '\n--- %s ---\n' "$f"
    ls -laZ "$f" 2>&1
    stat "$f" 2>&1
    sha256sum "$f" 2>&1
    have file && file "$f" 2>&1
    if [ -n "$READELF" ]; then
        "$READELF" -h -l -d -n "$f" >"$OUT/elf_${b}.txt" 2>&1
        "$READELF" --dyn-syms --wide "$f" >"$OUT/dynsym_${b}.txt" 2>&1
    fi
}

section "COLLECTOR"
echo "timestamp=$TS"
echo "package=$PKG"
echo "uid=$(id -u)"
echo "path=$PATH"
echo "readelf=${READELF:-not-found}"

section "OS AND CONTAINER"
run date -Ins
run id
run uname -a
run getconf LONG_BIT
run cat /proc/version
run cat /proc/1/cgroup
run cat /proc/self/cgroup
run cat /proc/self/status
run uptime
run df -h
run mount
run getprop ro.build.version.release
run getprop ro.build.version.sdk
run getprop ro.product.cpu.abi
run getprop ro.product.cpu.abilist
run getprop ro.boot.container
run getprop ro.kernel.qemu
getprop >"$OUT/getprop_all.txt" 2>&1

section "ROOT AND SELINUX"
run command -v su
run su -v
run su -V
run command -v magisk
have magisk && run magisk -v
have magisk && run magisk -V
have magisk && run magisk --path
run command -v ksud
run command -v apd
run getenforce
have sestatus && run sestatus
run cat /sys/fs/selinux/enforce
run ls -laZ /data/adb
run ls -laZ /data/adb/modules
run ps -AZ
dmesg 2>&1 | tail -n 2000 >"$OUT/dmesg_tail.txt"
grep -iE 'avc:|selinux|denied' "$OUT/dmesg_tail.txt" >"$OUT/selinux_denials.txt" 2>&1
if [ -r /proc/config.gz ]; then
    zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_(SECURITY_SELINUX|NAMESPACES|USER_NS|PID_NS|NET_NS|CGROUPS|OVERLAY_FS|BPF|BPF_SYSCALL|SECCOMP|ARM64)=' >"$OUT/kernel_config_selected.txt"
fi

section "DEVICE PROFILE"
for p in \
    ro.product.brand ro.product.manufacturer ro.product.model ro.product.device \
    ro.product.name ro.build.fingerprint ro.hardware ro.board.platform \
    ro.soc.manufacturer ro.soc.model ro.boot.hardware ro.boot.serialno \
    ro.serialno ril.imei gsm.version.baseband ro.boot.verifiedbootstate \
    ro.boot.vbmeta.device_state ro.boot.flash.locked; do
    printf '%-36s = %s\n' "$p" "$(getprop "$p" 2>/dev/null)"
done
run settings get secure android_id
run wm size
run wm density
cat /proc/cpuinfo >"$OUT/cpuinfo.txt" 2>&1
for f in \
    /sys/devices/soc0/machine /sys/devices/soc0/family /sys/devices/soc0/soc_id \
    /sys/devices/soc0/revision /sys/devices/soc0/serial_number \
    /sys/firmware/devicetree/base/model \
    /sys/class/kgsl/kgsl-3d0/gpu_model /sys/class/kgsl/kgsl-3d0/gpu_busy_percentage \
    /sys/class/kgsl/kgsl-3d0/max_gpuclk /sys/class/kgsl/kgsl-3d0/devfreq/cur_freq \
    /sys/class/kgsl/kgsl-3d0/devfreq/max_freq /sys/class/kgsl/kgsl-3d0/devfreq/min_freq; do
    if [ -r "$f" ]; then
        printf '%s = ' "$f"
        tr -d '\000' <"$f" 2>/dev/null
        printf '\n'
    else
        printf '%s = <missing>\n' "$f"
    fi
done
dumpsys SurfaceFlinger >"$OUT/surfaceflinger.txt" 2>&1
grep -iE 'GLES|GL_VENDOR|GL_RENDERER|GL_VERSION|Display' "$OUT/surfaceflinger.txt" | head -n 200 >"$OUT/gpu_display_selected.txt"
dumpsys sensorservice >"$OUT/sensorservice.txt" 2>&1

section "REPOSITORY"
if [ -d "$REPO/.git" ] && have git; then
    run git -c safe.directory="$REPO" -C "$REPO" rev-parse HEAD
    run git -c safe.directory="$REPO" -C "$REPO" branch --show-current
    run git -c safe.directory="$REPO" -C "$REPO" status --short
    run git -c safe.directory="$REPO" -C "$REPO" log -1 --oneline --decorate
else
    echo "repo-not-found=$REPO"
fi

section "DEPLOYED FILES"
run ls -laZ /data/local/tmp
for f in \
    /data/local/tmp/forge /data/local/tmp/libforgehook.so \
    /data/local/tmp/injector /data/local/tmp/forge_monitor \
    /data/local/tmp/forge_patches.json /data/local/tmp/forge_config.json \
    /data/local/tmp/diagnose_device.sh /data/local/tmp/propsadapt.sh \
    /data/local/tmp/propspoof.sh /data/local/tmp/forge-control.sh \
    /data/local/tmp/mihomo /data/local/tmp/clash-config.yaml; do
    inspect_file "$f"
done
if [ -f /data/local/tmp/forge_patches.json ]; then
    cp -p /data/local/tmp/forge_patches.json "$OUT/forge_patches.json"
    if have python; then
        python -m json.tool /data/local/tmp/forge_patches.json >"$OUT/forge_patches.validated.json" 2>"$OUT/forge_patches_json_error.txt"
        echo "forge_patches_json_status=$?"
    fi
fi
if [ -f "$REPO/runner/config/tersafe_patches.json" ]; then
    inspect_file "$REPO/runner/config/tersafe_patches.json"
    cp -p "$REPO/runner/config/tersafe_patches.json" "$OUT/repo_tersafe_patches.json"
fi
if [ -f "$REPO/runner/config/forge_config.json" ]; then
    inspect_file "$REPO/runner/config/forge_config.json"
    cp -p "$REPO/runner/config/forge_config.json" "$OUT/repo_forge_config.json"
fi

section "MAGISK OR ROOT MODULE FILES"
for d in /data/adb/modules/*; do
    [ -d "$d" ] || continue
    if printf '%s\n' "$d" | grep -qi forge || grep -qi 'DeltaForge\|forge' "$d/module.prop" 2>/dev/null; then
        echo "module=$d"
        find "$d" -maxdepth 4 -type f -exec ls -laZ {} \; 2>&1
        for f in "$d/module.prop" "$d/service.sh" "$d/post-fs-data.sh" "$d/propsadapt.sh" "$d/propspoof.sh"; do
            if [ -f "$f" ]; then
                echo "--- $f ---"
                sha256sum "$f"
                sed -n '1,300p' "$f"
            fi
        done
    fi
done

section "PROCESSES AND SOCKETS"
run ps -A
run pidof forge
run pidof forge_monitor
run pidof mihomo
run pidof "$PKG"
if have ss; then
    ss -lntup >"$OUT/listening_sockets.txt" 2>&1
else
    netstat -lntup >"$OUT/listening_sockets.txt" 2>&1
fi
grep -E '(^|:)9510([[:space:]]|$)' "$OUT/listening_sockets.txt" 2>/dev/null
cat /proc/net/unix >"$OUT/proc_net_unix.txt" 2>&1
grep -F '/data/local/tmp/forge_ipc.sock' "$OUT/proc_net_unix.txt" 2>&1
run ls -laZ /data/local/tmp/forge_ipc.sock

section "APP PACKAGE"
run pm path "$PKG"
run cmd package path "$PKG"
dumpsys package "$PKG" >"$OUT/dumpsys_package.txt" 2>&1
dumpsys activity processes >"$OUT/dumpsys_activity_processes.txt" 2>&1
pm path "$PKG" 2>/dev/null | sed 's/^package://' >"$OUT/apk_paths.txt"
while IFS= read -r apk; do
    [ -f "$apk" ] || continue
    echo "apk=$apk"
    ls -laZ "$apk"
    sha256sum "$apk"
done <"$OUT/apk_paths.txt"

PID="$(pidof "$PKG" 2>/dev/null | awk '{print $1}')"
echo "game_pid=${PID:-not-running}"
if [ -n "$PID" ] && [ -r "/proc/$PID/maps" ]; then
    cp "/proc/$PID/maps" "$OUT/game_maps.txt"
    cp "/proc/$PID/status" "$OUT/game_status.txt" 2>/dev/null
    cp "/proc/$PID/mountinfo" "$OUT/game_mountinfo.txt" 2>/dev/null
    cp "/proc/$PID/smaps_rollup" "$OUT/game_smaps_rollup.txt" 2>/dev/null
    readlink -f "/proc/$PID/exe" >"$OUT/game_exe.txt" 2>&1
    for ns in /proc/"$PID"/ns/*; do
        printf '%s -> %s\n' "$ns" "$(readlink "$ns" 2>/dev/null)"
    done >"$OUT/game_namespaces.txt"
    tr '\000' '\n' <"/proc/$PID/environ" 2>/dev/null | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH|PATH|CLASSPATH)=' >"$OUT/game_relevant_environ.txt"
    grep -E 'libtersafe\.so|libUE4\.so|libforgehook\.so|\[anon:|memfd:' "$OUT/game_maps.txt" >"$OUT/game_relevant_maps.txt"

    section "LOADED LIBRARIES"
    for lib in libtersafe.so libUE4.so libforgehook.so; do
        mapline="$(grep -F "$lib" "$OUT/game_maps.txt" | head -n 1)"
        echo "$lib map=$mapline"
        libpath="$(printf '%s\n' "$mapline" | awk '{print $6}')"
        libpath="${libpath% (deleted)}"
        if [ -f "$libpath" ]; then
            inspect_file "$libpath"
        else
            echo "$lib path unavailable as regular file: ${libpath:-not-mapped}"
        fi
    done

    section "TERSAFE PATCH BYTE SNAPSHOT"
    PATCH_JSON=/data/local/tmp/forge_patches.json
    [ -f "$PATCH_JSON" ] || PATCH_JSON="$REPO/runner/config/tersafe_patches.json"
    MAPLINE="$(grep -F 'libtersafe.so' "$OUT/game_maps.txt" | head -n 1)"
    if [ -n "$MAPLINE" ] && [ -f "$PATCH_JSON" ]; then
        RANGE="$(printf '%s\n' "$MAPLINE" | awk '{print $1}')"
        MAPOFF="$(printf '%s\n' "$MAPLINE" | awk '{print $3}')"
        START_HEX="${RANGE%%-*}"
        BASE_DEC=$((0x$START_HEX - 0x$MAPOFF))
        BASE_HEX="$(printf '0x%x' "$BASE_DEC")"
        TSAFE_PATH="$(printf '%s\n' "$MAPLINE" | awk '{print $6}')"
        TSAFE_PATH="${TSAFE_PATH% (deleted)}"
        echo "map_line=$MAPLINE"
        echo "computed_load_base=$BASE_HEX"
        echo "patch_json=$PATCH_JSON"
        echo "offset expected_word file_at_rva_le process_memory_le" >"$OUT/tersafe_patch_bytes.txt"
        sed -n '/"tersafe_patches"/,/"tersafe_bss"/p' "$PATCH_JSON" | \
            sed -n 's/.*"offset"[[:space:]]*:[[:space:]]*"\(0x[0-9A-Fa-f]*\)".*"value"[[:space:]]*:[[:space:]]*"\(0x[0-9A-Fa-f]*\)".*/\1 \2/p' | \
        while read -r off expected; do
            off_dec=$((16#${off#0x}))
            addr_dec=$((BASE_DEC + off_dec))
            file_bytes=unavailable
            mem_bytes=unavailable
            if [ -f "$TSAFE_PATH" ]; then
                file_bytes="$(dd if="$TSAFE_PATH" bs=1 skip="$off_dec" count=4 status=none 2>/dev/null | od -An -tx1 | tr -d ' \n')"
                [ -n "$file_bytes" ] || file_bytes=unreadable
            fi
            mem_bytes="$(dd if="/proc/$PID/mem" bs=1 skip="$addr_dec" count=4 status=none 2>/dev/null | od -An -tx1 | tr -d ' \n')"
            [ -n "$mem_bytes" ] || mem_bytes=unreadable
            printf '%s %s %s %s\n' "$off" "$expected" "$file_bytes" "$mem_bytes" >>"$OUT/tersafe_patch_bytes.txt"
        done
        cat "$OUT/tersafe_patch_bytes.txt"
    else
        echo "snapshot skipped: game/libtersafe/patch JSON not available"
    fi
else
    echo "Game is not running; process maps and patch bytes were not collected."
fi

section "NETWORK AND MIHOMO"
run ip -details address show
run ip rule show
run ip route show table all
run ip -6 route show table all
run cat /proc/net/route
run getprop net.dns1
run getprop net.dns2
have iptables-save && iptables-save >"$OUT/iptables.txt" 2>&1
have ip6tables-save && ip6tables-save >"$OUT/ip6tables.txt" 2>&1
have nft && nft list ruleset >"$OUT/nft_ruleset.txt" 2>&1
MIHOMO_PID="$(pidof mihomo 2>/dev/null | awk '{print $1}')"
if [ -n "$MIHOMO_PID" ]; then
    tr '\000' ' ' <"/proc/$MIHOMO_PID/cmdline" >"$OUT/mihomo_cmdline.txt" 2>&1
    cp "/proc/$MIHOMO_PID/status" "$OUT/mihomo_status.txt" 2>/dev/null
fi
if have curl; then
    echo "ip.sb=$(curl -4 -ksS --max-time 10 https://ip.sb 2>&1 | tr -d '\r\n')"
    echo "api.ipify.org=$(curl -4 -ksS --max-time 10 https://api.ipify.org 2>&1 | tr -d '\r\n')"
fi

section "LOGS AND CRASHES"
copy_tail /data/local/tmp/forge.log forge.log 10000
copy_tail /data/local/tmp/forge_hook.log forge_hook.log 10000
copy_tail /data/local/tmp/forge_monitor.log forge_monitor.log 10000
copy_tail /data/local/tmp/forge_repair.log forge_repair.log 10000
copy_tail /data/local/tmp/mihomo.log mihomo.log 5000
run ls -ltZ /data/tombstones
run ls -ltZ /data/anr
logcat -b all -d -v threadtime -t 8000 >"$OUT/logcat_tail.txt" 2>&1
grep -iE 'deltaforge|forge|tersafe|libUE4|com\.tencent\.tmgp\.dfm|FATAL EXCEPTION|Fatal signal|tombstone|avc:' "$OUT/logcat_tail.txt" >"$OUT/logcat_relevant.txt" 2>&1
{
    for t in $(ls -1t /data/tombstones/tombstone_* 2>/dev/null | head -n 3); do
        echo "===== $t ====="
        sed -n '1,1200p' "$t"
    done
} >"$OUT/recent_tombstones.txt" 2>&1

section "SUMMARY POINTERS"
echo "report_dir=$OUT"
echo "game_pid=${PID:-not-running}"
echo "forge_pid=$(pidof forge 2>/dev/null)"
echo "mihomo_pid=$(pidof mihomo 2>/dev/null)"
echo "tcp_9510=$(grep -cE '(^|:)9510([[:space:]]|$)' "$OUT/listening_sockets.txt" 2>/dev/null)"
echo "uds_socket=$(test -S /data/local/tmp/forge_ipc.sock && echo present || echo absent)"

exec 1>&3 2>&4
ARCHIVE="${OUT}.tar.gz"
tar -C /data/local/tmp -czf "$ARCHIVE" "$(basename "$OUT")"
chmod 0644 "$ARCHIVE"

HOME_COPY="$TERMUX_HOME/$(basename "$ARCHIVE")"
cp -p "$ARCHIVE" "$HOME_COPY" 2>/dev/null
if [ -f "$HOME_COPY" ]; then
    TUID="$(stat -c %u "$TERMUX_HOME" 2>/dev/null)"
    TGID="$(stat -c %g "$TERMUX_HOME" 2>/dev/null)"
    [ -n "$TUID" ] && chown "$TUID:$TGID" "$HOME_COPY" 2>/dev/null
fi

DOWNLOAD_COPY="/sdcard/Download/$(basename "$ARCHIVE")"
if [ -d /sdcard/Download ]; then
    cp -p "$ARCHIVE" "$DOWNLOAD_COPY" 2>/dev/null
fi

echo "Collection complete."
echo "Report:  $REPORT"
echo "Archive: $ARCHIVE"
[ -f "$HOME_COPY" ] && echo "Termux:  $HOME_COPY"
[ -f "$DOWNLOAD_COPY" ] && echo "Download: $DOWNLOAD_COPY"
ls -lh "$ARCHIVE" "$HOME_COPY" "$DOWNLOAD_COPY" 2>/dev/null
