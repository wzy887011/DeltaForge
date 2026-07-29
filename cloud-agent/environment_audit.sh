#!/system/bin/sh
# Read-only external observer for Android application environment access.
set -u

PKG=${PKG:-com.tencent.tmgp.dfm}
DURATION=${1:-60}
OUT=${2:-/data/local/tmp/deltaforge_env_audit_$(date +%Y%m%d_%H%M%S)}
case "$DURATION" in *[!0-9]*|'') echo 'duration must be an integer'; exit 2;; esac
[ "$DURATION" -ge 1 ] || { echo 'duration must be positive'; exit 2; }

PID="$(pidof "$PKG" 2>/dev/null | awk '{print $1}')"
[ -n "$PID" ] || { echo "package process not running: $PKG"; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'run as root'; exit 1; }
HOOK_ACTIVE=0
grep -q 'libforgehook.so' "/proc/$PID/maps" 2>/dev/null && HOOK_ACTIVE=1
if [ "$HOOK_ACTIVE" = 1 ] && [ "${ALLOW_HOOKED:-0}" != 1 ]; then
    echo 'libforgehook.so is active; launch the original application or set ALLOW_HOOKED=1 for a labeled comparison trace'
    exit 3
fi

WORK="$OUT.work.$$"
[ ! -e "$OUT" ] || { echo "output already exists: $OUT"; exit 1; }
mkdir -p "$WORK"
cleanup() { [ -n "${TRACE_PID:-}" ] && kill -INT "$TRACE_PID" 2>/dev/null || true; }
trap cleanup INT TERM EXIT

{
    echo "schema=1"
    echo "package=$PKG"
    echo "pid=$PID"
    echo "duration=$DURATION"
    echo "hook_active=$HOOK_ACTIVE"
    echo "started=$(date -Ins 2>/dev/null || date)"
    echo "kernel=$(uname -a 2>/dev/null)"
    echo "selinux=$(getenforce 2>/dev/null)"
} > "$WORK/metadata.txt"

cp "/proc/$PID/maps" "$WORK/maps.before.txt" 2>/dev/null || true
cp "/proc/$PID/mountinfo" "$WORK/mountinfo.txt" 2>/dev/null || true
getprop > "$WORK/properties.snapshot.txt" 2>/dev/null || true
lshal > "$WORK/lshal.snapshot.txt" 2>/dev/null || true

STRINGS="$(command -v strings 2>/dev/null || true)"
[ -n "$STRINGS" ] || STRINGS=/data/data/com.termux/files/usr/bin/strings
READELF="$(command -v readelf 2>/dev/null || true)"
SHA256SUM="$(command -v sha256sum 2>/dev/null || true)"
APP_APK="$(pm path "$PKG" 2>/dev/null | sed -n 's/^package://p' | head -n 1)"
APP_DIR="$(dirname "$APP_APK" 2>/dev/null)"
: > "$WORK/static_candidates.tsv"
: > "$WORK/native_inventory.tsv"
if [ -x "$STRINGS" ] && [ -d "$APP_DIR/lib/arm64" ]; then
    for so in "$APP_DIR"/lib/arm64/*.so; do
        [ -f "$so" ] || continue
        module="$(basename "$so")"
        case "$module" in
            libtersafe.so|libTDataMaster.so|libtdmqimei.so|libUE4.so|*qimei*|*Qimei*|*turing*|*Turing*|*hawk*|*Hawk*|*CrashSight*)
                bytes="$(wc -c < "$so" | tr -d ' ')"
                sha256=""
                [ -n "$SHA256SUM" ] && sha256="$($SHA256SUM "$so" 2>/dev/null | awk '{print $1}')"
                build_id=""
                [ -n "$READELF" ] && build_id="$($READELF -n "$so" 2>/dev/null | sed -n 's/.*Build ID: //p' | head -n 1)"
                versions="$($STRINGS -a "$so" 2>/dev/null | \
                    grep -E 'GCLOUD_VERSION_TDM_|[0-9]+\.[0-9]{2,3}\.[0-9]{2,3}\.[0-9]+' | \
                    head -n 8 | tr '\t\r\n' '   ')"
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$module" "$bytes" "$sha256" "$build_id" "$versions" "$so" \
                    >> "$WORK/native_inventory.tsv"
                ;;
        esac
        "$STRINGS" -a "$so" 2>/dev/null | awk -v module="$module" '
            function emit(kind, value) {
                print module "\t" kind "\t" value
                emitted++
                if (emitted >= 2000) exit
            }
            length($0) > 512 { next }
            /^(ro|persist|vendor|sys|debug)\.[A-Za-z0-9._-]+$/ {
                emit("property", $0); next
            }
            /^\/(proc|sys|dev|system|vendor|odm|data)\/[A-Za-z0-9._\/@:+-]+$/ {
                emit("path", $0); next
            }
            tolower($0) ~ /(keymint|keymaster|strongbox|gatekeeper|kgsl|adreno|mali|selinux|mountinfo|cpuinfo|qemu|virtual|cloud|container|lxc|magisk|xposed|frida|tersafe|tss_ano|ano_tmp|tdatamaster|tdm_tmp|qimei|turing|hawk|crashsight|android_id|settings_ssaid|serial_number|ro.serialno|build.fingerprint)/ {
                emit("token", $0)
            }
        ' >> "$WORK/static_candidates.tsv"
    done
    sort -u "$WORK/static_candidates.tsv" -o "$WORK/static_candidates.tsv"
else
    echo 'static scan skipped: strings or application library directory unavailable' \
        >> "$WORK/metadata.txt"
fi

STRACE="$(command -v strace 2>/dev/null || true)"
[ -n "$STRACE" ] || STRACE=/data/data/com.termux/files/usr/bin/strace
if [ -x "$STRACE" ]; then
    set --
    for task in "/proc/$PID/task"/*; do
        tid="${task##*/}"
        case "$tid" in *[!0-9]*|'') continue;; esac
        set -- "$@" -p "$tid"
    done
    "$STRACE" -ff -ttt -T -yy -s 256 -o "$WORK/strace" \
        -e trace=%file,%network,ioctl,uname,sysinfo,prctl "$@" \
        2> "$WORK/strace.stderr.txt" &
    TRACE_PID=$!
    sleep "$DURATION"
    kill -INT "$TRACE_PID" 2>/dev/null || true
    wait "$TRACE_PID" 2>/dev/null || true
    TRACE_PID=""
else
    echo 'dynamic syscall trace skipped: strace unavailable' >> "$WORK/metadata.txt"
    sleep "$DURATION"
fi

cp "/proc/$PID/maps" "$WORK/maps.after.txt" 2>/dev/null || true
logcat -d -v threadtime -t 20000 > "$WORK/logcat.txt" 2>/dev/null || true
echo "finished=$(date -Ins 2>/dev/null || date)" >> "$WORK/metadata.txt"

PYTHON="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
[ -n "$PYTHON" ] || PYTHON=/data/data/com.termux/files/usr/bin/python
REPORTER=/data/local/tmp/environment_audit_report.py
if [ -x "$PYTHON" ] && [ -r "$REPORTER" ]; then
    "$PYTHON" "$REPORTER" "$WORK" --json "$WORK/report.json" \
        > "$WORK/report.txt" 2>&1 || true
fi

mv "$WORK" "$OUT"
trap - INT TERM EXIT
echo "audit_dir=$OUT"
[ -f "$OUT/report.txt" ] && cat "$OUT/report.txt"
