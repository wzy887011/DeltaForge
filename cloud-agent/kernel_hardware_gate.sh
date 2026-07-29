#!/system/bin/sh
# DeltaForge v8.7 image/kernel/hardware capability gate. No state changes.
set -u

OUT=${1:-/data/local/tmp/deltaforge_kernel_hardware_gate.txt}
pass=0
fail=0

ok() { pass=$((pass + 1)); printf '[PASS] %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf '[BLOCKED_IMAGE] %s\n' "$*"; }
check_node() { [ -e "$1" ] && ok "node $1" || bad "missing node $1"; }

run_gate() {
    printf 'DeltaForge kernel/hardware integration gate\n'
    printf 'timestamp=%s\n' "$(date -Ins 2>/dev/null || date)"

    [ "$(getenforce 2>/dev/null)" = Enforcing ] \
        && ok 'SELinux enforcing' || bad 'base image must boot SELinux enforcing'
    [ -r /sys/fs/selinux/policy ] \
        && ok 'SELinux policy loaded' || bad 'SELinux policy file unavailable'
    [ "$(uname -m 2>/dev/null)" = aarch64 ] \
        && ok 'AArch64 kernel' || bad "unexpected architecture=$(uname -m 2>/dev/null)"

    grep -aq 'qcom,sm8150' /sys/firmware/devicetree/base/compatible 2>/dev/null \
        && ok 'SM8150 Device Tree compatible' || bad 'base DT is not qcom,sm8150'
    check_node /sys/devices/soc0/family
    check_node /sys/devices/soc0/machine
    check_node /sys/class/kgsl/kgsl-3d0
    check_node /dev/kgsl-3d0

    kgsl_model="$(cat /sys/class/kgsl/kgsl-3d0/gpu_model 2>/dev/null)"
    printf '%s' "$kgsl_model" | grep -qiE 'Adreno.*640|A640' \
        && ok "KGSL model=$kgsl_model" || bad "KGSL model is not Adreno 640: $kgsl_model"

    keymint="$(lshal 2>/dev/null | grep -iE 'keymint|keymaster' | head -n 1)"
    [ -n "$keymint" ] && ok "KeyMint/Keymaster HAL present" || bad 'KeyMint/Keymaster HAL absent'
    tee_hal="$(lshal 2>/dev/null | grep -iE 'gatekeeper|sharedsecret|secureclock|strongbox' | head -n 1)"
    [ -n "$tee_hal" ] && ok 'TEE-backed security HAL evidence present' || bad 'TEE-backed security HAL evidence absent'

    if [ -r /proc/config.gz ]; then
        for option in CONFIG_SECURITY_SELINUX CONFIG_SECCOMP CONFIG_NAMESPACES CONFIG_CGROUPS; do
            zcat /proc/config.gz 2>/dev/null | grep -q "^$option=y" \
                && ok "$option=y" || bad "$option is not built-in"
        done
    else
        bad 'kernel config unavailable; image provenance cannot be verified'
    fi

    for path in /system/xbin/s9su /system/bin/su /system/xbin/su; do
        [ -e "$path" ] && bad "public root binary remains $path" || ok "absent $path"
    done
    ps -A 2>/dev/null | grep -q 'rockchip\.hardware' \
        && bad 'Rockchip vendor service remains' || ok 'Rockchip vendor services absent'

    printf '[SUMMARY] pass=%d blocked=%d\n' "$pass" "$fail"
    [ "$fail" -eq 0 ]
}

mkdir -p "$(dirname "$OUT")"
if run_gate >"$OUT" 2>&1; then rc=0; else rc=$?; fi
cat "$OUT"
exit "$rc"
