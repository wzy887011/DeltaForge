#!/system/bin/sh
# DeltaForge 8.7 system identity overlay. Original proc/sysfs nodes remain
# untouched; read-only bind mounts can be removed with: $0 rollback
set -u

ACTION="${1:-apply}"
WORK="/data/local/tmp/deltaforge_identity.work"
MOUNTS="$WORK/mounts.state"
PROFILE="SM-G9730 / Android 11 / Snapdragon 855"
RESET_PROP=""

log() { printf '[identity] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" = "0" ] || die "root required"

find_resetprop() {
    for p in /system/bin/resetprop /data/adb/magisk/resetprop /data/adb/ksu/bin/resetprop /data/local/tmp/resetprop /sbin/resetprop; do
        if [ -x "$p" ]; then RESET_PROP="$p"; return 0; fi
    done
    return 1
}

unmount_overlay() {
    if [ -f "$MOUNTS" ]; then
        while IFS= read -r target; do
            [ -n "$target" ] && umount -l "$target" 2>/dev/null || true
        done < "$MOUNTS"
        : > "$MOUNTS"
    fi
}

restore_display() {
    if [ -f "$WORK/wm_size.before" ]; then
        before="$(cat "$WORK/wm_size.before")"
        [ -n "$before" ] && wm size "$before" 2>/dev/null || wm size reset 2>/dev/null
    else
        wm size reset 2>/dev/null
    fi
    if [ -f "$WORK/wm_density.before" ]; then
        before="$(cat "$WORK/wm_density.before")"
        [ -n "$before" ] && wm density "$before" 2>/dev/null || wm density reset 2>/dev/null
    else
        wm density reset 2>/dev/null
    fi
}

restore_properties() {
    [ -f "$WORK/props.before" ] || return 0
    find_resetprop || { log "resetprop absent; property snapshot not restored"; return 0; }
    while IFS='|' read -r key present value; do
        [ -n "$key" ] || continue
        if [ "$present" = 1 ]; then
            "$RESET_PROP" "$key" "$value" 2>/dev/null || true
        else
            "$RESET_PROP" --delete "$key" 2>/dev/null || "$RESET_PROP" "$key" "" 2>/dev/null || true
        fi
    done < "$WORK/props.before"
    log "global properties restored"
}

if [ "$ACTION" = "rollback" ]; then
    unmount_overlay
    restore_display
    restore_properties
    rm -f "$WORK/wm_size.before" "$WORK/wm_density.before" \
        "$WORK/props.before" "$WORK/props.profile" "$MOUNTS"
    log "rollback complete"
    exit 0
fi
if [ "$ACTION" = "status" ]; then
    log "profile=$PROFILE"
    cat "$MOUNTS" 2>/dev/null || true
    wm size 2>/dev/null
    wm density 2>/dev/null
    exit 0
fi
[ "$ACTION" = "apply" ] || die "usage: $0 [apply|rollback|status]"

mkdir -p "$WORK" || die "cannot create $WORK"
chmod 0700 "$WORK"

cat > "$WORK/props.profile" <<'EOF'
ro.product.manufacturer|samsung
ro.product.brand|samsung
ro.product.model|SM-G9730
ro.product.device|beyond1q
ro.product.name|beyond1qltezc
ro.product.odm.brand|samsung
ro.product.odm.device|beyond1q
ro.product.odm.manufacturer|samsung
ro.product.odm.model|SM-G9730
ro.product.odm.name|beyond1qltezc
ro.product.product.brand|samsung
ro.product.product.device|beyond1q
ro.product.product.manufacturer|samsung
ro.product.product.model|SM-G9730
ro.product.product.name|beyond1qltezc
ro.product.system.brand|samsung
ro.product.system.device|beyond1q
ro.product.system.manufacturer|samsung
ro.product.system.model|SM-G9730
ro.product.system.name|beyond1qltezc
ro.product.system_ext.brand|samsung
ro.product.system_ext.device|beyond1q
ro.product.system_ext.manufacturer|samsung
ro.product.system_ext.model|SM-G9730
ro.product.system_ext.name|beyond1qltezc
ro.product.vendor.brand|samsung
ro.product.vendor.device|beyond1q
ro.product.vendor.manufacturer|samsung
ro.product.vendor.model|SM-G9730
ro.product.vendor.name|beyond1qltezc
ro.hardware|qcom
ro.boot.hardware|qcom
ro.board.platform|msmnile
ro.product.board|msmnile
ro.soc.manufacturer|QUALCOMM
ro.soc.model|SM8150
ro.hardware.egl|adreno
ro.hardware.gralloc|adreno
ro.hardware.vulkan|adreno
ro.opengles.version|196610
ro.sf.lcd_density|420
ro.build.version.sdk|30
ro.build.version.release|11
ro.build.type|user
ro.build.tags|release-keys
ro.debuggable|0
ro.secure|1
ro.adb.secure|1
ro.boot.verifiedbootstate|green
ro.boot.veritymode|enforcing
ro.boot.flash.locked|1
EOF
chmod 0600 "$WORK/props.profile"

if [ ! -f "$WORK/wm_size.before" ]; then
    wm size 2>/dev/null | sed -n 's/^Override size: //p' | head -n 1 > "$WORK/wm_size.before"
fi
if [ ! -f "$WORK/wm_density.before" ]; then
    wm density 2>/dev/null | sed -n 's/^Override density: //p' | head -n 1 > "$WORK/wm_density.before"
fi

cat > "$WORK/cpuinfo" <<'EOF'
processor	: 0
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x805
CPU revision	: 14

processor	: 1
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x805
CPU revision	: 14

processor	: 2
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x805
CPU revision	: 14

processor	: 3
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x0
CPU part	: 0x805
CPU revision	: 14

processor	: 4
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0x804
CPU revision	: 14

processor	: 5
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0x804
CPU revision	: 14

processor	: 6
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0x804
CPU revision	: 14

processor	: 7
BogoMIPS	: 38.40
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0x804
CPU revision	: 14

Hardware	: Qualcomm Technologies, Inc SM8150
EOF
cat > "$WORK/version" <<'EOF'
Linux version 4.14.190-perf+ (dpi@SWDD6847) (Android clang version 9.0.8) #1 SMP PREEMPT Tue Jun 15 10:30:00 KST 2021
EOF
printf '4.14.190-perf+\n' > "$WORK/osrelease"
cat > "$WORK/cmdline" <<'EOF'
androidboot.hardware=qcom androidboot.bootloader=unknown androidboot.veritymode=enforcing androidboot.verifiedbootstate=green androidboot.slot_suffix=_a buildvariant=user rootwait ro init=/init rcupdate.rcu_expedited=1 rcu_nocbs=0-7
EOF
printf 'Samsung Galaxy S10 (SM-G9730)\000' > "$WORK/dt_model"
printf 'samsung,beyond1q\000qcom,sm8150\000' > "$WORK/dt_compatible"
chmod 0444 "$WORK/cpuinfo" "$WORK/version" "$WORK/osrelease" "$WORK/cmdline" \
    "$WORK/dt_model" "$WORK/dt_compatible"

unmount_overlay
bind_one() {
    src="$1"; dst="$2"
    [ -e "$dst" ] || { log "skip missing target $dst"; return 0; }
    if mount --bind "$src" "$dst" 2>/dev/null; then
        mount -o remount,bind,ro "$dst" 2>/dev/null || true
        printf '%s\n' "$dst" >> "$MOUNTS"
        log "bound $dst"
    else
        log "bind failed $dst"
    fi
}

bind_one "$WORK/cpuinfo" /proc/cpuinfo
bind_one "$WORK/version" /proc/version
bind_one "$WORK/osrelease" /proc/sys/kernel/osrelease
bind_one "$WORK/cmdline" /proc/cmdline
bind_one "$WORK/dt_model" /sys/firmware/devicetree/base/model
bind_one "$WORK/dt_compatible" /sys/firmware/devicetree/base/compatible

if find_resetprop; then
    if [ ! -f "$WORK/props.before" ]; then
        while IFS='|' read -r key value; do
            [ -n "$key" ] || continue
            old="$(getprop "$key" 2>/dev/null)"
            if getprop 2>/dev/null | grep -Fq "[$key]:"; then
                printf '%s|1|%s\n' "$key" "$old"
            else
                printf '%s|0|\n' "$key"
            fi
        done < "$WORK/props.profile" > "$WORK/props.before"
        chmod 0600 "$WORK/props.before"
    fi
    while IFS='|' read -r key value; do
        [ -n "$key" ] && "$RESET_PROP" "$key" "$value" 2>/dev/null || true
    done < "$WORK/props.profile"
    log "global properties applied with $RESET_PROP"
else
    log "resetprop absent; process hook remains the property fallback"
fi

# SM-G9730 supports FHD+ mode; this keeps its 19:9 aspect without WQHD cost.
wm size 1080x2280 2>/dev/null || true
wm density 420 2>/dev/null || true

log "apply complete profile=$PROFILE"
