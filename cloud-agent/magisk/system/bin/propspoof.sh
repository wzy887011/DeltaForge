#!/system/bin/sh
# 调用者: service.sh 第9行, 也可独立运行 (需 root)
# 读写: Android 系统属性 (resetprop/setprop), 无数据文件
#
# 注意: 云手机无 Magisk 时 resetprop 不可用，setprop 对 ro.* 无效
# 属性适配主要靠 libforgehook.so 的 __system_property_get hook
# 本脚本尽最大努力用 setprop + resetprop 双重写入

# --- 删除云手机特征属性 ---
for key in ro.kernel.qemu init.svc.vbox86-setup ro.genymotion.version \
           persist.nox.simulator_version microvirt.memu_version nemud.player_package \
           sys.tencent.init sys.tencent.model net.hostname ro.boot.qemu \
           ro.boot.qemu.avd_name ro.boot.qemu.cpuvulkan.version ro.kernel.android.qemud \
           qemu.hw.mainkeys qemu.sf.lcd_density; do
    resetprop --delete "$key" 2>/dev/null
    setprop "$key" "" 2>/dev/null
done

# --- 写入适配属性 (resetprop 优先, setprop 兜底) ---
set_prop() {
    resetprop "$1" "$2" 2>/dev/null || setprop "$1" "$2" 2>/dev/null
}

set_prop ro.product.manufacturer "samsung"
set_prop ro.product.model "SM-G9730"
set_prop ro.product.device "beyond1q"
set_prop ro.product.name "beyond1qltezc"
set_prop ro.build.product "beyond1q"
set_prop ro.product.brand "samsung"
for partition in odm product system system_ext vendor; do
    set_prop "ro.product.$partition.brand" "samsung"
    set_prop "ro.product.$partition.device" "beyond1q"
    set_prop "ro.product.$partition.manufacturer" "samsung"
    set_prop "ro.product.$partition.model" "SM-G9730"
    set_prop "ro.product.$partition.name" "beyond1qltezc"
done
set_prop ro.hardware "qcom"
set_prop ro.board.platform "msmnile"
set_prop ro.product.board "msmnile"
set_prop ro.soc.manufacturer "QUALCOMM"
set_prop ro.soc.model "SM8150"
set_prop ro.hardware.egl "adreno"
set_prop ro.hardware.gralloc "adreno"
set_prop ro.hardware.vulkan "adreno"
set_prop ro.opengles.version "196610"
set_prop ro.sf.lcd_density "420"
set_prop ro.build.fingerprint "samsung/beyond1qltezc/beyond1q:11/RP1A.200720.012/G9730ZCS6FULZ:user/release-keys"
set_prop ro.build.version.sdk "30"
set_prop ro.build.version.release "11"
set_prop ro.build.version.incremental "G9730ZCS6FULZ"
set_prop ro.build.tags "release-keys"
set_prop ro.build.type "user"
set_prop ro.build.user "dpi"
set_prop ro.build.host "SWDD6847"
set_prop ro.build.description "beyond1qltezc-user 11 RP1A.200720.012 G9730ZCS6FULZ release-keys"
set_prop ro.debuggable "0"
set_prop ro.secure "1"
set_prop ro.adb.secure "1"
set_prop ro.allow.mock.location "0"
set_prop persist.sys.usb.config "adb"
set_prop gsm.version.baseband "G9730ZCS6FULZ"
set_prop ro.boot.hardware "qcom"
set_prop ro.boot.bootloader "unknown"
set_prop ro.bootmode "unknown"
set_prop ro.boot.verifiedbootstate "green"
set_prop ro.boot.veritymode "enforcing"
set_prop ro.boot.flash.locked "1"

echo "[propspoof] done ($(getprop ro.product.model 2>/dev/null || echo '(ro只读)'))"
echo "[propspoof] 无 Magisk 时只读属性可能未修改 — 依赖 libforgehook.so hook"
