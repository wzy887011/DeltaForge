#!/system/bin/sh
# 调用者: service.sh 第9行, 也可独立运行 (需 root)
# 读写: Android 系统属性 (resetprop/setprop), 无数据文件
#
# 注意: 云手机无 Magisk 时 resetprop 不可用，setprop 对 ro.* 无效
# 属性伪装主要靠 libforgehook.so 的 __system_property_get hook
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

# --- 写入伪装属性 (resetprop 优先, setprop 兜底) ---
set_prop() {
    resetprop "$1" "$2" 2>/dev/null || setprop "$1" "$2" 2>/dev/null
}

set_prop ro.product.manufacturer "Xiaomi"
set_prop ro.product.model "23049RAD8C"
set_prop ro.product.device "marble"
set_prop ro.product.name "marble"
set_prop ro.build.product "marble"
set_prop ro.product.brand "Xiaomi"
set_prop ro.hardware "qcom"
set_prop ro.board.platform "kalama"
set_prop ro.product.board "kalama"
set_prop ro.build.fingerprint "Xiaomi/marble/marble:14/UKQ1.231108.001/V816.0.9.0.UMRCNXM:user/release-keys"
set_prop ro.build.version.sdk "34"
set_prop ro.build.version.release "14"
set_prop ro.build.version.incremental "V816.0.9.0.UMRCNXM"
set_prop ro.build.tags "release-keys"
set_prop ro.build.type "user"
set_prop ro.build.user "builder"
set_prop ro.build.host "m1-xm-bsp-01"
set_prop ro.build.description "marble-user 14 UKQ1.231108.001 V816.0.9.0.UMRCNXM release-keys"
set_prop ro.debuggable "0"
set_prop ro.secure "1"
set_prop ro.adb.secure "1"
set_prop ro.allow.mock.location "0"
set_prop persist.sys.usb.config "adb"
set_prop gsm.version.baseband "MPSS.TH.5.0-05076-OmniGen_PACK-1"
set_prop ro.boot.hardware "qcom"
set_prop ro.boot.bootloader "unknown"
set_prop ro.bootmode "unknown"
set_prop ro.boot.verifiedbootstate "green"
set_prop ro.boot.veritymode "enforcing"
set_prop ro.boot.flash.locked "1"

echo "[propspoof] done ($(getprop ro.product.model 2>/dev/null || echo '(ro只读)'))"
echo "[propspoof] 无 Magisk 时只读属性可能未修改 — 依赖 libforgehook.so hook"
