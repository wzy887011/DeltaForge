#!/system/bin/sh
# diagnose_device.sh — 云机设备路径诊断
# 找出 serial/SSAID/属性存储的实际位置，用于修复 L1/L4
# 用法: su -c "sh /data/local/tmp/diagnose_device.sh"

echo "=============================================="
echo " DeltaForge 设备路径诊断"
echo "=============================================="
echo ""

echo "--- Android 版本 ---"
getprop ro.build.version.release
getprop ro.build.version.sdk
echo ""

echo "--- serial_number sysfs 路径 ---"
find /sys -name "serial*" -readable 2>/dev/null | head -20
find /sys/devices/soc* -maxdepth 2 2>/dev/null | head -20
echo ""

echo "--- SSAID/Settings 存储位置 ---"
find /data/system -name "*ssaid*" 2>/dev/null
find /data/system/users -name "*.xml" -size +1k 2>/dev/null | head -10
find /data/system -name "settings*.db" 2>/dev/null | head -5
echo ""

echo "--- Android ID 当前值 ---"
settings get secure android_id 2>/dev/null
echo ""

echo "--- OAID/VAID 文件 ---"
ls -la /data/system/oaid* 2>/dev/null || echo "(未找到 oaid)"
ls -la /data/system/vaid* 2>/dev/null || echo "(未找到 vaid)"
cat /data/system/oaid_persistence_0 2>/dev/null && echo "" || true
echo ""

echo "--- resetprop 位置 ---"
for p in /system/bin/resetprop /data/adb/magisk/resetprop /data/adb/ksu/bin/resetprop /data/local/tmp/resetprop /sbin/resetprop; do
    [ -f "$p" ] && echo "FOUND: $p" || echo "miss:  $p"
done
echo ""

echo "--- 系统挂载点 (排查mount权限) ---"
mount | grep -E "system|vendor|cgroup|proc" | head -15
echo ""

echo "--- Property fail 分析 (ro.* 可改性) ---"
getprop ro.serialno
getprop ro.product.model
getprop ro.hardware
getprop ro.boot.verifiedbootstate
echo ""

echo "--- /proc/cpuinfo SoC 信息 ---"
grep -E "Hardware|Revision|Serial" /proc/cpuinfo 2>/dev/null | head -5
echo ""

echo "--- DFM 目录状态 ---"
ls /data/data/com.tencent.tmgp.dfm/files/ 2>/dev/null | head -20
ls /data/user/0/com.tencent.tmgp.dfm/files/ 2>/dev/null | head -10
echo ""

echo "=============================================="
echo " 诊断完成"
echo "=============================================="
