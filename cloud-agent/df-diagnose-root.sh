#!/system/bin/sh
# df-diagnose-root.sh — root 侧诊断采集, 后台 logcat 监控
TS=$(date +%Y%m%d_%H%M%S)
LOG="/data/local/tmp/diagnose_${TS}.log"
PKG="com.tencent.tmgp.dfm"

echo "=== DeltaForge diagnose $(date) ===" | tee "$LOG"

echo "--- device ---" | tee -a "$LOG"
for k in ro.hardware ro.product.brand ro.product.model ro.product.manufacturer \
         ro.product.device ro.build.tags ro.build.type ro.build.version.release \
         ro.build.fingerprint; do
    v=$(getprop "$k" 2>/dev/null)
    echo "  $k=$v" | tee -a "$LOG"
done

echo "--- wrap ---" | tee -a "$LOG"
wv=$(getprop "wrap.${PKG}" 2>/dev/null)
echo "  wrap=${wv:-not set}" | tee -a "$LOG"

echo "--- game ---" | tee -a "$LOG"
PID=$(pidof "$PKG" 2>/dev/null)
if [ -n "$PID" ]; then
    echo "  PID=$PID" | tee -a "$LOG"
    cat /proc/$PID/status 2>/dev/null | grep -E "Seccomp|TracerPid" | tee -a "$LOG"
    grep -cE "libforgehook|libtdmqimei" /proc/$PID/maps 2>/dev/null
    echo "  hook_in_maps=$?" | tee -a "$LOG"
else
    echo "  PID: not running" | tee -a "$LOG"
fi

echo "--- hijack ---" | tee -a "$LOG"
GLIB=$(find /data/app -type f -name "libtdmqimei.so" 2>/dev/null | head -1)
if [ -n "$GLIB" ]; then
    ls -l "$GLIB" | tee -a "$LOG"
    [ -f "$(dirname "$GLIB")/libtdmqimei_real.so" ] && echo "  backup: yes" | tee -a "$LOG"
else
    echo "  hijack: not installed" | tee -a "$LOG"
fi

echo "--- forge.log ---" | tee -a "$LOG"
tail -5 /data/local/tmp/forge.log 2>/dev/null | tee -a "$LOG"

echo "--- logcat bg ---" | tee -a "$LOG"
killall logcat 2>/dev/null; sleep 1; logcat -c 2>/dev/null
logcat -v time 2>/dev/null \
    | grep -iE "tersafe|TSS|ACE|Qimei|TGPA|GCloud.*init|MSDK.*init|TDM.*init|anti.cheat|forbid|ban|frozen|kicked|emulator" \
    > /data/local/tmp/detect_${TS}.log 2>&1 &
echo "  bg PID=$! log=/data/local/tmp/detect_${TS}.log" | tee -a "$LOG"

echo "=== diagnose done ===" | tee -a "$LOG"
