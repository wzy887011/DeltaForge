#!/system/bin/sh
# DeltaForge 封号诊断 v1.0 — 后台监控游戏日志
# 用法: su -c 'sh /data/local/tmp/diagnose.sh &'
# 输出: /data/local/tmp/diagnose_<timestamp>.log

TS=$(date +%Y%m%d_%H%M%S)
LOG="/data/local/tmp/diagnose_${TS}.log"
PKG="com.tencent.tmgp.dfm"

echo "=== DeltaForge 诊断启动 $(date) ===" | tee "$LOG"

# 1. 当前设备指纹
echo "" | tee -a "$LOG"
echo "--- 设备指纹 ---" | tee -a "$LOG"
for k in ro.hardware ro.hardware.gralloc ro.hardware.egl ro.product.base_version \
         ro.product.brand ro.product.model ro.product.manufacturer ro.product.device \
         ro.build.tags ro.build.type ro.build.fingerprint ro.build.version.sdk \
         ro.build.version.release ro.product.odm.model ro.product.board \
         ro.product.odm_dlkm.manufacturer ro.product.product.device; do
    v=$(getprop "$k" 2>/dev/null)
    echo "  $k=$v" | tee -a "$LOG"
done

# 2. wrap 属性是否生效
echo "" | tee -a "$LOG"
echo "--- wrap LD_PRELOAD ---" | tee -a "$LOG"
wv=$(getprop "wrap.${PKG}" 2>/dev/null)
[ -n "$wv" ] && echo "  wrap生效: $wv" | tee -a "$LOG" || echo "  wrap未生效 — ROM不支持wrap, 依赖ptrace注入" | tee -a "$LOG"

# 3. 游戏进程状态
echo "" | tee -a "$LOG"
echo "--- 游戏进程 ---" | tee -a "$LOG"
PID=$(pidof "$PKG" 2>/dev/null)
if [ -n "$PID" ]; then
    echo "  PID=$PID" | tee -a "$LOG"
    grep -q "libforgehook" /proc/$PID/maps 2>/dev/null \
        && echo "  libforgehook: maps可见" | tee -a "$LOG" \
        || echo "  libforgehook: maps隐藏 (或未加载)" | tee -a "$LOG"
    cat /proc/$PID/status 2>/dev/null | grep -E "Seccomp:|TracerPid:" | tee -a "$LOG"
else
    echo "  游戏未运行" | tee -a "$LOG"
fi

# 4. forge 注入日志
echo "" | tee -a "$LOG"
echo "--- forge 最近注入 ---" | tee -a "$LOG"
grep -E "注入|tersafe|patch|wrap|handle=" /data/local/tmp/forge.log 2>/dev/null | tail -5 | tee -a "$LOG"

# 5. 实时 logcat — 后台持续
echo "" | tee -a "$LOG"
echo "--- 实时 logcat (后台) ---" | tee -a "$LOG"
echo "  输出: /data/local/tmp/detect_${TS}.log" | tee -a "$LOG"

su -c "logcat -v time 2>/dev/null | grep -iE 'tersafe|TSS|ACE|anti_cheat|detect|ban|forbid|kicked|violation|emulator|tencent.*malfunction|cheat_report|data_report|Qimei|TGPA|GCloud.*init|MSDK.*init|TDM.*init' > /data/local/tmp/detect_${TS}.log 2>&1 &"

echo "" | tee -a "$LOG"
echo "=== 诊断准备就绪 ===" | tee -a "$LOG"
echo "  主日志: $LOG" | tee -a "$LOG"
echo "  实时检测: /data/local/tmp/detect_${TS}.log" | tee -a "$LOG"
echo "  封号后查看: cat /data/local/tmp/detect_${TS}.log | tail -100" | tee -a "$LOG"
