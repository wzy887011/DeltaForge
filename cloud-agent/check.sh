# DeltaForge v6.0 — 诊断脚本
# 用法: su -c 'sh /data/local/tmp/check.sh'
echo "=========================================="
echo " DeltaForge v6.0 诊断"
echo " $(date)"
echo "=========================================="

echo ""
echo "--- 1. hijack 状态 ---"
HIJACK=$(find /data/app -name libtdmqimei_real.so 2>/dev/null | head -1)
if [ -n "$HIJACK" ]; then
    DIR=$(dirname "$HIJACK")
    echo "hijack 已安装: $DIR"
    echo "  libtdmqimei.so      (应为 v5.8 hook):"
    ls -la "$DIR/libtdmqimei.so" 2>/dev/null
    echo "  libtdmqimei_real.so (应为原版 qimei):"
    ls -la "$DIR/libtdmqimei_real.so" 2>/dev/null
    VER=$(strings "$DIR/libtdmqimei.so" 2>/dev/null | grep "libforgehook.c v" | head -1)
    echo "  hook 版本: ${VER:-未找到版本字符串}"
    echo ""
    echo "  MD5:"
    md5sum "$DIR/libtdmqimei.so" /data/local/tmp/libforgehook.so 2>/dev/null
else
    echo "hijack 未安装! 运行: su -c 'sh /data/local/tmp/df-hijack-root.sh'"
fi

echo ""
echo "--- 2. /data/local/tmp/ 文件 ---"
ls -la /data/local/tmp/forge /data/local/tmp/libforgehook.so /data/local/tmp/injector 2>/dev/null

echo ""
echo "--- 3. forge_hook.log ---"
if [ -f /data/data/com.tencent.tmgp.dfm/files/forge_hook.log ]; then
    cat /data/data/com.tencent.tmgp.dfm/files/forge_hook.log
else
    echo "文件不存在 — hook constructor 未执行"
fi

echo ""
echo "--- 4. forge_audit.log (最后10行) ---"
tail -10 /data/data/com.tencent.tmgp.dfm/files/forge_audit.log 2>/dev/null || echo "文件不存在"

echo ""
echo "--- 5. 最新 tombstone ---"
LATEST=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
if [ -n "$LATEST" ]; then
    echo "文件: $LATEST ($(stat -c %s "$LATEST" 2>/dev/null || echo '?') bytes)"
    echo "时间: $(ls -l "$LATEST" | awk '{print $6,$7,$8}')"
    echo ""
    head -35 "$LATEST"
else
    echo "无 tombstone"
fi

echo ""
echo "--- 6. 游戏进程 ---"
PID=$(pidof com.tencent.tmgp.dfm 2>/dev/null)
if [ -n "$PID" ]; then
    echo "运行中 PID=$PID"
    echo "maps 中的关键库:"
    grep -E "libforgehook|libtersafe|libtdmqimei" /proc/$PID/maps 2>/dev/null | head -10
else
    echo "游戏未运行"
fi

echo ""
echo "=========================================="
echo " 诊断完成"
echo "=========================================="
