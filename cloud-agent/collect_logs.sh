#!/system/bin/sh
# DeltaForge 崩溃后一键日志采集
# 用法: su -c 'sh /data/local/tmp/collect_logs.sh'
# 输出一份汇总文件并直接打印，复制粘贴发出去就行，不用再一条条跑 grep

OUT=/data/local/tmp/report_$(date +%s).txt

{
echo "===== forge.log (tail 20) ====="
tail -20 /data/local/tmp/forge.log 2>/dev/null

echo ""
echo "===== forge_monitor.log (tail 20) ====="
tail -20 /data/local/tmp/forge_monitor.log 2>/dev/null

echo ""
echo "===== forge_hook.log (若存在) ====="
cat /data/local/tmp/forge_hook.log 2>/dev/null

echo ""
echo "===== detect_now.log (tail 20) ====="
tail -20 /data/local/tmp/detect_now.log 2>/dev/null

echo ""
echo "===== forge_audit.log (游戏data目录, 若存在) ====="
cat /data/data/com.tencent.tmgp.dfm/files/forge_audit.log 2>/dev/null | tail -20

echo ""
echo "===== 最新 tombstone ====="
LATEST=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
echo "文件: $LATEST"
if [ -n "$LATEST" ]; then
    head -20 "$LATEST"
    echo "--- 全部线程 pid/tid/pc/backtrace ---"
    grep -E "pid:|tid:|#00 pc|#01 pc|#02 pc|#03 pc" "$LATEST"
fi

echo ""
echo "===== 进程状态 ====="
ps -A 2>/dev/null | grep -E "forge|dfm"

} > "$OUT" 2>&1

echo "报告已生成: $OUT"
echo "===================================="
cat "$OUT"
