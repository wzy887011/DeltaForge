#!/system/bin/sh
# DeltaForge v6.1 — 诊断脚本 (自动判断崩溃阶段)
# 用法: su -c 'sh /data/local/tmp/check.sh'

PKG="com.tencent.tmgp.dfm"
TMP="/data/local/tmp"
APP="/data/data/$PKG"

echo "=========================================="
echo " DeltaForge v6.1 诊断"
echo " $(date)"
echo "=========================================="

echo ""
echo "--- 1. hijack 状态 ---"
HIJACK=$(find /data/app -name libtdmqimei_real.so 2>/dev/null | head -1)
if [ -n "$HIJACK" ]; then
    DIR=$(dirname "$HIJACK")
    echo "hijack 已安装: $DIR"
    HIJACK_SO="$DIR/libtdmqimei.so"
    REAL_SO="$DIR/libtdmqimei_real.so"
    echo "  libtdmqimei.so      ($(stat -c %s "$HIJACK_SO" 2>/dev/null || echo '?') bytes)"
    ls -la "$HIJACK_SO" 2>/dev/null
    echo "  libtdmqimei_real.so ($(stat -c %s "$REAL_SO" 2>/dev/null || echo '?') bytes)"
    ls -la "$REAL_SO" 2>/dev/null

    # 检查 so 有效性
    echo ""
    echo "  ELF 验证:"
    file "$HIJACK_SO" 2>/dev/null || echo "    file 命令不可用"
    # 检查是否有未定义符号
    readelf -s "$HIJACK_SO" 2>/dev/null | grep -c "UND" | xargs -I{} echo "    未定义符号数: {}" 2>/dev/null

    echo ""
    echo "  MD5 交叉验证:"
    md5sum "$HIJACK_SO" $TMP/libforgehook.so 2>/dev/null
    HIJACK_MD5=$(md5sum "$HIJACK_SO" 2>/dev/null | awk '{print $1}')
    TMP_MD5=$(md5sum $TMP/libforgehook.so 2>/dev/null | awk '{print $1}')
    if [ "$HIJACK_MD5" = "$TMP_MD5" ] && [ -n "$HIJACK_MD5" ]; then
        echo "  ✓ MD5 一致"
    else
        echo "  ✗ MD5 不一致! hijack=$HIJACK_MD5 tmp=$TMP_MD5"
    fi
else
    echo "hijack 未安装! 运行: su -c 'sh $TMP/df-hijack-root.sh'"
fi

echo ""
echo "--- 2. /data/local/tmp/ 二进制 ---"
ls -la $TMP/forge $TMP/libforgehook.so $TMP/injector 2>/dev/null

echo ""
echo "--- 3. hook constructor 执行追踪 ---"
# constructor(48) 写入 /data/local/tmp/forge_hook.log
# App 内日志写 /data/data/$PKG/files/forge_hook.log
HOOK_TMP="$TMP/forge_hook.log"
HOOK_APP="$APP/files/forge_hook.log"
HOOK_AUDIT="$APP/files/forge_audit.log"
FOUND=0

for LP in "$HOOK_TMP" "$HOOK_APP"; do
    if [ -f "$LP" ]; then
        FOUND=1
        SIZE=$(stat -c %s "$LP" 2>/dev/null || echo '?')
        echo "[$LP] ($SIZE bytes):"
        echo "---begin---"
        cat "$LP"
        echo "---end---"
        echo ""

        # 追踪 constructor 执行顺序
        echo "  constructor 执行顺序:"
        grep "\[CTOR\]" "$LP" 2>/dev/null | while read -r line; do
            echo "    $line"
        done

        # 找最后执行的 constructor
        LAST_CTOR=$(grep "\[CTOR\].*enter" "$LP" 2>/dev/null | tail -1)
        LAST_DONE=$(grep "\[CTOR\].*done" "$LP" 2>/dev/null | tail -1)
        echo ""
        echo "  ▶ 最后进入: ${LAST_CTOR:-无}"
        echo "  ▶ 最后完成: ${LAST_DONE:-无}"

        # 判断崩溃阶段
        if echo "$LAST_CTOR" | grep -q "enter"; then
            CTOR_NUM=$(echo "$LAST_CTOR" | grep -oE '[0-9]+' | head -1)
            if echo "$LAST_DONE" | grep -q "done"; then
                DONE_NUM=$(echo "$LAST_DONE" | grep -oE '[0-9]+' | head -1)
                if [ "$CTOR_NUM" != "$DONE_NUM" ]; then
                    echo "  ⚡ 崩溃发生在 constructor($CTOR_NUM) 内部!"
                else
                    echo "  ✓ 所有 constructor 正常完成"
                fi
            else
                echo "  ⚡ 崩溃发生在 constructor($CTOR_NUM) — 未执行到 done!"
            fi
        fi
        echo ""
    fi
done

if [ "$FOUND" = "0" ]; then
    echo "无 forge_hook.log — constructor(48) 未执行"
    echo "可能原因:"
    echo "  1. SELinux 阻止了 so 加载"
    echo "  2. so 缺少依赖符号 (check ELF)"
    echo "  3. so 架构不匹配"
    echo ""
    echo "SELinux 拒绝记录 (最近10条):"
    grep -E "libtdmqimei|libforgehook" /proc/kmsg 2>/dev/null | tail -5
    logcat -d -t 50 2>/dev/null | grep -iE "libtdmqimei|libforgehook|linker.*error|unsatisfied" | tail -10
fi

echo ""
echo "--- 4. forge_audit.log (最后10行) ---"
tail -10 "$HOOK_AUDIT" 2>/dev/null || echo "文件不存在"

echo ""
echo "--- 5. SELinux 拒绝记录 ---"
dmesg 2>/dev/null | grep -iE "avc.*denied.*$PKG|avc.*denied.*qimei|avc.*denied.*forge" | tail -10
logcat -d -b events 2>/dev/null | grep -iE "avc.*denied" | tail -5

echo ""
echo "--- 6. 最新 tombstone ---"
LATEST=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
if [ -n "$LATEST" ]; then
    TS_TIME=$(ls -l "$LATEST" | awk '{print $6,$7,$8}')
    echo "文件: $LATEST ($(stat -c %s "$LATEST" 2>/dev/null || echo '?') bytes)"
    echo "时间: $TS_TIME"
    echo ""

    # 提取关键信息
    echo "--- 进程信息 ---"
    grep -E "^pid:|^Name:|^Cmdline:|^Abort message:" "$LATEST" 2>/dev/null

    echo ""
    echo "--- 崩溃信号 ---"
    grep -E "^signal |^Signal" "$LATEST" 2>/dev/null | head -3

    echo ""
    echo "--- 寄存器 ---"
    grep -A2 "x0 " "$LATEST" 2>/dev/null | head -5

    echo ""
    echo "--- backtrace (前15帧) ---"
    grep -E "^    #" "$LATEST" 2>/dev/null | head -15

    echo ""
    echo "--- 崩溃地址附近的 maps ---"
    FAULT_ADDR=$(grep " fault addr " "$LATEST" 2>/dev/null | awk '{print $NF}')
    if [ -n "$FAULT_ADDR" ] && [ "$FAULT_ADDR" != "0x0000000000000000" ]; then
        echo "fault addr: $FAULT_ADDR"
        # 匹配到包含此地址的 so 段
    fi
else
    echo "无 tombstone (非 native crash)"
fi

echo ""
echo "--- 7. 游戏进程 ---"
PID=$(pidof $PKG 2>/dev/null)
if [ -n "$PID" ]; then
    echo "运行中 PID=$PID"
    echo "Seccomp 状态:"
    grep Seccomp /proc/$PID/status 2>/dev/null
    echo "maps 中的关键库:"
    grep -E "libforgehook|libtersafe|libtdmqimei" /proc/$PID/maps 2>/dev/null | head -10
else
    echo "游戏未运行"
fi

echo ""
echo "--- 8. 最近 logcat 异常 ---"
logcat -d -t 100 2>/dev/null | grep -iE "FATAL|AndroidRuntime.*FATAL|Process.*died|SIGSYS|seccomp|DEBUG.*signal|FOREGROUND_SERVICE" | tail -15

echo ""
echo "=========================================="
echo " 诊断完成"
echo "=========================================="
