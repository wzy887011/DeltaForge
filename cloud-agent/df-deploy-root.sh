#!/system/bin/sh
# df-deploy-root.sh — root 侧部署操作
# deploy.sh 通过 su -c 调用此脚本, 避免 Termux su -c 分号/管道截断
TARGET_DIR="/data/local/tmp"
NATIVE_DIR="/data/data/com.termux/files/home/DeltaForge/cloud-agent/native"
VERIFY_FAIL=0

killall forge 2>/dev/null; sleep 1
rm -f "$TARGET_DIR"/forge "$TARGET_DIR"/libforgehook.so "$TARGET_DIR"/touch_injector "$TARGET_DIR"/injector

echo "[+] deploy binaries..."
for BIN in forge libforgehook.so injector; do
    cp "$NATIVE_DIR/$BIN" "$TARGET_DIR/$BIN" || { echo "[-] cp $BIN failed"; exit 1; }
    chmod 755 "$TARGET_DIR/$BIN"
    echo "[+]   $BIN ok"
done

if [ -f "$NATIVE_DIR/touch_injector" ]; then
    cp "$NATIVE_DIR/touch_injector" "$TARGET_DIR/touch_injector"
    chmod 755 "$TARGET_DIR/touch_injector"
fi

echo "[+] MD5 verify..."
for BIN in forge libforgehook.so injector; do
    SM=$(md5sum "$NATIVE_DIR/$BIN" | awk '{print $1}')
    DM=$(md5sum "$TARGET_DIR/$BIN" | awk '{print $1}')
    if [ "$SM" = "$DM" ]; then
        echo "[+]   $BIN match"
    else
        echo "[-]   $BIN src=$SM dst=$DM"
        VERIFY_FAIL=1
    fi
done
if [ "$VERIFY_FAIL" -ne 0 ]; then
    echo "[-] MD5 FAIL"
    exit 1
fi
echo "[+] deploy done"
