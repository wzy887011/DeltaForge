#!/system/bin/sh
# DeltaForge v5.6 — Termux 编译 + root 部署
# 用法: sh cloud-agent/deploy.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE="$SCRIPT_DIR/native"
TMP=/data/local/tmp

# ---- 编译 ----
if command -v clang >/dev/null 2>&1; then
    CC="clang"
elif [ -f /data/data/com.termux/files/usr/bin/clang ]; then
    CC="/data/data/com.termux/files/usr/bin/clang"
else
    echo "[!] 无编译器"; exit 1
fi

echo "[DeltaForge] 编译 (CC=$CC)..."
cd "$NATIVE"
$CC -pie -Os -Wall forge.c -o forge
$CC -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
$CC -pie -Os -Wall forge_monitor.c -o forge_monitor
$CC -pie -Os -Wall injector.c -o injector -ldl
$CC -pie -Os -Wall touch_injector.c -o touch_injector
echo "[+] 编译完成"
ls -lh forge libforgehook.so forge_monitor injector touch_injector

# ---- 生成 root 部署子脚本(包含 hijack 更新) ----
DEPLOY_SH="$HOME/df_deploy.sh"
cat > "$DEPLOY_SH" << 'DEPLOY_EOF'
#!/bin/sh
TMP=/data/local/tmp
NATIVE="__NATIVE__"
SCRIPT_DIR="__SCRIPT_DIR__"

pkill -f "$TMP/forge" 2>/dev/null; sleep 1

# 部署到 /data/local/tmp/
cp "$NATIVE/forge"           $TMP/forge
cp "$NATIVE/libforgehook.so" $TMP/libforgehook.so
cp "$NATIVE/forge_monitor"   $TMP/forge_monitor
cp "$NATIVE/injector"        $TMP/injector
cp "$NATIVE/touch_injector"  $TMP/touch_injector
cp "$SCRIPT_DIR/collect_logs.sh"  $TMP/collect_logs.sh
cp "$SCRIPT_DIR/df-hijack-root.sh" $TMP/df-hijack-root.sh
cp "$SCRIPT_DIR/check.sh"          $TMP/check.sh
chmod 755 $TMP/forge $TMP/forge_monitor $TMP/injector $TMP/touch_injector $TMP/collect_logs.sh $TMP/df-hijack-root.sh $TMP/check.sh
chmod 644 $TMP/libforgehook.so

# 更新 hijack so (root 权限可以读 /data/app/)
HIJACK=$(find /data/app -name libtdmqimei_real.so 2>/dev/null | head -1)
if [ -n "$HIJACK" ]; then
    DIR=$(dirname "$HIJACK")
    cp "$NATIVE/libforgehook.so" "$DIR/libtdmqimei.so"
    chmod 644 "$DIR/libtdmqimei.so"
    echo "[+] hijack updated: $DIR/libtdmqimei.so"
    echo "--- MD5 ---"
    md5sum "$DIR/libtdmqimei.so" $TMP/libforgehook.so
else
    echo "[!] hijack not found — run df-hijack-root.sh first:"
    echo "    su -c 'sh $TMP/df-hijack-root.sh'"
fi

echo "[+] deploy done"
DEPLOY_EOF

# 替换占位符
sed -i "s|__NATIVE__|$NATIVE|g" "$DEPLOY_SH"
sed -i "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" "$DEPLOY_SH"

echo "[+] MD5 验证——"
md5sum forge libforgehook.so

su -c "sh $DEPLOY_SH"
rm -f "$DEPLOY_SH"

echo "[+] 部署完成"
echo "  su -c '/data/local/tmp/forge -l'"
