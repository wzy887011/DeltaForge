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

# ---- 找 hijack 目标路径 ----
HIJACK_DIR=""
for d in /data/app/*/com.tencent.tmgp.dfm*/lib/arm64/; do
    [ -d "$d" ] && HIJACK_DIR="$d" && break
done

# ---- 生成 root 部署子脚本 ----
DEPLOY_SH="$HOME/df_deploy.sh"
cat > "$DEPLOY_SH" << EOF
#!/bin/sh
pkill -f '$TMP/forge' 2>/dev/null; sleep 1
cp $NATIVE/forge           $TMP/forge
cp $NATIVE/libforgehook.so $TMP/libforgehook.so
cp $NATIVE/forge_monitor   $TMP/forge_monitor
cp $NATIVE/injector        $TMP/injector
cp $NATIVE/touch_injector  $TMP/touch_injector
cp $SCRIPT_DIR/collect_logs.sh  $TMP/collect_logs.sh
cp $SCRIPT_DIR/df-hijack-root.sh $TMP/df-hijack-root.sh
chmod 755 $TMP/forge $TMP/forge_monitor $TMP/injector $TMP/touch_injector $TMP/collect_logs.sh $TMP/df-hijack-root.sh
chmod 644 $TMP/libforgehook.so
EOF

# 如果有 hijack 目录,也更新 hijack 的 so
if [ -n "$HIJACK_DIR" ] && [ -f "$HIJACK_DIR/libtdmqimei_real.so" ]; then
    cat >> "$DEPLOY_SH" << EOF
cp $NATIVE/libforgehook.so $HIJACK_DIR/libtdmqimei.so
chmod 644 $HIJACK_DIR/libtdmqimei.so
echo "[+] hijack so 已更新: $HIJACK_DIR"
EOF
    echo "[*] 检测到 hijack 已安装,将同步更新"
fi

echo "[+] MD5 验证——"
md5sum forge libforgehook.so

su -c "sh $DEPLOY_SH"
rm -f "$DEPLOY_SH"

echo "[+] 部署完成"
echo "  su -c '/data/local/tmp/forge -l'"
