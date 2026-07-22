#!/data/data/com.termux/files/usr/bin/bash
# DeltaForge v5.5 — Termux 一键编译 + 部署脚本
# 用法: sh cloud-agent/deploy.sh [build]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE="$SCRIPT_DIR/native"
TMP=/data/local/tmp

echo "[DeltaForge] 编译开始..."
cd "$NATIVE"

clang -pie -Os -Wall forge.c -o forge && echo "[+] forge"
clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl && echo "[+] libforgehook.so"
clang -pie -Os -Wall forge_monitor.c -o forge_monitor && echo "[+] forge_monitor"
clang -pie -Os -Wall injector.c -o injector -ldl && echo "[+] injector"
clang -pie -Os -Wall touch_injector.c -o touch_injector && echo "[+] touch_injector"
echo "[+] 编译完成"
ls -lh forge libforgehook.so forge_monitor injector touch_injector

echo "[DeltaForge] 生成部署子脚本..."
DEPLOY_TMP="$HOME/df_deploy_tmp.sh"
cat > "$DEPLOY_TMP" << EOF
#!/bin/sh
cp $NATIVE/forge $TMP/forge
cp $NATIVE/libforgehook.so $TMP/libforgehook.so
cp $NATIVE/forge_monitor $TMP/forge_monitor
cp $NATIVE/injector $TMP/injector
cp $NATIVE/touch_injector $TMP/touch_injector
chmod 755 $TMP/forge $TMP/forge_monitor $TMP/injector $TMP/touch_injector
chmod 644 $TMP/libforgehook.so
echo "[+] 部署完成"
ls -lh $TMP/forge $TMP/libforgehook.so $TMP/forge_monitor
EOF

echo "[DeltaForge] 以 root 身份部署到 $TMP ..."
su -c "sh $DEPLOY_TMP"
echo "[DeltaForge] 全部完成，运行: su -c '/data/local/tmp/forge -l'"
