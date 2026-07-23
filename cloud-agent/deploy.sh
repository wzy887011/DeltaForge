#!/system/bin/sh
# DeltaForge v5.6 — 编译 + 部署脚本 (兼容 Termux 和 adb shell)
# 用法: sh cloud-agent/deploy.sh
# 如果 Termux 可用: 自动使用 termux 的 clang 编译
# 如果不可用: 直接从预编译目录复制

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE="$SCRIPT_DIR/native"
TMP=/data/local/tmp

# 检测编译工具链
if command -v clang >/dev/null 2>&1; then
    CC="clang"
elif command -v gcc >/dev/null 2>&1; then
    CC="gcc"
elif [ -f "/data/data/com.termux/files/usr/bin/clang" ]; then
    CC="/data/data/com.termux/files/usr/bin/clang"
else
    echo "[!] 无编译器 — 使用预编译二进制文件"
    CC=""
fi

if [ -n "$CC" ]; then
    echo "[DeltaForge] 编译开始... (CC=$CC)"
    cd "$NATIVE"
    $CC -pie -Os -Wall forge.c -o forge && echo "[+] forge"
    $CC -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl && echo "[+] libforgehook.so"
    $CC -pie -Os -Wall forge_monitor.c -o forge_monitor && echo "[+] forge_monitor"
    $CC -pie -Os -Wall injector.c -o injector -ldl && echo "[+] injector"
    $CC -pie -Os -Wall touch_injector.c -o touch_injector && echo "[+] touch_injector"
    echo "[+] 编译完成"
    ls -lh forge libforgehook.so forge_monitor injector touch_injector
else
    echo "[DeltaForge] 跳过编译 — 使用已有二进制"
fi

echo "[DeltaForge] 部署到 $TMP ..."

# 先停止现有 forge 进程
pkill -f "$TMP/forge" 2>/dev/null || true
sleep 1

# 复制所有产物
cp "$NATIVE/forge"           "$TMP/forge"          2>/dev/null || true
cp "$NATIVE/libforgehook.so" "$TMP/libforgehook.so" 2>/dev/null || true
cp "$NATIVE/forge_monitor"   "$TMP/forge_monitor"   2>/dev/null || true
cp "$NATIVE/injector"        "$TMP/injector"        2>/dev/null || true
cp "$NATIVE/touch_injector"  "$TMP/touch_injector"  2>/dev/null || true
cp "$SCRIPT_DIR/collect_logs.sh" "$TMP/collect_logs.sh" 2>/dev/null || true
cp "$SCRIPT_DIR/df-hijack-root.sh" "$TMP/df-hijack-root.sh" 2>/dev/null || true

chmod 755 "$TMP/forge" "$TMP/forge_monitor" "$TMP/injector" \
          "$TMP/touch_injector" "$TMP/collect_logs.sh" "$TMP/df-hijack-root.sh" 2>/dev/null || true
chmod 644 "$TMP/libforgehook.so" 2>/dev/null || true

echo "[+] 部署完成"
ls -lh "$TMP/forge" "$TMP/libforgehook.so" "$TMP/forge_monitor" 2>/dev/null || true
echo "[DeltaForge] 运行: su -c '/data/local/tmp/forge -l'"
