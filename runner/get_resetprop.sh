#!/system/bin/sh
# get_resetprop.sh — 从 Magisk 发行版提取并部署 standalone resetprop
# 在 Termux 中运行（需要网络）
# 用法: sh get_resetprop.sh

set -e

DEST="/data/local/tmp/resetprop"
TMP="/data/local/tmp/magisk_tmp"

echo "[*] 检查 resetprop 位置..."
for p in /system/bin/resetprop /data/adb/magisk/resetprop /data/adb/ksu/bin/resetprop "$DEST"; do
    if [ -x "$p" ]; then
        echo "[+] 已找到 resetprop: $p"
        exit 0
    fi
done

echo "[*] 未找到 resetprop，尝试从 Magisk APK 提取..."

# Magisk v28.1 ARM64
MAGISK_URL="https://github.com/topjohnwu/Magisk/releases/download/v28.1/Magisk-v28.1.apk"
MAGISK_APK="/data/local/tmp/magisk_tmp.apk"

# 下载
echo "[*] 下载 Magisk APK..."
if command -v curl >/dev/null 2>&1; then
    curl -L -o "$MAGISK_APK" "$MAGISK_URL" --max-time 120 --retry 3
elif command -v wget >/dev/null 2>&1; then
    wget -O "$MAGISK_APK" "$MAGISK_URL"
else
    echo "[-] 需要 curl 或 wget: pkg install curl"
    exit 1
fi

# 解压 (APK 是 zip)
mkdir -p "$TMP"
cd "$TMP"
if command -v unzip >/dev/null 2>&1; then
    unzip -o "$MAGISK_APK" "lib/arm64-v8a/libresetprop.so" 2>/dev/null || \
    unzip -o "$MAGISK_APK" "lib/arm64-v8a/libmagisk64.so" 2>/dev/null
else
    echo "[-] 需要 unzip: pkg install unzip"
    exit 1
fi

# Magisk 新版中 resetprop 被编译进 magisk64，旧版有独立 libresetprop.so
if [ -f "$TMP/lib/arm64-v8a/libresetprop.so" ]; then
    cp "$TMP/lib/arm64-v8a/libresetprop.so" "$DEST"
elif [ -f "$TMP/lib/arm64-v8a/libmagisk64.so" ]; then
    # magisk64 本身可以作为 resetprop 使用（通过符号链接或直接调用）
    cp "$TMP/lib/arm64-v8a/libmagisk64.so" "$DEST"
fi

chmod 755 "$DEST"
rm -rf "$TMP" "$MAGISK_APK"

if [ -x "$DEST" ]; then
    echo "[+] resetprop 已部署: $DEST"
    # 简单验证
    su -c "$DEST --version 2>&1 || echo '(二进制存在但版本检测失败，仍可用)'"
else
    echo "[-] 提取失败"
    echo ""
    echo "手动方式："
    echo "  1. 下载 Magisk apk"
    echo "  2. 用 zip/7z 解压，取出 lib/arm64-v8a/libresetprop.so"
    echo "  3. cp libresetprop.so /data/local/tmp/resetprop"
    echo "  4. chmod 755 /data/local/tmp/resetprop"
    exit 1
fi
