#!/system/bin/sh
# df-hijack-root.sh — root 侧 library hijack 安装
PKG="com.tencent.tmgp.dfm"
HOOK_SRC="/data/local/tmp/libforgehook.so"
REAL_NAME="libtdmqimei_real.so"
TARGET_NAME="libtdmqimei.so"
CHAINLOAD_FILE="/data/local/tmp/chainload_path.txt"

GAME_LIB=$(find /data/app -type f -name "$TARGET_NAME" 2>/dev/null | head -1)
if [ -z "$GAME_LIB" ]; then
    echo "[-] hijack FAIL: libtdmqimei.so not found"
    exit 1
fi

DIR=$(dirname "$GAME_LIB")

if [ ! -f "$DIR/$REAL_NAME" ]; then
    echo "[+] hijack: backup $TARGET_NAME => $REAL_NAME"
    cp "$GAME_LIB" "$DIR/$REAL_NAME" || exit 1
    chmod 644 "$DIR/$REAL_NAME"
fi

if [ ! -f "$HOOK_SRC" ]; then
    echo "[-] hijack FAIL: $HOOK_SRC not found"
    exit 1
fi

cp "$HOOK_SRC" "$GAME_LIB" || exit 1
chmod 644 "$GAME_LIB"

# 写入 chainload 路径文件，hook 构造函数只读这一个文件
REAL_PATH="$DIR/$REAL_NAME"
echo "$REAL_PATH" > "$CHAINLOAD_FILE"
chmod 644 "$CHAINLOAD_FILE"
echo "[+] chainload path: $REAL_PATH"

HS=$(ls -l "$GAME_LIB" | awk '{print $5}')
echo "[+] hijack done: hook=${HS}b path=${GAME_LIB}"
