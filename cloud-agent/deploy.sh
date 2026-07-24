#!/system/bin/sh
# DeltaForge v6.1 deploy script — compile + deploy
# Usage: sh cloud-agent/deploy.sh [--dry-run] [--no-hijack]
#   --dry-run   编译但不部署，输出 MD5
#   --no-hijack 跳过 hijack so 更新 (推荐，默认行为将 deprecated)
#   --auto      部署后自动运行 forge -l 注入启动游戏
#   --restore-qimei  恢复原版 libtdmqimei.so (清理旧 hijack 残留)
# NOTE: hijack (so替换) 模式已弃用。推荐使用 forge -l inject 模式。
# BUG: 旧 hijack so 残留会导致 inject 模式闪退——两个版本同时加载冲突
set -e

DRY_RUN=0
NO_HIJACK=0
AUTO_LAUNCH=0
RESTORE_QIMEI=0
for a in "$@"; do
    case "$a" in
        --dry-run) DRY_RUN=1;;
        --no-hijack) NO_HIJACK=1; RESTORE_QIMEI=1;;
        --restore-qimei) RESTORE_QIMEI=1;;
        --auto) AUTO_LAUNCH=1;;
        --no-hijack) NO_HIJACK=1;;
        --auto) AUTO_LAUNCH=1;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE="$SCRIPT_DIR/native"
TMP=/data/local/tmp
BACKUP_DIR="$TMP/forge_backup"
TIMESTAMP=$(date +%s)

# ---- compiler detection ----
if command -v clang >/dev/null 2>&1; then
    CC="clang"
elif [ -f /data/data/com.termux/files/usr/bin/clang ]; then
    CC="/data/data/com.termux/files/usr/bin/clang"
else
    echo "[!] No compiler found"; exit 1
fi

echo "[Build] Compiling v6 (CC=$CC)..."
cd "$NATIVE"
$CC -pie -Os -Wall forge.c -o forge
$CC -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl
$CC -pie -Os -Wall forge_monitor.c -o forge_monitor
$CC -pie -Os -Wall injector.c -o injector -ldl
$CC -pie -Os -Wall touch_injector.c -o touch_injector

# ---- MD5 checksums ----
echo "[+] Build complete — checksums:"
md5sum forge libforgehook.so forge_monitor injector touch_injector | tee "$TMP/forge_build.md5"
FORGE_MD5=$(md5sum forge | awk '{print $1}')
HOOK_MD5=$(md5sum libforgehook.so | awk '{print $1}')

# ---- version stamp ----
echo "v6 $TIMESTAMP $FORGE_MD5 $HOOK_MD5" > "$TMP/forge.version"

# ---- backup existing binaries ----
if [ "$DRY_RUN" = "0" ]; then
    mkdir -p "$BACKUP_DIR"
    for f in forge libforgehook.so forge_monitor injector touch_injector; do
        [ -f "$TMP/$f" ] && cp "$TMP/$f" "$BACKUP_DIR/$f.$TIMESTAMP" 2>/dev/null
    done
    echo "[+] Previous version backed up to $BACKUP_DIR/"
fi

# ---- dry-run exit ----
if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] Build verified. No files deployed."
    echo "  forge:       $FORGE_MD5"
    echo "  libforgehook: $HOOK_MD5"
    exit 0
fi

# ---- generate root deploy sub-script ----
DEPLOY_SH="$HOME/df_deploy.sh"
cat > "$DEPLOY_SH" << 'DEPLOY_EOF'
#!/bin/sh
TMP=/data/local/tmp
NATIVE="__NATIVE__"
SCRIPT_DIR="__SCRIPT_DIR__"

pkill -f "$TMP/forge" 2>/dev/null; sleep 1

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

HIJACK=$(find /data/app -name libtdmqimei_real.so 2>/dev/null | head -1)
if [ -n "$HIJACK" ]; then
    DIR=$(dirname "$HIJACK")
    if [ "__RESTORE_QIMEI__" = "1" ]; then
        cp "$DIR/libtdmqimei_real.so" "$DIR/libtdmqimei.so"
        chmod 644 "$DIR/libtdmqimei.so"
        restorecon "$DIR/libtdmqimei.so" 2>/dev/null
        echo "[!] Qimei RESTORED to original — inject mode safe now"
    fi
    if [ "__NO_HIJACK__" = "1" ]; then
        echo "[!] Hijack SKIPPED (--no-hijack). Use inject mode: su -c '$TMP/forge -l'"
    else
        cp "$NATIVE/libforgehook.so" "$DIR/libtdmqimei.so"
        chmod 644 "$DIR/libtdmqimei.so"
        restorecon "$DIR/libtdmqimei.so" 2>/dev/null
        echo "[!] Hijack updated: $DIR/libtdmqimei.so (DEPRECATED — use forge -l instead)"
        echo "--- MD5 ---"
        md5sum "$DIR/libtdmqimei.so" $TMP/libforgehook.so
    fi
else
    echo "[!] Hijack not found — inject mode only: su -c '$TMP/forge -l'"
fi

echo "[+] Deploy done"
DEPLOY_EOF

sed -i "s|__NATIVE__|$NATIVE|g" "$DEPLOY_SH"
sed -i "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" "$DEPLOY_SH"
sed -i "s|__RESTORE_QIMEI__|$RESTORE_QIMEI|g" "$DEPLOY_SH"
sed -i "s|__NO_HIJACK__|$NO_HIJACK|g" "$DEPLOY_SH"

echo "[+] Deploy MD5:"
md5sum forge libforgehook.so

su -c "sh $DEPLOY_SH"
rm -f "$DEPLOY_SH"

# ---- post-deploy diagnostics ----
echo ""
echo "[+] Running post-deploy diagnostics..."
su -c "sh $TMP/check.sh" 2>/dev/null || echo "[!] Diagnostics failed — run manually: su -c 'sh $TMP/check.sh'"

echo ""
echo "[+] v6 deploy complete. Rollback: cp $BACKUP_DIR/*.$TIMESTAMP $TMP/"
echo "    Launch (inject mode, recommended): su -c '$TMP/forge -l'"
echo "    Launch (hijack mode, deprecated): su -c 'am start -n com.tencent.tmgp.dfm/.SplashActivity'"
if [ "$AUTO_LAUNCH" = "1" ]; then
    echo "[*] Auto-launching forge -l..."
    su -c "$TMP/forge -l" &
fi
