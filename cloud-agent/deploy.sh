#!/system/bin/sh
# Android instrumentation deploy script v6 — compile + deploy with rollback
# Usage: sh cloud-agent/deploy.sh [--dry-run]
set -e

DRY_RUN=0
if [ "$1" = "--dry-run" ]; then DRY_RUN=1; shift; fi

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
    cp "$NATIVE/libforgehook.so" "$DIR/libtdmqimei.so"
    chmod 644 "$DIR/libtdmqimei.so"
    restorecon "$DIR/libtdmqimei.so" 2>/dev/null
    echo "[+] Hijack updated: $DIR/libtdmqimei.so"
    echo "--- MD5 ---"
    md5sum "$DIR/libtdmqimei.so" $TMP/libforgehook.so
else
    echo "[!] Hijack not found — run df-hijack-root.sh first:"
    echo "    su -c 'sh $TMP/df-hijack-root.sh'"
fi

echo "[+] Deploy done"
DEPLOY_EOF

sed -i "s|__NATIVE__|$NATIVE|g" "$DEPLOY_SH"
sed -i "s|__SCRIPT_DIR__|$SCRIPT_DIR|g" "$DEPLOY_SH"

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
echo "    Launch: su -c '/data/local/tmp/forge -l'"
