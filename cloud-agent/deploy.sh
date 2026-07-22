#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# DeltaForge deploy.sh v5.0 — Termux 适配版
# 核心设计: su -c 每次只执行单一脚本路径, 避免分号/管道截断
# ============================================================
set -e
cd "$HOME/DeltaForge" 2>/dev/null || { echo "[-] cd DeltaForge FAIL"; exit 1; }

# 纯文本, 无 ANSI — Termux 对颜色码处理有 bug
ok()  { echo "[+] $*"; }
err() { echo "[-] $*"; }
warn(){ echo "[!] $*"; }

NATIVE_DIR="$HOME/DeltaForge/cloud-agent/native"
SCRIPTS_DIR="$HOME/DeltaForge/cloud-agent"
TARGET_DIR="/data/local/tmp"
CMD="${1:-build}"

case "$CMD" in
    clean)
        ok "clean..."
        rm -f "$NATIVE_DIR"/forge "$NATIVE_DIR"/libforgehook.so \
              "$NATIVE_DIR"/touch_injector "$NATIVE_DIR"/injector
        ok "done"
        ;;

    build)
        ok "=== DeltaForge build v5.0 ==="
        cd "$NATIVE_DIR"

        ok "compile libforgehook.so..."
        clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl 2>&1 | grep -v "warning" || true
        [ -f libforgehook.so ] || { err "FAIL libforgehook.so"; exit 1; }
        ok "  ok"

        ok "compile forge..."
        clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge 2>&1 | grep -v "warning" || true
        [ -f forge ] || { err "FAIL forge"; exit 1; }
        ok "  ok"

        ok "compile injector..."
        clang -Os -Wall injector.c -o injector -ldl 2>&1 | grep -v "warning" || true
        [ -f injector ] || { err "FAIL injector"; exit 1; }
        ok "  ok"

        ok "compile touch_injector..."
        clang -Os -Wall touch_injector.c -o touch_injector -lm 2>&1 | grep -v "warning" || true
        [ -f touch_injector ] && ok "  ok" || warn "  skipped (optional)"

        ok "build done"

        # deploy via root script (single su -c invocation)
        ok "deploy..."
        DEPLOY_SCRIPT="$SCRIPTS_DIR/df-deploy-root.sh"
        if [ -f "$DEPLOY_SCRIPT" ]; then
            su -c "sh $DEPLOY_SCRIPT" || { err "deploy FAIL"; exit 1; }
        else
            su -c "cp $NATIVE_DIR/forge $TARGET_DIR/forge"
            su -c "cp $NATIVE_DIR/libforgehook.so $TARGET_DIR/libforgehook.so"
            su -c "cp $NATIVE_DIR/injector $TARGET_DIR/injector"
            su -c "chmod 755 $TARGET_DIR/forge $TARGET_DIR/libforgehook.so $TARGET_DIR/injector"
        fi
        ok "deploy done"

        # hijack via root script
        ok "hijack..."
        HIJACK_SCRIPT="$SCRIPTS_DIR/df-hijack-root.sh"
        if [ -f "$HIJACK_SCRIPT" ]; then
            su -c "sh $HIJACK_SCRIPT" || warn "hijack FAIL: start game once then retry build"
        fi

        ok "=== build complete ==="
        echo "  next: su -c /data/local/tmp/forge -l"
        ;;

    full)
        ok "=== DeltaForge full v5.0 ==="
        ok "Step 1: git pull..."
        git pull origin master 2>&1 | tail -3 || warn "git pull FAIL"

        ok "Step 2: build..."
        sh "$0" build

        ok "Step 3: verify..."
        VERIFY_SCRIPT="$SCRIPTS_DIR/../magisk/system/bin/forge-check.sh"
        su -c "sh $VERIFY_SCRIPT" 2>&1 | tail -8 || true

        ok "Step 4: daemon..."
        su -c "nohup $TARGET_DIR/forge -d > /dev/null 2>&1 &"
        sleep 2
        su -c "ss -tlnp" 2>/dev/null | grep -q 9510 && ok "daemon TCP 9510 OK" || warn "daemon check"
        ok "=== full deploy done ==="
        echo "  next: su -c /data/local/tmp/forge -l"
        ;;

    diagnose)
        ok "=== diagnose ==="
        DIAG_SCRIPT="$SCRIPTS_DIR/df-diagnose-root.sh"
        su -c "sh $DIAG_SCRIPT"
        ;;

    status)
        echo "=== status ==="
        echo "--- binaries ---"
        ls -lh "$TARGET_DIR"/forge "$TARGET_DIR"/libforgehook.so "$TARGET_DIR"/injector 2>/dev/null || warn "missing"
        echo "--- daemon ---"
        su -c "ss -tlnp" 2>/dev/null | grep 9510 || warn "daemon offline"
        echo "--- game ---"
        su -c "pidof com.tencent.tmgp.dfm" 2>/dev/null || warn "game offline"
        ;;

    *)
        echo "usage: sh cloud-agent/deploy.sh [build|full|diagnose|status|clean]"
        echo "  build    - compile + deploy + hijack"
        echo "  full     - git pull + build + verify + daemon"
        echo "  diagnose - collect env + bg logcat"
        echo "  status   - quick state check"
        echo "  clean    - remove compiled binaries"
        ;;
esac
