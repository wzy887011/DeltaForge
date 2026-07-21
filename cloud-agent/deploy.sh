#!/system/bin/sh
# ============================================================
# DeltaForge deploy.sh — 云手机端一键编译+部署+启动
# 用法: cd ~/DeltaForge && sh cloud-agent/deploy.sh
# ============================================================

set -e
NATIVE_DIR="$HOME/DeltaForge/cloud-agent/native"
TARGET_DIR="/data/local/tmp"
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; NC='\033[0m'
ok()  { echo "${GREEN}[+]${NC} $*"; }
err() { echo "${RED}[-]${NC} $*"; }
warn(){ echo "${YELLOW}[!]${NC} $*"; }

CMD="${1:-full}"

case "$CMD" in
    clean)
        ok "清理编译产物..."
        rm -f "$NATIVE_DIR/forge" "$NATIVE_DIR/libforgehook.so" \
              "$NATIVE_DIR/touch_injector" "$NATIVE_DIR/injector"
        ok "done"
        ;;
    build)
        ok "=== 编译 DeltaForge v4.1 ==="
        cd "$NATIVE_DIR"
        clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl 2>&1 | grep -v warning || true
        ok "libforgehook.so: $(ls -lh libforgehook.so | awk '{print $5}')"
        clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge -lpthread 2>&1 | grep -v warning || true
        ok "forge: $(ls -lh forge | awk '{print $5}')"
        clang -Os -Wall touch_injector.c -o touch_injector -lm 2>&1 | grep -v warning || true
        ok "touch_injector: $(ls -lh touch_injector | awk '{print $5}')"
        clang -Os -Wall injector.c -o injector -ldl 2>&1 | grep -v warning || true
        ok "injector: $(ls -lh injector | awk '{print $5}')"
        ok "编译完成"
        ;;
    status)
        echo "=== DeltaForge 状态 ==="
        ls -lh "$TARGET_DIR/forge" "$TARGET_DIR/libforgehook.so" \
               "$TARGET_DIR/touch_injector" "$TARGET_DIR/injector" 2>/dev/null \
            || warn "二进制未部署"
        su -c "ss -tlnp | grep 9510" 2>/dev/null && ok "daemon TCP 9510 运行中" || warn "daemon 未运行"
        su -c "pidof com.tencent.tmgp.dfm" 2>/dev/null && ok "游戏运行中" || warn "游戏未运行"
        ;;
    full)
        ok "=== DeltaForge 一键部署 v4.1 ==="

        ok "Step 1/5: 拉取仓库..."
        cd ~/DeltaForge
        git pull origin master 2>&1 | tail -1

        ok "Step 2/5: 编译..."
        cd "$NATIVE_DIR"
        clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl 2>&1 | grep -v warning || true
        clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge -lpthread 2>&1 | grep -v warning || true
        clang -Os -Wall touch_injector.c -o touch_injector -lm 2>&1 | grep -v warning || true
        clang -Os -Wall injector.c -o injector -ldl 2>&1 | grep -v warning || true
        ok "编译完成"

        ok "Step 3/5: 部署二进制..."
        su -c "killall forge 2>/dev/null; sleep 1" || true
        su -c "rm -f $TARGET_DIR/forge $TARGET_DIR/libforgehook.so $TARGET_DIR/touch_injector $TARGET_DIR/injector"
        su -c "cp $NATIVE_DIR/forge          $TARGET_DIR/forge"
        su -c "cp $NATIVE_DIR/libforgehook.so $TARGET_DIR/libforgehook.so"
        su -c "cp $NATIVE_DIR/touch_injector $TARGET_DIR/touch_injector"
        su -c "cp $NATIVE_DIR/injector       $TARGET_DIR/injector"
        su -c "chmod 755 $TARGET_DIR/forge $TARGET_DIR/libforgehook.so $TARGET_DIR/touch_injector $TARGET_DIR/injector"
        ok "部署完成"

        ok "Step 3.5/5: MD5 交叉验证..."
        VERIFY_FAIL=0
        for BIN in forge libforgehook.so touch_injector injector; do
            SRC_MD5=$(md5sum "$NATIVE_DIR/$BIN" 2>/dev/null | awk '{print $1}')
            DST_MD5=$(su -c "md5sum $TARGET_DIR/$BIN 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            if [ -n "$SRC_MD5" ] && [ "$SRC_MD5" = "$DST_MD5" ]; then
                ok "  $BIN OK ($DST_MD5)"
            else
                err "  $BIN MD5 不匹配! src=$SRC_MD5 dst=$DST_MD5"
                VERIFY_FAIL=$((VERIFY_FAIL+1))
            fi
        done
        [ "$VERIFY_FAIL" -gt 0 ] && { err "部署验证失败 $VERIFY_FAIL 个文件"; exit 1; }

        ok "Step 4/5: 验证..."
        su -c "sh $NATIVE_DIR/../magisk/system/bin/forge-check.sh" 2>&1 || true

        ok "Step 5/5: 启动 daemon..."
        su -c "nohup $TARGET_DIR/forge -d > /dev/null 2>&1 &"
        sleep 2
        su -c "ss -tlnp | grep 9510" 2>/dev/null && ok "daemon TCP 9510 OK" || warn "daemon 启动失败"

        echo ""
        ok "=== 部署完成 ==="
        echo "  启动游戏: su -c '$TARGET_DIR/forge -l'"
        echo "  验证:     su -c 'sh $NATIVE_DIR/../magisk/system/bin/forge-check.sh'"
        ;;
    *)
        echo "用法: sh cloud-agent/deploy.sh [build|clean|status|full]"
        echo "  build   — 仅编译"
        echo "  full    — 完整: git pull → 编译 → 部署 → 启动 daemon (默认)"
        echo "  status  — 查看状态"
        echo "  clean   — 清理产物"
        ;;
esac
