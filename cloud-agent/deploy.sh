#!/system/bin/sh
# ============================================================
# DeltaForge deploy.sh — 云手机端一键编译+部署+启动 v4.3
# 用法: cd ~/DeltaForge && sh cloud-agent/deploy.sh
# ============================================================

set -e

# Termux 对 ANSI 转义码处理有 bug, 自动检测并禁用颜色
if [ -n "$TERMUX_VERSION" ] || [ -d /data/data/com.termux ]; then
    GREEN=''; RED=''; YELLOW=''; NC=''
else
    GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; NC='\033[0m'
fi

NATIVE_DIR="$HOME/DeltaForge/cloud-agent/native"
TARGET_DIR="/data/local/tmp"
ok()  { echo "${GREEN}[+]${NC} $*"; }
err() { echo "${RED}[-]${NC} $*"; }
warn(){ echo "${YELLOW}[!]${NC} $*"; }

# 防止 ANSI 颜色码异常后终端 echo 失效
_cleanup() { stty echo 2>/dev/null; printf '\033[0m'; }
trap _cleanup EXIT

CMD="${1:-full}"

case "$CMD" in
    clean)
        ok "清理编译产物..."
        rm -f "$NATIVE_DIR/forge" "$NATIVE_DIR/libforgehook.so" \
              "$NATIVE_DIR/touch_injector" "$NATIVE_DIR/injector"
        ok "done"
        ;;
    build)
        ok "=== 编译 DeltaForge v4.2 ==="
        cd "$NATIVE_DIR"

        # 1. libforgehook.so (共享库, 必须)
        clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl 2>&1 | grep -v "^.*warning:" || true
        if [ -f libforgehook.so ]; then
            ok "libforgehook.so: $(ls -lh libforgehook.so | awk '{print $5}')"
        else
            err "libforgehook.so 编译失败"; exit 1
        fi

        # 2. forge (主程序, 必须)
        # 注: forge.c 不使用 pthread, 无需 -lpthread
        clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge 2>&1 | grep -v "^.*warning:" || true
        if [ -f forge ]; then
            ok "forge: $(ls -lh forge | awk '{print $5}')"
        else
            err "forge 编译失败"; exit 1
        fi

        # 3. injector (ptrace 注入器, 必须)
        clang -Os -Wall injector.c -o injector -ldl 2>&1 | grep -v "^.*warning:" || true
        if [ -f injector ]; then
            ok "injector: $(ls -lh injector | awk '{print $5}')"
        else
            err "injector 编译失败"; exit 1
        fi

        # 4. touch_injector (触摸注入, 可选 — bot_runner.py 有 input 回退)
        clang -Os -Wall touch_injector.c -o touch_injector -lm 2>&1 | grep -v "^.*warning:" || true
        if [ -f touch_injector ]; then
            ok "touch_injector: $(ls -lh touch_injector | awk '{print $5}')"
        else
            warn "touch_injector 编译失败 (可选, bot_runner 会回退到 input 命令)"
        fi

        ok "编译完成"

        # Step 2.5: 自动安装 library hijack (需要先启动一次游戏让 Android 挂载 lib 目录)
        # 延迟初始化: 先尝试 hijack, 找不到路径就警告但继续
        su -c "find /data/app -type f -name 'libtdmqimei.so' 2>/dev/null | head -1" > /tmp/game_lib_path.txt 2>/dev/null
        GAME_LIB=$(cat /tmp/game_lib_path.txt 2>/dev/null)
        if [ -n "$GAME_LIB" ] && [ -f "$GAME_LIB" ]; then
            GAME_LIB_DIR=$(dirname "$GAME_LIB")
            if [ ! -f "${GAME_LIB_DIR}/libtdmqimei_real.so" ]; then
                ok "hijack: 首次备份 libtdmqimei.so"
                su -c "cp '${GAME_LIB}' '${GAME_LIB_DIR}/libtdmqimei_real.so'"
                su -c "chmod 644 '${GAME_LIB_DIR}/libtdmqimei_real.so'"
            fi
            su -c "cp '${NATIVE_DIR}/libforgehook.so' '${GAME_LIB}'"
            su -c "chmod 644 '${GAME_LIB}'"
            ok "hijack: libforgehook.so → libtdmqimei.so 已替换"
        else
            warn "hijack: 未找到游戏 libtdmqimei.so — 游戏可能未安装或需先启动一次"
            warn "         先执行: su -c 'am start -n com.tencent.tmgp.dfm/com.epicgames.ue4.SplashActivity; sleep 3; am force-stop com.tencent.tmgp.dfm'"
            warn "         再执行: sh cloud-agent/deploy.sh build"
        fi
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
        ok "=== DeltaForge 一键部署 v4.2 ==="

        ok "Step 1/5: 拉取仓库..."
        cd ~/DeltaForge
        git pull origin master 2>&1 | tail -3 || warn "git pull 失败, 使用本地代码继续"

        ok "Step 2/5: 编译..."
        cd "$NATIVE_DIR"

        # 1. libforgehook.so
        clang -shared -fPIC -Os -Wall libforgehook.c -o libforgehook.so -ldl 2>&1 | grep -v "^.*warning:" || true
        ok "libforgehook.so: $(ls -lh libforgehook.so 2>/dev/null | awk '{print $5}' || echo 'FAIL')"

        # 2. forge (不使用 pthread, 无需 -lpthread)
        clang -Os -Wall -fno-stack-protector -fomit-frame-pointer forge.c -o forge 2>&1 | grep -v "^.*warning:" || true
        ok "forge: $(ls -lh forge 2>/dev/null | awk '{print $5}' || echo 'FAIL')"

        # 3. injector
        clang -Os -Wall injector.c -o injector -ldl 2>&1 | grep -v "^.*warning:" || true
        ok "injector: $(ls -lh injector 2>/dev/null | awk '{print $5}' || echo 'FAIL')"

        # 4. touch_injector (可选)
        clang -Os -Wall touch_injector.c -o touch_injector -lm 2>&1 | grep -v "^.*warning:" || true
        ok "touch_injector: $(ls -lh touch_injector 2>/dev/null | awk '{print $5}' || echo 'FAIL (可选)')"

        # 必须文件检查 (不含 touch_injector)
        for BIN in forge libforgehook.so injector; do
            [ -f "$NATIVE_DIR/$BIN" ] || { err "编译失败: $BIN 不存在, 终止部署"; exit 1; }
        done
        ok "编译完成"

        ok "Step 3/5: 部署二进制..."
        su -c "killall forge 2>/dev/null; sleep 1" || true
        su -c "rm -f $TARGET_DIR/forge $TARGET_DIR/libforgehook.so $TARGET_DIR/touch_injector $TARGET_DIR/injector"
        su -c "cp $NATIVE_DIR/forge          $TARGET_DIR/forge"
        su -c "cp $NATIVE_DIR/libforgehook.so $TARGET_DIR/libforgehook.so"
        su -c "cp $NATIVE_DIR/injector       $TARGET_DIR/injector"
        su -c "chmod 755 $TARGET_DIR/forge $TARGET_DIR/libforgehook.so $TARGET_DIR/injector"
        # touch_injector 可选部署
        if [ -f "$NATIVE_DIR/touch_injector" ]; then
            su -c "cp $NATIVE_DIR/touch_injector $TARGET_DIR/touch_injector"
            su -c "chmod 755 $TARGET_DIR/touch_injector"
            ok "touch_injector 已部署"
        else
            warn "touch_injector 不存在, 跳过 (bot_runner 使用 input 回退)"
        fi
        ok "部署完成"

        ok "Step 3.5/5: MD5 交叉验证..."
        VERIFY_FAIL=0
        for BIN in forge libforgehook.so injector; do
            SRC_MD5=$(md5sum "$NATIVE_DIR/$BIN" 2>/dev/null | awk '{print $1}')
            DST_MD5=$(su -c "md5sum $TARGET_DIR/$BIN 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            if [ -n "$SRC_MD5" ] && [ "$SRC_MD5" = "$DST_MD5" ]; then
                ok "  $BIN OK ($DST_MD5)"
            else
                err "  $BIN MD5 不匹配! src=$SRC_MD5 dst=$DST_MD5"
                VERIFY_FAIL=$((VERIFY_FAIL+1))
            fi
        done
        # touch_injector 可选验证
        if [ -f "$NATIVE_DIR/touch_injector" ]; then
            SRC_MD5=$(md5sum "$NATIVE_DIR/touch_injector" 2>/dev/null | awk '{print $1}')
            DST_MD5=$(su -c "md5sum $TARGET_DIR/touch_injector 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            if [ -n "$SRC_MD5" ] && [ "$SRC_MD5" = "$DST_MD5" ]; then
                ok "  touch_injector OK ($DST_MD5)"
            else
                warn "  touch_injector MD5 跳过 (可选)"
            fi
        fi
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
