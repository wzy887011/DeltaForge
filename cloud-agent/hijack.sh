#!/system/bin/sh
# ============================================================
# DeltaForge hijack.sh — 库劫持方案, hook 在 SDK 之前加载
# 原理: libforgehook.so → 伪装成 libtdmqimei.so
#       游戏加载 Qimei 时加载 hook, 构造函数比所有 SDK 更早
#       链式加载真 Qimei 保证原功能
# ============================================================
set -e
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; NC='\033[0m'
trap 'stty echo 2>/dev/null; printf "\033[0m"' EXIT
ok()  { echo "${GREEN}[+]${NC} $*"; }
err() { echo "${RED}[-]${NC} $*"; }
warn(){ echo "${YELLOW}[!]${NC} $*"; }

PKG="com.tencent.tmgp.dfm"
GAME_LIB=""
TARGET_SO="libtdmqimei.so"
HOOK_SO="libforgehook.so"
REAL_SO="libtdmqimei_real.so"

CMD="${1:-install}"

find_game_lib() {
    for path in /data/app/*/com.tencent.tmgp.dfm*/lib/arm64 /data/app/*/com.tencent.tmgp.dfm*/lib/arm64-v8a; do
        if [ -d "$path" ]; then
            GAME_LIB="$path"
            return 0
        fi
    done
    return 1
}

case "$CMD" in
    install)
        ok "=== DeltaForge 库劫持安装 ==="

        if ! find_game_lib; then
            err "找不到游戏 lib 目录, 游戏是否已安装?"
            exit 1
        fi
        ok "游戏 lib: $GAME_LIB"

        if [ ! -f "${GAME_LIB}/${REAL_SO}" ]; then
            ok "备份原生 ${TARGET_SO} → ${REAL_SO}"
            cp "${GAME_LIB}/${TARGET_SO}" "${GAME_LIB}/${REAL_SO}"
            chmod 644 "${GAME_LIB}/${REAL_SO}"
        else
            ok "备份已存在, 跳过"
        fi

        HOOK_PATH="/data/local/tmp/${HOOK_SO}"
        if [ ! -f "$HOOK_PATH" ]; then
            err "找不到 $HOOK_PATH, 先编译: sh cloud-agent/deploy.sh build"
            exit 1
        fi

        ok "替换 ${TARGET_SO} → hook"
        cp "$HOOK_PATH" "${GAME_LIB}/${TARGET_SO}"
        chmod 644 "${GAME_LIB}/${TARGET_SO}"

        su -c "killall forge 2>/dev/null; am force-stop ${PKG} 2>/dev/null; sleep 2" || true

        HOOK_SIZE=$(ls -l "${GAME_LIB}/${TARGET_SO}" | awk '{print $5}')
        REAL_SIZE=$(ls -l "${GAME_LIB}/${REAL_SO}" | awk '{print $5}')
        ok "安装完成: hook=${HOOK_SIZE} real=${REAL_SIZE}"

        echo ""
        ok "=== 下一步 ==="
        echo "  1. 启动游戏+注入: su -c '/data/local/tmp/forge -l'"
        echo "  2. 验证maps: su -c \"cat /proc/\$(pidof ${PKG})/maps | grep forge\""
        echo "     应出现 libforgehook 在 maps 中"
        echo "  3. 验证属性: su -c 'sh ~/DeltaForge/cloud-agent/magisk/system/bin/forge-check.sh'"
        ;;

    restore)
        ok "=== 恢复原生 Qimei ==="
        if ! find_game_lib; then
            err "找不到游戏 lib 目录"
            exit 1
        fi
        if [ -f "${GAME_LIB}/${REAL_SO}" ]; then
            cp "${GAME_LIB}/${REAL_SO}" "${GAME_LIB}/${TARGET_SO}"
            chmod 644 "${GAME_LIB}/${TARGET_SO}"
            ok "已恢复原生 ${TARGET_SO}"
        else
            warn "没有备份, 无法恢复 — 需重装游戏"
        fi
        ;;

    status)
        echo "=== 劫持状态 ==="
        if find_game_lib; then
            echo "游戏 lib: $GAME_LIB"
            ls -lh "${GAME_LIB}/${TARGET_SO}" 2>/dev/null || echo "  ${TARGET_SO}: 不存在"
            ls -lh "${GAME_LIB}/${REAL_SO}" 2>/dev/null || echo "  ${REAL_SO}: 未备份"
        else
            echo "游戏未安装"
        fi
        ;;

    *)
        echo "用法: sh cloud-agent/hijack.sh [install|restore|status]"
        echo "  install — 替换 libtdmqimei.so 为 hook"
        echo "  restore — 恢复原生 Qimei"
        echo "  status  — 查看状态"
        ;;
esac
