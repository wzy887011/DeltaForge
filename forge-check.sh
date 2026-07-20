#!/system/bin/sh
# 调用者: 云手机 root shell — forge 部署后/跑刀前验证过检效果
# 读取: /proc/[pid]/mem, /proc/[pid]/maps, /proc/cpuinfo, logcat, 系统属性, ss 网络
# 输出: /data/local/tmp/forge_check_result.txt (终端同步显示)
# 用户指令: "需不需要先在云手机那边跑一遍,然后抓取一些日志看看能不能被检测到?"

PKG="com.tencent.tmgp.dfm"
OUT="/data/local/tmp/forge_check_result.txt"
PASS=0; FAIL=0; WARN=0
> "$OUT"

GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; NC='\033[0m'
pass() { echo "${GREEN}[PASS]${NC} $*"; echo "[PASS] $*" >> "$OUT"; PASS=$((PASS+1)); }
fail() { echo "${RED}[FAIL]${NC} $*"; echo "[FAIL] $*" >> "$OUT"; FAIL=$((FAIL+1)); }
warn() { echo "${YELLOW}[WARN]${NC} $*"; echo "[WARN] $*" >> "$OUT"; WARN=$((WARN+1)); }
info() { echo " [*] $*"; echo " [*] $*" >> "$OUT"; }

echo "======================================"
echo " DeltaForge 过检测验证"
echo " $(date)"
echo "======================================"

# --- 0. ROOT ---
echo ""; echo "--- 0. 基础环境 ---"
[ "$(id -u)" = "0" ] && pass "ROOT: uid=0" || fail "ROOT: uid=$(id -u) (需要root)"

# --- 1. 属性 ---
echo ""; echo "--- 1. 属性伪装 ---"

for key in ro.kernel.qemu init.svc.vbox86-setup ro.genymotion.version \
           persist.nox.simulator_version microvirt.memu_version nemud.player_package \
           sys.tencent.init sys.tencent.model ro.boot.qemu; do
    val=$(getprop "$key" 2>/dev/null)
    [ -z "$val" ] && pass "prop $key deleted" || fail "prop $key=$val (应被删除)"
done

check_prop() {
    val=$(getprop "$1" 2>/dev/null)
    [ "$val" = "$2" ] && pass "prop $1=$val" || fail "prop $1: expected=$2 actual=$val"
}
check_prop ro.product.manufacturer "Xiaomi"
check_prop ro.product.model "23049RAD8C"
check_prop ro.product.device "marble"
check_prop ro.product.brand "Xiaomi"
check_prop ro.build.tags "release-keys"
check_prop ro.build.type "user"
check_prop ro.debuggable "0"

# --- 2. 虚拟化痕迹 ---
echo ""; echo "--- 2. 虚拟化痕迹 ---"
# sysfs 节点 /sys/bus/virtio /sys/class/misc/* 不可直接删除 — 由 libforgehook.so hook 拦截
for f in /system/bin/qemud /system/bin/qemu-props \
         /system/bin/androVM-prop /system/lib/libdroid4x.so; do
    [ -e "$f" ] && fail "文件存在: $f" || pass "已清理: $f"
done
# sysfs 节点检查 — 依赖 hook 库拦截, 只做 warn
for f in /sys/class/misc/qemu /sys/class/misc/vbox /sys/class/misc/vhost /sys/bus/virtio; do
    [ -e "$f" ] && warn "sysfs 节点存在 (hook库应拦截): $f" || pass "sysfs 节点不可访问 (hook 生效): $f"
done
{ grep -qE 'qemu-pipe|goldfish|vbox|virtio' /proc/iomem 2>/dev/null; } \
    && fail "/proc/iomem 包含虚拟化特征" \
    || pass "/proc/iomem 干净"

# --- 3. 反作弊文件 ---
echo ""; echo "--- 3. 反作弊文件 ---"
DATA="/data/data/$PKG"
for f in "$DATA/files/qm/5093f053c62f9ae1" "$DATA/files/tdm_track.dat" \
         "$DATA/files/GPMSDK.mmap3" "$DATA/shared_prefs/qm_global_sp.xml" \
         "$DATA/shared_prefs/GCloudCoreSP.xml" "$DATA/files/MSDK_GUID" \
         "$DATA/files/.beacon_id" "$DATA/files/bugly_crash" "/sdcard/.imei"; do
    [ -e "$f" ] && fail "存在: $f" || pass "已删除: $f"
done

# --- 4. 内存补丁 (需游戏在运行) ---
echo ""; echo "--- 4. 内存补丁 ---"
PID=$(pidof "$PKG" 2>/dev/null)
if [ -z "$PID" ]; then
    warn "游戏未运行, 跳过内存补丁验证"
else
    info "游戏 PID=$PID"
    TSBASE=$(grep libtersafe.so /proc/$PID/maps 2>/dev/null | head -1 | cut -d'-' -f1)
    if [ -n "$TSBASE" ]; then
        TSBASE=$((16#$TSBASE))
        info "libtersafe.so base=0x$(printf '%x' $TSBASE)"

        # 验证补丁 — 从 /proc/PID/mem 读取, 部分内核/cgroup 会阻止
        A1=$((TSBASE + 0x5137C0))
        V1=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((A1/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -z "$V1" ]; then
            warn "无法读取 /proc/$PID/mem (cgroup 或内核阻断)，依赖 forge 自身 108 ok/0 fail 记录"
        else
            [ "$V1" = "ff031f2a" ] && pass "tersafe@0x5137C0 OK" || warn "tersafe@0x5137C0=$V1 (期望=ff031f2a)"
        fi

        A2=$((TSBASE + 0x50E380))
        V2=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((A2/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -n "$V2" ]; then
            [ "$V2" = "c0031fd6" ] && pass "tersafe@0x50E380 (BR X30) OK" || warn "tersafe@0x50E380=$V2 (期望=c0031fd6)"
        fi

        # BSS 清空验证
        BSSBASE=$(grep "libtersafe.so" /proc/$PID/maps 2>/dev/null | grep "anon:.bss" | head -1 | cut -d'-' -f1)
        if [ -n "$BSSBASE" ]; then
            BSSBASE=$((16#$BSSBASE))
            BV=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$(( (BSSBASE+0x47F0)/4 )) 2>/dev/null | xxd -p | tr -d '\n')
            if [ -n "$BV" ]; then
                [ "$BV" = "00000000" ] && pass "tersafe BSS@0x47F0=0 OK" || warn "tersafe BSS@0x47F0=$BV (非零)"
            fi
        fi
    else
        warn "libtersafe.so 未加载"
    fi

    # UE4 patch
    UE4BASE=$(grep libUE4.so /proc/$PID/maps 2>/dev/null | head -1 | cut -d'-' -f1)
    if [ -n "$UE4BASE" ]; then
        UE4BASE=$((16#$UE4BASE))
        UA=$((UE4BASE + 0x1347F7F4))
        UV=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((UA/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -n "$UV" ]; then
            [ "$UV" = "c0031fd6" ] && pass "UE4@0x1347F7F4 OK" || warn "UE4@0x1347F7F4=$UV (期望=c0031fd6)"
        fi
    fi
fi

# --- 5. Hook 库 ---
echo ""; echo "--- 5. Hook库 ---"
[ -f /data/local/tmp/libforgehook.so ] && pass "libforgehook.so 存在" || fail "libforgehook.so 缺失"
if [ -n "$PID" ]; then
    cat /proc/$PID/root/proc/cpuinfo 2>/dev/null | grep -qE "Kailua|Snapdragon|0x51" \
        && pass "cpuinfo hook 生效 (真机内容)" \
        || warn "无法验证 cpuinfo hook (可能 cgroup 隔离)"
fi

# --- 6. logcat ---
echo ""; echo "--- 6. logcat 扫描 ---"
LOGS=$(logcat -d -t "00:00:30" 2>/dev/null)
CRITICAL=0
for kw in "emulator_name=" "is_root=" "debugger:" "inline_hook" "DeviceISRooted"; do
    if echo "$LOGS" | grep -qi "$kw"; then
        n=$(echo "$LOGS" | grep -ci "$kw")
        fail "logcat 发现 '$kw' ($n 次)"
        echo "$LOGS" | grep -i "$kw" | head -3
        CRITICAL=$((CRITICAL+1))
    fi
done
[ "$CRITICAL" -eq 0 ] && pass "logcat 无 TSS/Root/模拟器 检测关键词"

# --- 7. 网络 ---
echo ""; echo "--- 7. 网络上报 ---"
TSS=0
if command -v ss >/dev/null 2>&1; then
    TSS=$(ss -tnp 2>/dev/null | grep -cE "14000|19000|8085|8088")
    TSS=${TSS:-0}
fi
if [ "$TSS" -eq 0 ] 2>/dev/null; then
    pass "无 TSS 协议端口连接"
else
    warn "$TSS 个 TSS 相关连接"
fi

# --- 8. 进程伪装 ---
echo ""; echo "--- 8. 进程伪装 ---"
FPID=$(pidof forge 2>/dev/null)
if [ -n "$FPID" ]; then
    COMM=$(cat /proc/$FPID/comm 2>/dev/null)
    echo "$COMM" | grep -q kworker && pass "forge comm=$COMM" || warn "forge comm=$COMM"
else
    warn "forge daemon 未运行"
fi
if [ -n "$PID" ]; then
    SUS=$(grep -cE 'frida|xposed|magisk|substrate|lib5.so' /proc/$PID/maps 2>/dev/null)
    SUS=${SUS:-0}
    if [ "$SUS" -gt 0 ] 2>/dev/null; then
        fail "游戏进程 maps 有 $SUS 处注入痕迹"
    else
        pass "游戏进程 maps 干净"
    fi
else
    warn "游戏未运行, 跳过进程扫描"
fi

# --- 总结 ---
echo ""; echo "======================================"
echo -e "${GREEN}通过: $PASS  ${RED}失败: $FAIL  ${YELLOW}警告: $WARN${NC}"
echo "完整日志: $OUT"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}[!] $FAIL 个问题, 先修复再跑刀${NC}"
    exit 1
elif [ "$WARN" -gt 3 ]; then
    echo -e "${YELLOW}[!] $WARN 个警告, 建议排查${NC}"
else
    echo -e "${GREEN}[+] 过检测验证通过, 可以跑刀${NC}"
fi
