#!/system/bin/sh
# DeltaForge 过检测验证 v4.0 — P0/P1/P2 全量检测
# 读取: /proc/[pid]/mem, /proc/[pid]/maps, /proc/cpuinfo, /proc/version, logcat, ss
# 输出: /data/local/tmp/forge_check_result.txt

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
echo " DeltaForge 过检测验证 v4.0"
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

PID=$(pidof "$PKG" 2>/dev/null)

# --- 2. P0: 内核特征 ---
echo ""; echo "--- 2. P0: 内核特征伪装 ---"

cat /proc/version 2>/dev/null | grep -qE "GNU.*gcc|prod-fsfn|build-server|chenrl" \
    && fail "/proc/version 包含云厂商构建特征" \
    || pass "/proc/version 无云厂商构建特征"

cat /proc/cmdline 2>/dev/null | grep -q "androidboot.hardware=qcom" \
    && pass "/proc/cmdline 含 qcom 硬件标识" \
    || warn "/proc/cmdline 缺 qcom 硬件标识"

for dev in /dev/qemu_pipe /dev/goldfish_pipe /dev/socket/qemud; do
    [ -e "$dev" ] && fail "$dev 存在" || pass "$dev 不存在"
done

for f in /system/bin/qemud /system/bin/qemu-props \
         /system/bin/androVM-prop /system/lib/libdroid4x.so \
         /system/bin/microvirt-prop /system/bin/nox-prop; do
    [ -e "$f" ] && fail "文件存在: $f" || pass "已清理: $f"
done

for f in /sys/class/misc/qemu /sys/class/misc/vbox /sys/class/misc/vhost; do
    [ -e "$f" ] && warn "sysfs 节点存在 (hook库应拦截): $f" || pass "sysfs $f 不可访问 (hook 生效)"
done

[ -e /sys/bus/virtio ] && warn "sysfs 节点存在: /sys/bus/virtio (hook库应拦截)" \
    || pass "/sys/bus/virtio 不可访问 (hook 生效)"

{ grep -qE 'qemu-pipe|goldfish|vbox|virtio' /proc/iomem 2>/dev/null; } \
    && fail "/proc/iomem 包含虚拟化特征" || pass "/proc/iomem 干净"

{ grep -qE 'goldfish|virtio|qemu' /proc/ioports 2>/dev/null; } \
    && fail "/proc/ioports 包含虚拟化特征" || pass "/proc/ioports 干净"

{ grep -q goldfish /proc/tty/drivers 2>/dev/null; } \
    && fail "/proc/tty/drivers 含 goldfish" || pass "/proc/tty/drivers 无 goldfish"

{ grep -qE "virtio|goldfish|qemu" /proc/modules 2>/dev/null; } \
    && fail "/proc/modules 含虚拟化模块" || pass "/proc/modules 无虚拟化模块"

# --- 3. 反作弊文件 ---
echo ""; echo "--- 3. 反作弊文件 ---"
DATA="/data/data/$PKG"
for f in "$DATA/files/qm/5093f053c62f9ae1" "$DATA/files/tdm_track.dat" \
         "$DATA/files/GPMSDK.mmap3" "$DATA/shared_prefs/qm_global_sp.xml" \
         "$DATA/shared_prefs/GCloudCoreSP.xml" "$DATA/files/MSDK_GUID" \
         "$DATA/files/.beacon_id" "$DATA/files/bugly_crash" "/sdcard/.imei" \
         "$DATA/files/ano_tmp/tp_report.dat" "$DATA/files/ano_tmp/ano_sc.dat" \
         "$DATA/files/com.tencent.tdm.qimei.sdk.QimeiSDK"; do
    [ -e "$f" ] && fail "存在: $f" || pass "已删除: $f"
done

# --- 4. P1: Seccomp-BPF ---
echo ""; echo "--- 4. P1: Seccomp-BPF 验证 ---"
if [ -n "$PID" ]; then
    cat /proc/$PID/status 2>/dev/null | grep -q "Seccomp:.*2" \
        && pass "seccomp filter mode=2 (已安装)" \
        || warn "seccomp filter 可能未安装 (检查 status)"

    grep -q "libGPM.so" /proc/$PID/maps 2>/dev/null \
        && info "libGPM.so 已加载 — seccomp-bpf 已拦截其内联 svc" \
        || pass "libGPM.so 未加载"

    cat /proc/$PID/root/proc/cpuinfo 2>/dev/null | grep -qE "Kailua|Snapdragon|0x51" \
        && pass "cpuinfo hook 生效 (Snapdragon 8+ Gen1)" \
        || warn "无法验证 cpuinfo hook"

    cat /proc/$PID/root/proc/version 2>/dev/null | grep -qE "clang|5\.15\.74" \
        && pass "version hook 生效 (clang 5.15.74)" \
        || warn "无法验证 /proc/version hook"
else
    warn "游戏未运行, 跳过 seccomp 验证"
fi

# --- 5. 内存补丁 ---
echo ""; echo "--- 5. 内存补丁 ---"
if [ -z "$PID" ]; then
    warn "游戏未运行, 跳过内存补丁验证"
else
    info "游戏 PID=$PID"
    TSBASE=$(grep libtersafe.so /proc/$PID/maps 2>/dev/null | head -1 | cut -d'-' -f1)
    if [ -n "$TSBASE" ]; then
        TSBASE=$((16#$TSBASE))
        info "libtersafe.so base=0x$(printf '%x' $TSBASE)"

        A1=$((TSBASE + 0x5137C0))
        V1=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((A1/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -z "$V1" ]; then
            warn "无法读取 /proc/$PID/mem (cgroup 阻断)"
        else
            [ "$V1" = "ff031f2a" ] && pass "tersafe@0x5137C0 OK" || warn "tersafe@0x5137C0=$V1 (期望=ff031f2a)"
        fi

        A2=$((TSBASE + 0x50E380))
        V2=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((A2/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -n "$V2" ]; then
            [ "$V2" = "c0031fd6" ] && pass "tersafe@0x50E380 (BR X30) OK" || warn "tersafe@0x50E380=$V2"
        fi

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

    UE4BASE=$(grep libUE4.so /proc/$PID/maps 2>/dev/null | head -1 | cut -d'-' -f1)
    if [ -n "$UE4BASE" ]; then
        UE4BASE=$((16#$UE4BASE))
        UA=$((UE4BASE + 0x1347F7F4))
        UV=$(dd if=/proc/$PID/mem bs=4 count=1 skip=$((UA/4)) 2>/dev/null | xxd -p | tr -d '\n')
        if [ -n "$UV" ]; then
            [ "$UV" = "c0035fd6" ] && pass "UE4@0x1347F7F4 OK" || warn "UE4@0x1347F7F4=$UV"
        fi
    fi
fi

# --- 6. P2: Java 属性 ---
echo ""; echo "--- 6. P2: Java 属性一致性 ---"
for pair in "ro.product.manufacturer:Xiaomi" "ro.product.model:23049RAD8C" \
            "ro.product.brand:Xiaomi" "ro.hardware:qcom"; do
    key="${pair%%:*}"
    exp="${pair##*:}"
    val=$(getprop "$key" 2>/dev/null)
    [ "$val" = "$exp" ] && pass "Java $key=$val" || warn "Java $key: shell=$val (hook应返回=$exp)"
done

# --- 7. Hook库 & 注入器 ---
echo ""; echo "--- 7. Hook库 & 注入器 ---"
[ -f /data/local/tmp/libforgehook.so ] && pass "libforgehook.so 存在" || fail "libforgehook.so 缺失"
ls -lh /data/local/tmp/libforgehook.so 2>/dev/null | awk '{print " [*] hook: " $5 " " $6 " " $7 " " $8}' >> "$OUT"
[ -f /data/local/tmp/injector ] && pass "injector 存在" || fail "injector 缺失 — ptrace 注入不可用"
[ -f /data/local/tmp/forge ]    && pass "forge 存在"    || fail "forge 缺失"

# --- 7.5 注入结果验证 ---
echo ""; echo "--- 7.5 注入结果验证 ---"
if [ -n "$PID" ]; then
    # 检查 forge.log 中是否有注入成功记录
    INJECT_LOG=$(grep -iE "inject|dlopen|libforgehook" /data/local/tmp/forge.log 2>/dev/null | tail -3)
    if [ -n "$INJECT_LOG" ]; then
        pass "forge.log 有注入记录"
        echo " [*] $(echo "$INJECT_LOG" | head -1)" >> "$OUT"
    else
        warn "forge.log 无注入记录 — 尚未执行 forge -l 或注入失败"
    fi

    # 以游戏进程视角访问 /sys/class/misc/qemu — hook 生效应返回 ENOENT
    QEMU_CHK=$(su -c "ls /proc/$PID/root/sys/class/misc/qemu 2>&1" 2>/dev/null)
    if echo "$QEMU_CHK" | grep -qiE "no such|not found|cannot access|enoent"; then
        pass "sysfs /sys/class/misc/qemu → ENOENT (hook 拦截生效)"
    elif [ -z "$QEMU_CHK" ]; then
        warn "无法通过 /proc/$PID/root 访问 sysfs (可能权限受限，不影响结论)"
    else
        fail "/sys/class/misc/qemu 对游戏可见 — hook 未生效，请确认 injector 已执行"
        info "  返回: $QEMU_CHK"
    fi

    # smaps 中匿名可执行段数量 — 注入后通常 >2
    ANON_RWX=$(grep -cE "^[0-9a-f].*rwxp[[:space:]]+0 00:00 0" /proc/$PID/smaps 2>/dev/null || echo 0)
    if [ "$ANON_RWX" -gt 2 ] 2>/dev/null; then
        pass "smaps 匿名可执行段: $ANON_RWX (正常注入特征)"
    else
        warn "smaps 匿名可执行段: $ANON_RWX (偏少，注入可能未完成)"
    fi
else
    warn "游戏未运行，跳过注入验证 — 请先运行: su -c '/data/local/tmp/forge -l'"
fi

# --- 8. logcat ---
echo ""; echo "--- 8. logcat 扫描 ---"
LOGS=$(logcat -d -t "00:00:30" 2>/dev/null)
CRITICAL=0
for kw in "emulator_name=" "is_root=" "debugger:" "inline_hook" "DeviceISRooted" \
          "qemu_pipe" "goldfish" "virtio" "virtual_machine"; do
    if echo "$LOGS" | grep -qi "$kw"; then
        n=$(echo "$LOGS" | grep -ci "$kw")
        fail "logcat 发现 '$kw' ($n 次)"
        echo "$LOGS" | grep -i "$kw" | head -3
        CRITICAL=$((CRITICAL+1))
    fi
done
[ "$CRITICAL" -eq 0 ] && pass "logcat 无检测关键词"

# --- 9. 网络 ---
echo ""; echo "--- 9. 网络上报 ---"
TSS=0
if command -v ss >/dev/null 2>&1; then
    TSS=$(ss -tnp 2>/dev/null | grep -cE "14000|19000|8085|8088")
    TSS=${TSS:-0}
fi
[ "$TSS" -eq 0 ] 2>/dev/null && pass "无 TSS 协议端口连接" || warn "$TSS 个 TSS 相关连接"

iptables -L OUTPUT -n 2>/dev/null | grep -qE "tdm|crashsight" \
    && pass "iptables TDM/CrashSight 阻断规则存在" \
    || warn "iptables 规则可能未安装"

# --- 10. 进程伪装 ---
echo ""; echo "--- 10. 进程伪装 ---"
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
    [ "$SUS" -gt 0 ] 2>/dev/null \
        && fail "游戏进程 maps 有 $SUS 处注入痕迹" \
        || pass "游戏进程 maps 干净"

    grep -q "libforgehook" /proc/$PID/maps 2>/dev/null \
        && warn "libforgehook 在 maps 中可见" \
        || pass "libforgehook 已从 maps 隐藏"
else
    warn "游戏未运行, 跳过进程扫描"
fi

# --- 总结 ---
echo ""; echo "======================================"
echo -e "${GREEN}通过: $PASS  ${RED}失败: $FAIL  ${YELLOW}警告: $WARN${NC}"
echo "完整日志: $OUT"

[ "$FAIL" -gt 0 ] && { echo -e "${RED}[!] $FAIL 个问题, 先修复再跑刀${NC}"; exit 1; }
[ "$WARN" -gt 5 ] && echo -e "${YELLOW}[!] $WARN 个警告, 建议排查${NC}" \
    || echo -e "${GREEN}[+] 过检测验证通过, 可以跑刀${NC}"
