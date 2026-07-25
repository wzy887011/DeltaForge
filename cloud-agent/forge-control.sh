#!/system/bin/sh
# 调用者: 用户在云手机 root shell 手动执行
# 依赖: /data/local/tmp/forge (核心引擎)
#        /data/local/tmp/libforgehook.so (硬件文件拦截库,可选)
#        /data/local/tmp/propsadapt.sh (属性适配,可选)
set -e
FORGE=/data/local/tmp/forge
HOOK=/data/local/tmp/libforgehook.so
PROPS=/data/local/tmp/propsadapt.sh
echo "[*] DeltaForge 一键部署"
[ "$(id -u)" != "0" ] && { echo "[-] need root"; exit 1; }

# 1. 属性适配
if [ -f "$PROPS" ]; then
    echo "[*] adapting properties..."
    sh "$PROPS"
else
    echo "[!] propsadapt.sh not found — skipping property adapt"
fi

# 2. 权限
chmod 755 "$FORGE" 2>/dev/null || true
chmod 644 "$HOOK" 2>/dev/null || true

# 3. 重启 daemon
pkill forge 2>/dev/null || true
sleep 1

# 4. 确保 hook 库在 LD_LIBRARY_PATH 中
if [ -f "$HOOK" ]; then
    export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH
    echo "[+] libforgehook.so ready — will intercept /proc/cpuinfo etc."
else
    echo "[!] libforgehook.so not found — hardware file hook unavailable"
fi

nohup "$FORGE" -d > /data/local/tmp/forge.log 2>&1 &
sleep 2
echo "[+] forge daemon PID=$(pidof forge 2>/dev/null || echo 'unknown')"
echo "[+] done"
