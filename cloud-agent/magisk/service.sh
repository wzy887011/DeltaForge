#!/system/bin/sh
# 调用者: Magisk late_start service 触发器
# 本脚本调用: propspoof.sh (第9行), forge -d (第14行)
MODDIR=${0%/*}
while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 5; done
"$MODDIR/system/bin/propspoof.sh" &
if [ -f "$MODDIR/system/bin/forge" ]; then
    chmod 755 "$MODDIR/system/bin/forge"
    "$MODDIR/system/bin/forge" -d &
fi
