#!/system/bin/sh
# 终端修复 — Termux ANSI/echo 故障时执行
printf '\033[0m'
stty sane 2>/dev/null
stty echo 2>/dev/null
echo OK
