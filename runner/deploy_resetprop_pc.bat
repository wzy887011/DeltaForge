@echo off
:: deploy_resetprop_pc.bat — 在 Windows PC 上下载 Magisk 并推送 resetprop 到云机
:: 比在云机上下载快很多；需要 adb 可用且云机已连接

setlocal
set MAGISK_VER=v28.1
set MAGISK_URL=https://github.com/topjohnwu/Magisk/releases/download/%MAGISK_VER%/Magisk-%MAGISK_VER%.apk
set TMP_APK=%TEMP%\magisk_tmp.apk
set TMP_SO=%TEMP%\libmagisk64.so
set DEST_NAME=resetprop

echo [*] DeltaForge — 推送 resetprop 到云机
echo.

:: 检查 adb
where adb >nul 2>&1
if errorlevel 1 (
    echo [-] 未找到 adb，请安装 Android Platform Tools 并加入 PATH
    echo     下载: https://developer.android.com/studio/releases/platform-tools
    pause & exit /b 1
)

:: 检查云机连接
echo [*] 检查云机连接...
adb get-state >nul 2>&1
if errorlevel 1 (
    echo [-] 未找到云机，请先通过 adb connect 连接
    pause & exit /b 1
)
echo [+] 云机已连接

:: 下载 Magisk APK
echo [*] 下载 Magisk %MAGISK_VER% ...
powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -Uri '%MAGISK_URL%' -OutFile '%TMP_APK%' -UseBasicParsing }"
if errorlevel 1 (
    echo [-] 下载失败，检查网络连接
    pause & exit /b 1
)
echo [+] 下载完成

:: 从 APK (ZIP) 提取 libmagisk64.so
echo [*] 提取 ARM64 二进制...
powershell -Command "& { Add-Type -Assembly System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('%TMP_APK%'); $e=$z.Entries|Where-Object{$_.FullName -eq 'lib/arm64-v8a/libmagisk64.so'}; if($e){[System.IO.Compression.ZipFileExtensions]::ExtractToFile($e,'%TMP_SO%',$true); Write-Host '[+] 提取成功' } else { Write-Host '[-] 未找到 libmagisk64.so'; exit 1 }; $z.Dispose() }"
if errorlevel 1 (
    echo [-] 提取失败
    del "%TMP_APK%" >nul 2>&1
    pause & exit /b 1
)

:: 推送到云机
echo [*] 推送到云机 /data/local/tmp/%DEST_NAME% ...
adb push "%TMP_SO%" "/data/local/tmp/%DEST_NAME%"
if errorlevel 1 (
    echo [-] push 失败
    goto :cleanup
)

:: 设置权限并验证
adb shell su -c "chmod 755 /data/local/tmp/%DEST_NAME%"
echo.
echo [*] 验证...
adb shell su -c "/data/local/tmp/%DEST_NAME% --version 2>&1 || echo '(无 --version，但二进制已就位)'"

echo.
echo [+] resetprop 已部署！
echo.
echo 下一步在云机 Termux 执行:
echo   su -c "getprop ro.serialno"
echo   su -c "/data/local/tmp/resetprop ro.serialno R88TEST123AB"
echo   su -c "getprop ro.serialno"
echo.

:cleanup
del "%TMP_APK%" >nul 2>&1
del "%TMP_SO%" >nul 2>&1
pause
