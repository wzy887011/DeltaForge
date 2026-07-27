@echo off
:: proxy_pc_setup.bat — Windows PC 端 SOCKS5 代理服务器
:: 云机通过 adb reverse 将流量通过 PC 出口
::
:: 前提：PC 连接的是非数据中心网络（家庭宽带、4G热点等）
:: 执行后 PC 上 1080 端口提供 SOCKS5，云机通过 adb reverse 使用

setlocal
set GOST_URL=https://github.com/ginuerzh/gost/releases/download/v2.12.0/gost-windows-amd64-2.12.0.zip
set GOST_DIR=%~dp0gost_bin
set GOST_EXE=%GOST_DIR%\gost.exe
set SOCKS_PORT=1080

echo [*] DeltaForge PC 代理服务器
echo.

:: 检查 gost 是否已存在
if exist "%GOST_EXE%" goto :start_gost

echo [*] 下载 gost 代理工具...
if not exist "%GOST_DIR%" mkdir "%GOST_DIR%"

:: 用 PowerShell 下载
powershell -Command "& {Invoke-WebRequest -Uri '%GOST_URL%' -OutFile '%GOST_DIR%\gost.zip' -UseBasicParsing}"
if errorlevel 1 (
    echo [-] 下载失败，请手动下载:
    echo     %GOST_URL%
    echo     解压后将 gost.exe 放到: %GOST_DIR%
    pause
    exit /b 1
)

:: 解压
powershell -Command "& {Expand-Archive -Path '%GOST_DIR%\gost.zip' -DestinationPath '%GOST_DIR%' -Force}"
del "%GOST_DIR%\gost.zip" 2>nul

:: 找到解压出来的 gost.exe
for /r "%GOST_DIR%" %%f in (gost.exe) do (
    if not "%%f"=="%GOST_EXE%" copy "%%f" "%GOST_EXE%" >nul 2>&1
)

if not exist "%GOST_EXE%" (
    echo [-] 解压失败，请手动操作
    pause
    exit /b 1
)
echo [+] gost 已准备好

:start_gost
:: 显示当前出口 IP
echo [*] 当前 PC 出口 IP：
powershell -Command "& {(Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing).Content}"
echo.

:: 检查 ADB
where adb >nul 2>&1
if errorlevel 1 (
    echo [!] 未找到 adb，跳过 adb reverse 步骤
    echo     请手动执行: adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
) else (
    echo [*] 设置 adb reverse（云机 127.0.0.1:%SOCKS_PORT% → PC:%SOCKS_PORT%）...
    adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
    if errorlevel 1 (
        echo [!] adb reverse 失败，请确认云机已连接
    ) else (
        echo [+] adb reverse 成功
    )
)

echo.
echo [+] 启动 SOCKS5 服务 (端口 %SOCKS_PORT%)...
echo [*] 保持此窗口打开，关闭将断开代理
echo [*] 在云机上执行:
echo        su -c "sh /data/local/tmp/proxy_phone.sh start"
echo.

"%GOST_EXE%" -L "socks5://:%SOCKS_PORT%"
