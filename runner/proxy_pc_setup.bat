@echo off
setlocal

set GOST_URL=https://github.com/ginuerzh/gost/releases/download/v2.12.0/gost-windows-amd64-2.12.0.zip
set GOST_DIR=%~dp0gost_bin
set GOST_EXE=%GOST_DIR%\gost.exe
set SOCKS_PORT=1080

echo [*] DeltaForge PC SOCKS5 proxy
echo [*] Requires: PC on home broadband or 4G (not datacenter)
echo.

if exist "%GOST_EXE%" goto :start_gost

echo [*] Downloading gost...
if not exist "%GOST_DIR%" mkdir "%GOST_DIR%"

powershell -Command "Invoke-WebRequest -Uri '%GOST_URL%' -OutFile '%GOST_DIR%\gost.zip' -UseBasicParsing"
if errorlevel 1 (
    echo [-] Download failed. Manually download:
    echo     %GOST_URL%
    echo     Extract gost.exe to: %GOST_DIR%
    pause
    exit /b 1
)

powershell -Command "Expand-Archive -Path '%GOST_DIR%\gost.zip' -DestinationPath '%GOST_DIR%' -Force"
del "%GOST_DIR%\gost.zip" 2>nul

for /r "%GOST_DIR%" %%f in (gost.exe) do (
    if not "%%f"=="%GOST_EXE%" copy "%%f" "%GOST_EXE%" >nul 2>&1
)

if not exist "%GOST_EXE%" (
    echo [-] Extract failed. Please do it manually.
    pause
    exit /b 1
)
echo [+] gost ready

:start_gost
echo [*] Current PC IP:
powershell -Command "(Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing).Content"
echo.

where adb >nul 2>&1
if errorlevel 1 (
    echo [!] adb not found - run manually: adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
) else (
    echo [*] Setting adb reverse ...
    adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
    if errorlevel 1 (
        echo [!] adb reverse failed - check device connection
    ) else (
        echo [+] adb reverse OK
    )
)

echo.
echo [+] Starting SOCKS5 on port %SOCKS_PORT% - keep this window open
echo [*] On cloud phone run: su -c "sh /data/local/tmp/proxy_phone.sh start"
echo.

"%GOST_EXE%" -L "socks5://:%SOCKS_PORT%"
pause
