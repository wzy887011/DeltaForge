@echo off
setlocal
set SOCKS_PORT=1080
set SCRIPT=%~dp0socks5_proxy.py

echo [*] DeltaForge PC SOCKS5 proxy
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [-] Python not found. Install Python 3 from https://python.org
    pause
    exit /b 1
)

where adb >nul 2>&1
if errorlevel 1 (
    echo [!] adb not in PATH - skipping adb reverse
    echo [!] Run manually: adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
) else (
    echo [*] Setting adb reverse tcp:%SOCKS_PORT% ...
    adb reverse tcp:%SOCKS_PORT% tcp:%SOCKS_PORT%
    if errorlevel 1 (
        echo [!] adb reverse failed - check device connection
    ) else (
        echo [+] adb reverse OK
    )
)

echo.
echo [+] Starting SOCKS5 proxy on port %SOCKS_PORT% ...
echo [*] Keep this window open
echo.
python "%SCRIPT%"
pause
