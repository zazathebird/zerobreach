@echo off
setlocal EnableDelayedExpansion

:: ── Self-elevate if not already admin ──────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -WindowStyle Hidden -Command ^
        "Start-Process cmd.exe -ArgumentList ('/c \"%~f0\" %*') -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: ── Parse optional argument: "python" launches the Flask/Python server ─────────
set "MODE=ps"
if /i "%~1"=="python" set "MODE=python"
if /i "%~1"=="py"     set "MODE=python"

if "%MODE%"=="python" goto :launch_python

:: ── Default: Pure PowerShell server (no Python required) ──────────────────────
:launch_ps
echo.
echo  [ZeroBreach] Launching ZeroBreach-Server.ps1 ...
echo  [ZeroBreach] Tip: run "Launch-GUI.bat python" to use the Python/Flask server instead.
echo.

set "LOGFILE=%~dp0zerobreach_launch_error.log"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ZeroBreach-Server.ps1" 2>"%LOGFILE%"
set "PS_EXIT=%errorlevel%"

:: Non-zero exit = something went wrong — keep window open
if %PS_EXIT% neq 0 (
    echo.
    echo  ╔══════════════════════════════════════════════════════════╗
    echo  ║  ZeroBreach-Server.ps1 exited with code %PS_EXIT%              ║
    echo  ║  Errors written to: zerobreach_launch_error.log         ║
    echo  ╚══════════════════════════════════════════════════════════╝
    echo.
    type "%LOGFILE%"
    echo.
    pause
)
goto :eof

:: ── Python/Flask server ────────────────────────────────────────────────────────
:launch_python
echo.
echo  [ZeroBreach] Launching Python/Flask server (_python\server.py)...
echo.

:: Check Python is available
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found in PATH.
    echo  Install Python 3.10+ or run without the "python" argument to use the PS server.
    pause
    exit /b 1
)

:: Install/verify dependencies
echo  [ZeroBreach] Checking Python dependencies...
python -m pip install -q -r "%~dp0_python\requirements.txt"
if %errorlevel% neq 0 (
    echo  [ERROR] pip install failed. Check _python\requirements.txt and your Python environment.
    pause
    exit /b 1
)

echo  [ZeroBreach] Starting Flask server...
python "%~dp0_python\server.py"
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Python server exited unexpectedly ^(code %errorlevel%^).
    pause
)
goto :eof
