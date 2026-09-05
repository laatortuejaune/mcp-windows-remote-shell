@echo off
setlocal
cd /d "%TEMP%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-relay.ps1" %*
echo.
pause
