@echo off
setlocal
set "FOLDER=%~dp0"
set "FOLDER=%FOLDER:~0,-1%"
cd /d "%TEMP%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%FOLDER%\relay-cleaner.ps1" -Folder "%FOLDER%" -PauseOnFailure
if errorlevel 1 pause
