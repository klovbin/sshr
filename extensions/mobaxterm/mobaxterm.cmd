@echo off
rem Windows runs no .ps1 file directly, this starts mobaxterm.ps1 with the
rem PowerShell every Windows has, the arguments go on as they are
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0mobaxterm.ps1" %*
exit /b %ERRORLEVEL%
