@echo off
setlocal
cd /d "%~dp0"
py -u threat_intel_monitor_v4.py %*
echo.
echo If Python launcher py is not available, run manually: python -u threat_intel_monitor_v4.py
pause