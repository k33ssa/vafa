@echo off
rem Двойной щелчок — установка VPN Guard. Сам попросит права администратора.
net session >nul 2>&1 || (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
