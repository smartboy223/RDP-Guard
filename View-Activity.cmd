@echo off
REM Double-click to view RDP-Guard activity (will prompt for admin).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Show-Activity.ps1" -Hours 24
