@echo off
REM Double-click to validate the RDP-Guard install (will prompt for admin).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-RDPGuard.ps1"
