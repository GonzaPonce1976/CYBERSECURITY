@echo off
chcp 65001 >nul
title CyberSec DApp - Backup Manual Anvil State
powershell -ExecutionPolicy Bypass -File "%~dp0BACKUP_ANVIL.ps1" -Trigger manual
pause
