@echo off
chcp 65001 >nul
title CyberSec DApp - Restaurar Backup Anvil State
powershell -ExecutionPolicy Bypass -File "%~dp0RESTORE_ANVIL_BACKUP.ps1"
