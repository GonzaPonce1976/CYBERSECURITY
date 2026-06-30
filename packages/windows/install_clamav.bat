@echo off
title Instalador ClamAV Antivirus - CyberSec
echo ===================================================
echo [INFO] Solicitando permisos de administrador...
echo ===================================================

:: Comprobar privilegios de administrador de cmd
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Re-lanzando con privilegios de Administrador (UAC)...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"%~dp0install_clamav.bat\"' -Verb RunAs"
    exit /b
)

:: Ejecutar el script PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_clamav.ps1" -GatewayIp "192.168.125.250"

echo.
echo ===================================================
echo Proceso de instalacion finalizado.
echo ===================================================
pause
