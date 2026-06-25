@echo off
chcp 65001 >nul
title Reiniciar Rust Gateway ARCAT
color 0A

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "GATEWAY_DIR=%PROJECT_DIR%\rust-gateway"

echo ==========================================================
echo    Reiniciar Rust Gateway - con variables ARCAT SBT
echo ==========================================================
echo.

rem Detener proceso previo en el puerto 8080
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [AVISO] Puerto 8080 ocupado - terminando proceso previo...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    ping 127.0.0.1 -n 3 >nul
    echo [OK] Puerto 8080 liberado.
) else (
    echo [INFO] Puerto 8080 libre.
)

echo Buscando toolchain MSVC de Visual Studio...

set "VSTOOLS="
set "VC_PATHS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat""

for %%P in (%VC_PATHS%) do (
    if exist %%P (
        set "VSTOOLS=%%~P"
        goto :FOUND_VC
    )
)
:FOUND_VC

echo.
if defined VSTOOLS (
    echo [OK] Usando MSVC: %VSTOOLS%
    echo Iniciando Rust Gateway con MSVC toolchain...
    start "Rust Gateway :8080 [ARCAT activo]" cmd /k "title Rust Gateway :8080 [ARCAT activo] && call "%VSTOOLS%" x64 && cd /d "%GATEWAY_DIR%" && cargo run"
) else (
    echo [INFO] MSVC no encontrado, usando toolchain por defecto de Rust...
    start "Rust Gateway :8080 [ARCAT activo]" cmd /k "title Rust Gateway :8080 [ARCAT activo] && cd /d "%GATEWAY_DIR%" && cargo run"
)

echo.
echo Esperando a que el Gateway arranque (hasta 60s)...
ping 127.0.0.1 -n 10 >nul
echo [OK] Proceso completado. Gateway iniciado.

echo.
echo Abriendo Dashboard en el navegador...
start "" "http://localhost:5173"
echo.
pause
