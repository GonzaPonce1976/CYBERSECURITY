@echo off
chcp 65001 >nul
title CyberSecurity DApp -- Detener Stack v0.4.0
color 0C
setlocal EnableDelayedExpansion

REM Cargar y parsear ETH_RPC_URL desde .env
set "ETH_RPC_URL=http://127.0.0.1:8545"
if exist ".env" (
    for /f "usebackq tokens=1,2 delims===" %%i in (".env") do (
        if "%%i"=="ETH_RPC_URL" set "ETH_RPC_URL=%%j"
    )
)
set "RPC_TEMP=!ETH_RPC_URL!"
set "RPC_TEMP=!RPC_TEMP: =!"
set "RPC_TEMP=!RPC_TEMP:http://=!"
set "RPC_TEMP=!RPC_TEMP:https://=!"
for /f "tokens=1,2 delims=:" %%a in ("!RPC_TEMP!") do (
    set "RPC_HOST=%%a"
    set "RPC_PORT=%%b"
)
if "!RPC_HOST!"=="" set "RPC_HOST=127.0.0.1"
if "!RPC_PORT!"=="" set "RPC_PORT=8545"

echo.
echo  +==============================================================+
echo  ^|       CyberSecurity DApp -- Detener todos los servicios      ^|
echo  ^|                      Version 0.4.0                           ^|
echo  +==============================================================+
echo.
echo  Deteniendo el stack de CyberSec DApp...
echo.

REM ── [v0.4.0] AUTO-BACKUP antes de detener (nodo aun activo) ──────────────
echo  +--------------------------------------------------------------+
echo  ^|  AUTO-BACKUP: Guardando estado Anvil ANTES de detener        ^|
echo  +--------------------------------------------------------------+
if exist ".anvil_state.json" (
    echo  Realizando backup de .anvil_state.json...
    powershell -ExecutionPolicy Bypass -NonInteractive -File "%~dp0BACKUP_ANVIL.ps1" -Trigger "STOP_CYBERSEC"
    if !errorlevel!==0 (
        echo  [OK] Backup completado antes de detener el stack.
    ) else (
        echo  [WARN] Backup retorno codigo !errorlevel! - verifica BACKUP_ANVIL.ps1
    )
) else (
    echo  [INFO] .anvil_state.json no encontrado - omitiendo backup.
    echo         Ejecuta SETUP_ANVIL_STATE.bat para activar persistencia.
)
echo.

REM ── Detener Gateway por nombre de proceso (v0.3.0: binario directo) ─
echo  Deteniendo cybersec-gateway.exe...
taskkill /F /IM cybersec-gateway.exe >nul 2>&1 && echo  [OK] cybersec-gateway.exe detenido || echo  [INFO] No habia gateway activo

REM ── Detener procesos por puerto ─────────────────────────────────────
echo.
echo  Buscando y deteniendo proceso en puerto 8080 (Rust Gateway)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :8080 detenido
)

echo  Buscando y deteniendo proceso en puerto 5173 (Vite Frontend)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :5173 detenido
)

echo  Buscando y deteniendo proceso en puerto !RPC_PORT! (Hardhat/Anvil Node)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":!RPC_PORT! " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :!RPC_PORT! detenido
)

REM ── Detener procesos Node.js y Anvil residuales ────────────────────
echo.
echo  Deteniendo procesos Node.js y Anvil residuales...
taskkill /F /IM anvil.exe >nul 2>&1 && echo  [OK] Procesos anvil.exe detenidos || echo  [INFO] No habia procesos anvil.exe activos
taskkill /F /IM node.exe >nul 2>&1 && echo  [OK] Procesos node.exe detenidos || echo  [INFO] No habia procesos node.exe activos

echo.
echo  Stack detenido correctamente. v0.3.0
echo.
pause
