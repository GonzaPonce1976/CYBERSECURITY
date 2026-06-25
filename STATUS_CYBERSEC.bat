@echo off
chcp 65001 >nul
title 📊 CyberSecurity DApp — Estado de Servicios
color 0B
setlocal EnableDelayedExpansion

REM Cargar y parsear ETH_RPC_URL desde .env
set "ETH_RPC_URL=http://127.0.0.1:8545"
if exist ".env" (
    for /f "usebackq tokens=1,2 delims==" %%i in (".env") do (
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
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║      📊 CyberSecurity DApp — Estado de los Servicios         ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Verificando el estado de cada servicio...
echo  Hora: %time%
echo.

echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  Puerto :8080 — Rust API Gateway                             │
echo  └─────────────────────────────────────────────────────────────┘
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  Estado: 🟢 ONLINE — Gateway escuchando en puerto 8080
    curl -s "http://localhost:8080/api/health" > "%TEMP%\health.json" 2>nul
    echo  Respuesta: 
    type "%TEMP%\health.json" 2>nul || echo  [No se pudo obtener respuesta HTTP]
) else (
    echo  Estado: 🔴 OFFLINE — Gateway no encontrado en puerto 8080
)
echo.

echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  Puerto :5173 — Frontend Vite Dashboard                      │
echo  └─────────────────────────────────────────────────────────────┘
netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  Estado: 🟢 ONLINE — Frontend disponible en http://localhost:5173
) else (
    echo  Estado: 🔴 OFFLINE — Frontend no encontrado en puerto 5173
)
echo.

echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  Puerto :!RPC_PORT! — Hardhat/Anvil Blockchain Node                │
echo  └─────────────────────────────────────────────────────────────┘
netstat -ano | findstr ":!RPC_PORT! " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  Estado: 🟢 ONLINE — Hardhat/Anvil escuchando en puerto !RPC_PORT!
) else (
    echo  Estado: 🟡 OFFLINE — Hardhat/Anvil no activo (opcional en desarrollo)
)
echo.

echo  ══════════════════════════════════════════════════════════════
echo   Ejecuta START_CYBERSEC.bat para arrancar todos los servicios
echo   Ejecuta STOP_CYBERSEC.bat  para detener todos los servicios
echo  ══════════════════════════════════════════════════════════════
echo.
pause
