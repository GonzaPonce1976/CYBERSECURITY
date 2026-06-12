@echo off
chcp 65001 >nul
title 📊 CyberSecurity DApp — Estado de Servicios
color 0B

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
echo  │  Puerto :8545 — Hardhat Blockchain Node                      │
echo  └─────────────────────────────────────────────────────────────┘
netstat -ano | findstr ":8545 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  Estado: 🟢 ONLINE — Hardhat/Anvil escuchando en puerto 8545
) else (
    echo  Estado: 🟡 OFFLINE — Hardhat no activo (opcional en desarrollo)
)
echo.

echo  ══════════════════════════════════════════════════════════════
echo   Ejecuta START_CYBERSEC.bat para arrancar todos los servicios
echo   Ejecuta STOP_CYBERSEC.bat  para detener todos los servicios
echo  ══════════════════════════════════════════════════════════════
echo.
pause
