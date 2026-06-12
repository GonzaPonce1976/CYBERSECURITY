@echo off
chcp 65001 >nul
title 🔐 CyberSecurity DApp — Detener Stack
color 0C

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║       🔐 CyberSecurity DApp — Detener todos los servicios    ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Deteniendo el stack de CyberSec DApp...
echo.

REM ── Detener procesos por puerto ───────────────────────────────────
echo  Buscando y deteniendo proceso en puerto 8080 (Rust Gateway)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :8080 detenido
)

echo  Buscando y deteniendo proceso en puerto 5173 (Vite Frontend)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :5173 detenido
)

echo  Buscando y deteniendo proceso en puerto 8545 (Hardhat Node)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8545 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1 && echo  [OK] Proceso PID %%p en :8545 detenido
)

REM ── Detener procesos por nombre ────────────────────────────────────
echo.
echo  Deteniendo procesos Node.js residuales...
taskkill /F /IM node.exe >nul 2>&1 && echo  [OK] Procesos node.exe detenidos || echo  [INFO] No habia procesos node.exe activos

echo.
echo  ✅ Stack detenido correctamente.
echo.
pause
