@echo off
chcp 65001 >nul
title CyberSecurity DApp — Iniciador de Stack
color 0A
setlocal EnableDelayedExpansion

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║      🔐  CyberSecurity DApp  —  Iniciador de Stack           ║
echo  ║             Version 0.1.0  ^|  Blockchain Edition             ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Fecha/Hora de inicio: %date% %time%
echo.

REM ══════════════════════════════════════════════════════════════════
REM  CONFIGURACION — Ajusta PROJECT_DIR si cambia la ubicacion
REM ══════════════════════════════════════════════════════════════════
set "PROJECT_DIR=C:\Users\USUARIO\Desktop\curso-primera\CYBERSECURITY_Dapp_VersionNew"
set "GATEWAY_DIR=%PROJECT_DIR%\rust-gateway"
set "DEPLOY_JSON=%PROJECT_DIR%\deployments\localhost.json"
set "SYNC_SCRIPT=%PROJECT_DIR%\sync_contracts.ps1"
set "VSTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"

REM ══════════════════════════════════════════════════════════════════
REM  PASO 1 — Verificar existencia del proyecto
REM ══════════════════════════════════════════════════════════════════
if not exist "%PROJECT_DIR%" (
    echo  [ERROR] Directorio del proyecto no encontrado:
    echo          %PROJECT_DIR%
    echo  Ajusta la variable PROJECT_DIR al inicio de este script.
    pause & exit /b 1
)
cd /d "%PROJECT_DIR%"

echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 1: Verificando dependencias del sistema                │
echo  └─────────────────────────────────────────────────────────────┘
echo.

node --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] Node.js no encontrado - https://nodejs.org/ & pause & exit /b 1 )
for /f "tokens=*" %%v in ('node --version') do echo  [OK] Node.js %%v

npm --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] npm no encontrado. & pause & exit /b 1 )
for /f "tokens=*" %%v in ('npm --version') do echo  [OK] npm v%%v

cargo --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] Rust/Cargo no encontrado - https://rustup.rs/ & pause & exit /b 1 )
for /f "tokens=*" %%v in ('cargo --version') do echo  [OK] %%v

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 2: Iniciando Nodo Blockchain Hardhat (:8545)           │
echo  └─────────────────────────────────────────────────────────────┘
echo.

netstat -ano | findstr ":8545 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Hardhat ya estaba corriendo en :8545 — omitiendo inicio.
    goto :SKIP_HARDHAT
)

echo  Abriendo ventana de Hardhat blockchain...
start "Hardhat Blockchain :8545" cmd /k "title Hardhat Blockchain :8545 && cd /d ""%PROJECT_DIR%"" && npm run dev:contracts"

echo  Esperando 10 segundos para que el nodo este listo...
timeout /t 10 /nobreak >nul

netstat -ano | findstr ":8545 " | findstr "LISTENING" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Hardhat no pudo iniciar. Revisa la ventana de Hardhat.
    pause & exit /b 1
)
echo  [OK] Hardhat blockchain activo en puerto 8545.

:SKIP_HARDHAT

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 3: Compilando contratos Solidity                       │
echo  └─────────────────────────────────────────────────────────────┘
echo.

call npm run compile >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo la compilacion de contratos.
    echo  Ejecuta manualmente: npm run compile
    pause & exit /b 1
)
echo  [OK] Contratos Solidity compilados correctamente.

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 4: Desplegando Smart Contracts en Hardhat local        │
echo  └─────────────────────────────────────────────────────────────┘
echo.
echo  Desplegando SecurityAudit + AlertRegistry...

call npm run deploy:local
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo el deploy. Verifica que Hardhat este en :8545.
    pause & exit /b 1
)

if not exist "%DEPLOY_JSON%" (
    echo  [ERROR] deployments\localhost.json no generado. Deploy fallido.
    pause & exit /b 1
)
echo.
echo  [OK] Smart Contracts desplegados exitosamente.

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 5: Sincronizando addresses en ambos archivos .env      │
echo  └─────────────────────────────────────────────────────────────┘
echo.

powershell -ExecutionPolicy Bypass -File "%SYNC_SCRIPT%"
if %errorlevel% neq 0 (
    echo  [ERROR] sync_contracts.ps1 fallo. Revisa el script.
    pause & exit /b 1
)

REM ── Leer las addresses para mostrar en el resumen final ───────────
for /f "usebackq tokens=2 delims==" %%A in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content '%DEPLOY_JSON%' | ConvertFrom-Json).contracts.SecurityAudit"`) do set "ADDR_SECURITY=%%A"
for /f "usebackq tokens=2 delims==" %%A in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content '%DEPLOY_JSON%' | ConvertFrom-Json).contracts.AlertRegistry"`) do set "ADDR_REGISTRY=%%A"

REM Fallback: leer directo si el for no funciono
if "!ADDR_SECURITY!"=="" (
    for /f "delims=" %%A in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content '%DEPLOY_JSON%'|ConvertFrom-Json).contracts.SecurityAudit"') do set "ADDR_SECURITY=%%A"
)
if "!ADDR_REGISTRY!"=="" (
    for /f "delims=" %%A in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content '%DEPLOY_JSON%'|ConvertFrom-Json).contracts.AlertRegistry"') do set "ADDR_REGISTRY=%%A"
)

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 6: Iniciando Rust API Gateway (:8080)                  │
echo  └─────────────────────────────────────────────────────────────┘
echo.

REM ── Liberar el puerto si habia un gateway previo ──────────────────
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [AVISO] Puerto 8080 ocupado — terminando proceso previo...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
    echo  [OK] Puerto 8080 liberado.
)

if exist "%VSTOOLS%" (
    echo  Iniciando Gateway con Visual Studio MSVC toolchain...
    start "Rust Gateway :8080" cmd /k "title Rust Gateway :8080 && call ""%VSTOOLS%"" x64 && cd /d ""%GATEWAY_DIR%"" && cargo run"
) else (
    echo  Iniciando Gateway sin MSVC (toolchain por defecto)...
    start "Rust Gateway :8080" cmd /k "title Rust Gateway :8080 && cd /d ""%GATEWAY_DIR%"" && cargo run"
)
echo  [OK] Ventana del Rust Gateway iniciada.

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 7: Iniciando Frontend Dashboard Vite (:5173)           │
echo  └─────────────────────────────────────────────────────────────┘
echo.

netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Frontend Vite ya estaba corriendo — omitiendo inicio.
    goto :SKIP_VITE
)

start "Frontend Vite :5173" cmd /k "title Frontend Vite :5173 && cd /d ""%PROJECT_DIR%"" && npm run dev:frontend"
echo  [OK] Ventana del Frontend Vite iniciada.

:SKIP_VITE

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 8: Esperando que el Gateway este operativo             │
echo  └─────────────────────────────────────────────────────────────┘
echo.
echo  Polling al Gateway cada 3 segundos (maximo 20 intentos / 60s)...
echo.

set GW_READY=0
set GW_ATTEMPTS=0

:GW_WAIT_LOOP
    set /a GW_ATTEMPTS+=1
    if !GW_ATTEMPTS! gtr 20 goto :GW_TIMEOUT
    timeout /t 3 /nobreak >nul
    curl -s --max-time 2 -o nul -w "%%{http_code}" http://localhost:8080/api/health > "%TEMP%\gw_check.txt" 2>nul
    set /p GW_CODE=<"%TEMP%\gw_check.txt"
    if "!GW_CODE!"=="200" (
        set GW_READY=1
        goto :GW_READY
    )
    echo  [Intento !GW_ATTEMPTS!/20] Gateway respondio HTTP !GW_CODE! — compilando...
    goto :GW_WAIT_LOOP

:GW_TIMEOUT
echo.
echo  [AVISO] Gateway no respondio en 60s. Puede seguir compilando.
echo  Verifica en: http://localhost:8080/api/health
goto :SUMMARY

:GW_READY
echo  [OK] Rust Gateway operativo en el intento !GW_ATTEMPTS! (HTTP 200).

REM ── Registrar evento SYSTEM_START en la blockchain ───────────────
echo.
echo  Registrando evento de arranque del sistema en la blockchain...

curl -s -X POST http://localhost:8080/api/audit/log ^
     -H "Content-Type: application/json" ^
     -d "{\"event_type\":\"SYSTEM_START\",\"severity\":\"INFO\",\"description\":\"Stack CyberSec DApp iniciado — SecurityAudit activo\"}" ^
     > "%TEMP%\bc_init.txt" 2>nul

findstr /c:"\"ok\"" "%TEMP%\bc_init.txt" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Evento SYSTEM_START registrado on-chain correctamente.
) else (
    echo  [AVISO] No se pudo registrar el evento on-chain ^(blockchain puede estar sincronizando^).
)

:SUMMARY
echo.
echo  ══════════════════════════════════════════════════════════════
echo.
echo    CYBERSECURITY DAPP — STACK COMPLETO INICIADO
echo.
echo    BLOCKCHAIN
if defined ADDR_SECURITY (
    echo      SecurityAudit  : !ADDR_SECURITY!
    echo      AlertRegistry  : !ADDR_REGISTRY!
) else (
    echo      Revisa deployments\localhost.json para las addresses
)
echo      Red            : Chain ID 31337  Hardhat/Anvil local
echo.
echo    SERVICIOS
echo      Hardhat Node   : http://localhost:8545
echo      Rust Gateway   : http://localhost:8080
echo      Health Check   : http://localhost:8080/api/health
echo      Audit Trail    : http://localhost:8080/api/audit/trail
echo      WebSocket      : ws://localhost:8080/ws/alerts
echo      Dashboard      : http://localhost:5173
echo      Red LAN        : http://192.168.125.250:5173
echo.
echo    NOTAS
echo      * Ctrl+F5 en el navegador para recargar sin cache
echo      * STOP_CYBERSEC.bat para detener todos los servicios
echo      * STATUS_CYBERSEC.bat para verificar el estado
echo.
echo  ══════════════════════════════════════════════════════════════
echo.

echo  Abriendo Dashboard en el navegador...
timeout /t 3 /nobreak >nul
start "" "http://localhost:5173"

echo  Este menu se cerrara en 15 segundos.
timeout /t 15 /nobreak
endlocal
