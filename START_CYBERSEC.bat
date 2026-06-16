@echo off
chcp 65001 >nul
title CyberSecurity DApp — Iniciador de Stack
color 0A
setlocal EnableDelayedExpansion

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║      🔐  CyberSecurity DApp  —  Iniciador de Stack           ║
echo  ║             Version 0.2.0  ^|  Blockchain Edition             ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Fecha/Hora de inicio: %date% %time%
echo.

REM ══════════════════════════════════════════════════════════════════
REM  CONFIGURACION — Rutas dinamicas de la DApp
REM ══════════════════════════════════════════════════════════════════
REM Obtener el directorio de este script (directorio del proyecto)
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "PROJECT_DIR=%SCRIPT_DIR%"
set "GATEWAY_DIR=%PROJECT_DIR%\rust-gateway"
set "DEPLOY_JSON=%PROJECT_DIR%\deployments\localhost.json"
set "SYNC_SCRIPT=%PROJECT_DIR%\sync_contracts.ps1"

REM Buscar ruta de Visual Studio MSVC Build Tools de forma automatica
set "VSTOOLS="
set "VC_PATHS="C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat""

for %%P in (%VC_PATHS%) do (
    if exist %%P (
        set "VSTOOLS=%%~P"
        goto :FOUND_VC
    )
)
:FOUND_VC

cd /d "%PROJECT_DIR%"

echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 1: Verificando dependencias del sistema                │
echo  └─────────────────────────────────────────────────────────────┘
echo.

node --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] Node.js no encontrado - https://nodejs.org/ & pause & exit /b 1 )
for /f "tokens=*" %%v in ('node --version') do echo  [OK] Node.js %%v

call npm --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] npm no encontrado. & pause & exit /b 1 )
for /f "tokens=*" %%v in ('npm --version') do echo  [OK] npm v%%v

cargo --version >nul 2>&1
if %errorlevel% neq 0 ( echo  [ERROR] Rust/Cargo no encontrado - https://rustup.rs/ & pause & exit /b 1 )
for /f "tokens=*" %%v in ('cargo --version') do echo  [OK] %%v

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 2: Verificando y levantando contenedores Docker (Wazuh) │
echo  └─────────────────────────────────────────────────────────────┘
echo.

docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [AVISO] Docker no encontrado. Omitiendo verificacion de contenedores.
    goto :SKIP_DOCKER
)

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Docker esta instalado pero el daemon no se encuentra corriendo.
    echo          Inicia Docker Desktop e intenta de nuevo.
    pause & exit /b 1
)

echo  Comprobando estado de los contenedores de Wazuh...
docker ps --filter "name=cybersec-wazuh-manager" --format "{{.Status}}" > "%TEMP%\docker_check.txt" 2>nul
set /p DOCKER_STATUS=<"%TEMP%\docker_check.txt"

if "%DOCKER_STATUS%"=="" (
    echo  [AVISO] Los contenedores de Wazuh estan inactivos. Iniciando con docker-compose...
    call npm run docker:up
    if %errorlevel% neq 0 (
        echo  [ERROR] Fallo al iniciar los contenedores de Docker.
        pause & exit /b 1
    )
    echo  Esperando 10 segundos para inicializacion de servicios...
    ping 127.0.0.1 -n 11 >nul
) else (
    echo  [OK] Los contenedores de Wazuh ya se encuentran activos.
)

:SKIP_DOCKER

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 3: Iniciando Nodo Blockchain Hardhat (:8545)           │
echo  └─────────────────────────────────────────────────────────────┘
echo.

netstat -ano | findstr ":8545 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Hardhat ya estaba corriendo en :8545 — omitiendo inicio.
    goto :SKIP_HARDHAT
)

echo  Abriendo ventana de Hardhat blockchain...
start "Hardhat Blockchain :8545" cmd /k "title Hardhat Blockchain :8545 && cd /d "%PROJECT_DIR%" && npm run dev:contracts"

echo  Esperando 10 segundos para que el nodo este listo...
ping 127.0.0.1 -n 11 >nul

netstat -ano | findstr ":8545 " | findstr "LISTENING" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Hardhat no pudo iniciar. Revisa la ventana de Hardhat.
    pause & exit /b 1
)
echo  [OK] Hardhat blockchain activo en puerto 8545.

:SKIP_HARDHAT

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 4: Compilando contratos Solidity                       │
echo  └─────────────────────────────────────────────────────────────┘
echo.

call npm run compile
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo la compilacion de contratos.
    echo  Ejecuta manualmente: npm run compile
    pause & exit /b 1
)
echo  [OK] Contratos Solidity compilados correctamente.

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 5: Desplegando Smart Contracts en Hardhat local        │
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
echo  │  PASO 6: Sincronizando addresses en archivos .env            │
echo  └─────────────────────────────────────────────────────────────┘
echo.

powershell -ExecutionPolicy Bypass -File "%SYNC_SCRIPT%"
if %errorlevel% neq 0 (
    echo  [ERROR] sync_contracts.ps1 fallo. Revisa el script.
    pause & exit /b 1
)

REM Leer las addresses sincronizadas directamente del archivo .env
set "ADDR_SECURITY="
set "ADDR_REGISTRY="
for /f "usebackq tokens=1,2 delims==" %%i in ("%PROJECT_DIR%\.env") do (
    if "%%i"=="CONTRACT_SECURITY_AUDIT" set "ADDR_SECURITY=%%j"
    if "%%i"=="CONTRACT_ALERT_REGISTRY" set "ADDR_REGISTRY=%%j"
)

echo.
echo  [OK] Direcciones sincronizadas:
echo       SecurityAudit: !ADDR_SECURITY!
echo       AlertRegistry: !ADDR_REGISTRY!

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 7: Iniciando Rust API Gateway (:8080)                  │
echo  └─────────────────────────────────────────────────────────────┘
echo.

REM Liberar el puerto si habia un gateway previo
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [AVISO] Puerto 8080 ocupado — terminando proceso previo...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    ping 127.0.0.1 -n 3 >nul
    echo  [OK] Puerto 8080 liberado.
)

if defined VSTOOLS (
    echo  Iniciando Gateway con Visual Studio MSVC toolchain...
    echo  Usando: !VSTOOLS!
    start "Rust Gateway :8080" cmd /k "title Rust Gateway :8080 && call "!VSTOOLS!" x64 && cd /d "%GATEWAY_DIR%" && cargo run"
) else (
    echo  [AVISO] MSVC toolchain no encontrado de forma automatica.
    echo  Iniciando Gateway con la toolchain por defecto de Rust...
    start "Rust Gateway :8080" cmd /k "title Rust Gateway :8080 && cd /d "%GATEWAY_DIR%" && cargo run"
)
echo  [OK] Ventana del Rust Gateway iniciada.

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 8: Iniciando Frontend Dashboard Vite (:5173)           │
echo  └─────────────────────────────────────────────────────────────┘
echo.

netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Frontend Vite ya estaba corriendo — omitiendo inicio.
    goto :SKIP_VITE
)

start "Frontend Vite :5173" cmd /k "title Frontend Vite :5173 && cd /d "%PROJECT_DIR%" && npm run dev:frontend"
echo  [OK] Ventana del Frontend Vite iniciada.

:SKIP_VITE

echo.
echo  ┌─────────────────────────────────────────────────────────────┐
echo  │  PASO 9: Esperando que el Gateway este operativo             │
echo  └─────────────────────────────────────────────────────────────┘
echo.
echo  Polling al Gateway cada 3 segundos (maximo 20 intentos / 60s)...
echo.

set GW_READY=0
set GW_ATTEMPTS=0

:GW_WAIT_LOOP
    set /a GW_ATTEMPTS+=1
    if !GW_ATTEMPTS! gtr 20 goto :GW_TIMEOUT
    ping 127.0.0.1 -n 4 >nul
    curl.exe -s --max-time 2 -o nul -w "%%{http_code}" http://localhost:8080/api/health > "%TEMP%\gw_check.txt" 2>nul
    set "GW_CODE="
    set /p GW_CODE=<"%TEMP%\gw_check.txt"
    if "!GW_CODE!"=="200" (
        set GW_READY=1
        goto :GW_READY
    )
    echo  [Intento !GW_ATTEMPTS!/20] Gateway respondio HTTP !GW_CODE! — compilando...
    goto :GW_WAIT_LOOP

:GW_TIMEOUT
echo.
echo  [AVISO] Gateway no respondio en 60s. Puede seguir compilando en segundo plano.
echo  Verifica en: http://localhost:8080/api/health
goto :SUMMARY

:GW_READY
echo  [OK] Rust Gateway operativo en el intento !GW_ATTEMPTS! (HTTP 200).

REM ── Registrar evento SYSTEM_START en la blockchain ───────────────
echo.
echo  Registrando evento de arranque del sistema en la blockchain...

echo {> "%TEMP%\bc_init_body.json"
echo   "event_type": "SYSTEM_START",>> "%TEMP%\bc_init_body.json"
echo   "severity": "INFO",>> "%TEMP%\bc_init_body.json"
echo   "description": "Stack CyberSec DApp iniciado — SecurityAudit activo">> "%TEMP%\bc_init_body.json"
echo }>> "%TEMP%\bc_init_body.json"

curl.exe -s -X POST http://localhost:8080/api/audit/log ^
     -H "Content-Type: application/json" ^
     -d @"%TEMP%\bc_init_body.json" ^
     > "%TEMP%\bc_init.txt" 2>nul

del "%TEMP%\bc_init_body.json" >nul 2>&1

findstr /c:"\"ok\"" "%TEMP%\bc_init.txt" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Evento SYSTEM_START registrado on-chain correctamente.
) else (
    echo  [AVISO] No se pudo registrar el evento on-chain ^(la blockchain puede estar sincronizando^).
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
    echo      Revisa deployments\localhost.json para las direcciones de contratos
)
echo      Red            : Chain ID 31337  Hardhat local
echo.
echo    SERVICIOS
echo      Hardhat Node   : http://localhost:8545
echo      Rust Gateway   : http://localhost:8080
echo      Health Check   : http://localhost:8080/api/health
echo      Dashboard      : http://localhost:5173
echo.
echo    NOTAS
echo      * Haz Ctrl+F5 en el navegador para recargar sin cache.
echo      * Ejecuta STOP_CYBERSEC.bat para detener todos los servicios.
echo      * Ejecuta STATUS_CYBERSEC.bat para verificar el estado de puertos.
echo.
echo  ══════════════════════════════════════════════════════════════
echo.

echo  Abriendo Dashboard en el navegador...
ping 127.0.0.1 -n 4 >nul
start "" "http://localhost:5173"

echo  Esta ventana se cerrara automaticamente en 10 segundos.
ping 127.0.0.1 -n 11 >nul
endlocal
