@echo off
chcp 65001 >nul
title CyberSecurity DApp - Iniciador de Stack v0.4.0
color 0A
setlocal EnableDelayedExpansion

REM =================================================================
REM  START_CYBERSEC.bat  -  Iniciador del Stack CyberSecurity DApp
REM
REM  CHANGELOG:
REM    v0.1.0  Arranque basico con cargo run
REM    v0.2.0  Soporte ARCAT Multicontratos SBT + Blockchain Edition
REM    v0.3.0  2026-06-24 - Optimizaciones de performance y robustez:
REM              [+] Binary-first: usa .exe precompilado (~2s vs ~2min)
REM              [+] Verificacion de integridad de gateway_data.db
REM              [+] Auto-build con build.bat si no existe binario
REM              [+] Flag --clean-db: limpia DB ante esquema desactualizado
REM              [+] Flag --rebuild:  fuerza recompilacion del gateway
REM              [+] Polling optimizado (2s intervalo, 30 intentos max)
REM              [+] Ruta /api/ip/exposures Shodan perimetral corregida
REM              [+] Datos simulados Shodan cuando la BD esta vacia
REM              [+] Panel Servicios: Shodan muestra modo correcto
REM              [+] load_persistent_data tolerante a esquema antiguo
REM    v0.4.0  2026-07-31 - Persistencia real de SBT con Anvil state-file:
REM              [+] Deploy CONDICIONAL: skip si contratos ya activos
REM              [+] check_contracts_alive.js verifica bytecode on-chain
REM              [+] SBT sobreviven al reinicio del SO sin re-acunar
REM              [+] RESTORE_STAFF_DATA restaura Gateway (off-chain)
REM              [+] SETUP_ANVIL_STATE.bat para configuracion inicial
REM
REM  USO:
REM    START_CYBERSEC.bat             -> Arranque normal
REM    START_CYBERSEC.bat --clean-db  -> Limpia DB gateway antes de arrancar
REM    START_CYBERSEC.bat --rebuild   -> Recompila gateway antes de arrancar
REM    START_CYBERSEC.bat --force-deploy -> Fuerza redeploy aunque haya estado
REM =================================================================

echo.
echo  +================================================================+
echo  ^|    CyberSecurity DApp  -  Iniciador de Stack v0.3.0            ^|
echo  ^|    Blockchain + Shodan Perimetral Edition                       ^|
echo  +================================================================+
echo.
echo  Fecha/Hora de inicio: %date% %time%
echo.

REM ----------------------------------------------------------------
REM  Parsear argumentos de linea de comandos
REM ----------------------------------------------------------------
set "CLEAN_DB=0"
set "FORCE_REBUILD=0"
set "FORCE_HARDHAT=0"
set "FORCE_ANVIL=0"
set "FORCE_DEPLOY=0"

for %%A in (%*) do (
    if /i "%%A"=="--clean-db"     set "CLEAN_DB=1"
    if /i "%%A"=="--rebuild"       set "FORCE_REBUILD=1"
    if /i "%%A"=="--hardhat"       set "FORCE_HARDHAT=1"
    if /i "%%A"=="--anvil"         set "FORCE_ANVIL=1"
    if /i "%%A"=="--force-deploy"  set "FORCE_DEPLOY=1"
)

if "!CLEAN_DB!"=="1"      echo  [FLAG] --clean-db     activado: gateway_data.db sera reiniciada
if "!FORCE_REBUILD!"=="1" echo  [FLAG] --rebuild       activado: gateway sera recompilado
if "!FORCE_HARDHAT!"=="1" echo  [FLAG] --hardhat       activado: forzando uso de Hardhat Node
if "!FORCE_ANVIL!"=="1"   echo  [FLAG] --anvil         activado: forzando uso de Anvil Node
if "!FORCE_DEPLOY!"=="1"  echo  [FLAG] --force-deploy  activado: redeploy forzado aunque haya estado Anvil
echo.

REM ----------------------------------------------------------------
REM  CONFIGURACION - Rutas dinamicas del proyecto
REM ----------------------------------------------------------------
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "PROJECT_DIR=%SCRIPT_DIR%"
set "GATEWAY_DIR=%PROJECT_DIR%\rust-gateway"
set "GATEWAY_BIN=%GATEWAY_DIR%\target\release\cybersec-gateway.exe"
set "GATEWAY_DB=%GATEWAY_DIR%\gateway_data.db"
set "BUILD_BAT=%GATEWAY_DIR%\build.bat"
set "DEPLOY_JSON=%PROJECT_DIR%\deployments\localhost.json"
set "SYNC_SCRIPT=%PROJECT_DIR%\sync_contracts.ps1"
set "ANVIL_STATE_FILE=%PROJECT_DIR%\.anvil_state.json"

cd /d "%PROJECT_DIR%"

REM =================================================================
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 1: Verificando dependencias del sistema                   ^|
echo  +-----------------------------------------------------------------+
echo.

node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Node.js no encontrado. Descarga: https://nodejs.org/
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('node --version') do echo  [OK] Node.js %%v

call npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] npm no encontrado.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('npm --version') do echo  [OK] npm v%%v

cargo --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Rust/Cargo no encontrado. Descarga: https://rustup.rs/
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('cargo --version') do echo  [OK] %%v

REM v0.3.0: Verificar binario precompilado del gateway
if exist "%GATEWAY_BIN%" (
    echo  [OK] Gateway binario encontrado en target\release\ - arranque rapido activado
    set "BIN_AVAILABLE=1"
) else (
    echo  [AVISO] Gateway binario NO encontrado - se compilara automaticamente
    set "BIN_AVAILABLE=0"
    set "FORCE_REBUILD=1"
)
echo.

REM =================================================================
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 2: Verificando contenedores Docker / Wazuh SIEM          ^|
echo  +-----------------------------------------------------------------+
echo.

docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [AVISO] Docker no encontrado. Wazuh SIEM no estara disponible.
    goto :SKIP_DOCKER
)

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo  [AVISO] Docker instalado pero el daemon no esta corriendo.
    echo         Inicia Docker Desktop para activar Wazuh SIEM.
    goto :SKIP_DOCKER
)

echo  Comprobando contenedores de Wazuh...
docker ps --filter "name=cybersec-wazuh-manager" --format "{{.Status}}" > "%TEMP%\docker_check.txt" 2>nul
set /p DOCKER_STATUS=<"%TEMP%\docker_check.txt"

if "%DOCKER_STATUS%"=="" (
    echo  [AVISO] Contenedores de Wazuh inactivos. Iniciando con docker-compose...
    call npm run docker:up
    if !errorlevel! neq 0 (
        echo  [ERROR] Fallo al iniciar los contenedores de Docker.
        pause & exit /b 1
    )
    echo  Esperando 10s para inicializacion de servicios Wazuh...
    ping 127.0.0.1 -n 11 >nul
) else (
    echo  [OK] Contenedores de Wazuh activos: !DOCKER_STATUS!
)

:SKIP_DOCKER

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 3: Integridad de la base de datos del Gateway   [v0.3.0]  ^|
echo  +-----------------------------------------------------------------+
echo.
REM v0.3.0: Fix para el crash "missing field timestamp" en gateway_data.db
REM   El codigo Rust ya es tolerante (skip rows con esquema antiguo),
REM   pero --clean-db permite limpiar la BD si se prefiere empezar limpio.

if "!CLEAN_DB!"=="1" (
    if exist "%GATEWAY_DB%" (
        echo  Realizando backup antes de limpiar la base de datos...
        copy "%GATEWAY_DB%" "%GATEWAY_DB%.bak" >nul 2>&1
        del  "%GATEWAY_DB%" >nul 2>&1
        echo  [OK] gateway_data.db reiniciada (backup: gateway_data.db.bak)
    ) else (
        echo  [INFO] gateway_data.db no existe - nada que limpiar
    )
) else (
    if exist "%GATEWAY_DB%" (
        for %%F in ("%GATEWAY_DB%") do set "DB_SIZE=%%~zF"
        echo  [OK] gateway_data.db encontrada (!DB_SIZE! bytes)
        echo       El Gateway la cargara tolerando filas con esquema antiguo.
        echo       Tip: usa --clean-db si ocurren errores al iniciar.
    ) else (
        echo  [OK] Sin gateway_data.db - se creara nueva al arrancar
    )
)
echo.

REM =================================================================
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 4: Iniciando Nodo Blockchain (Anvil / Hardhat)           ^|
echo  +-----------------------------------------------------------------+
echo.

REM Cargar y parsear ETH_RPC_URL y VITE_CHAIN_ID desde .env
set "ETH_RPC_URL=http://127.0.0.1:8545"
set "CHAIN_ID=1"
if exist "%PROJECT_DIR%\.env" (
    for /f "usebackq tokens=1,2 delims==" %%i in ("%PROJECT_DIR%\.env") do (
        if "%%i"=="ETH_RPC_URL" set "ETH_RPC_URL=%%j"
        if "%%i"=="VITE_CHAIN_ID" set "CHAIN_ID=%%j"
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

netstat -ano | findstr ":!RPC_PORT! " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Blockchain ya estaba corriendo en :!RPC_PORT! - omitiendo inicio.
    goto :SKIP_BLOCKCHAIN
)

set "USE_ANVIL=0"
if "!FORCE_HARDHAT!"=="1" (
    echo  Forzando el uso de Hardhat Node por argumento...
) else (
    anvil --version >nul 2>&1
    if !errorlevel!==0 (
        set "USE_ANVIL=1"
    ) else (
        if "!FORCE_ANVIL!"=="1" (
            echo  [ERROR] Se solicito --anvil pero anvil.exe no esta en el PATH.
            pause & exit /b 1
        )
        echo  [INFO] Anvil no detectado en el PATH. Se usara Hardhat Node.
    )
)

if "!USE_ANVIL!"=="1" (
    echo  Abriendo ventana de Anvil blockchain...
    start "Anvil Blockchain :!RPC_PORT!" cmd /k "title Anvil Blockchain :!RPC_PORT! && anvil --host !RPC_HOST! --port !RPC_PORT! --chain-id !CHAIN_ID! --state "%ANVIL_STATE_FILE%""
) else (
    echo  Abriendo ventana de Hardhat blockchain...
    start "Hardhat Blockchain :!RPC_PORT!" cmd /k "title Hardhat Blockchain :!RPC_PORT! && cd /d "%PROJECT_DIR%" && npx hardhat node --hostname !RPC_HOST! --port !RPC_PORT! --config hardhat.config.cjs"
)

echo  Esperando 10 segundos para que el nodo este listo...
ping 127.0.0.1 -n 11 >nul

netstat -ano | findstr ":!RPC_PORT! " | findstr "LISTENING" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] El nodo blockchain no pudo iniciar.
    pause & exit /b 1
)

if "!USE_ANVIL!"=="1" (
    echo  [OK] Anvil blockchain activo en puerto !RPC_PORT! - Chain ID !CHAIN_ID!.
) else (
    echo  [OK] Hardhat blockchain activo en puerto !RPC_PORT! - Chain ID !CHAIN_ID!.
)

:SKIP_BLOCKCHAIN

REM =================================================================
REM  v0.4.0: Verificacion inteligente — deploy CONDICIONAL
REM  Si .anvil_state.json existe Y los contratos estan activos on-chain,
REM  se saltan los PASOS 5, 6 y 7 (no se re-despliega nada).
REM  Esto preserva los SBT ya acunados entre reinicios del SO.
REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 4.5 [v0.4.0]: Verificando persistencia de contratos      ^|
echo  +-----------------------------------------------------------------+
echo.

set "CONTRACTS_ALIVE=0"
if "!FORCE_DEPLOY!"=="1" (
    echo  [FLAG] --force-deploy activo - omitiendo verificacion, redeploy forzado.
    goto :DO_DEPLOY
)

if exist "%ANVIL_STATE_FILE%" (
    echo  [v0.4.0] .anvil_state.json detectado - verificando contratos on-chain...
    node scripts/check_contracts_alive.js
    if !errorlevel!==0 (
        set "CONTRACTS_ALIVE=1"
        echo  [v0.4.0] Contratos ACTIVOS - saltando PASOS 5, 6 y 7.
        goto :SKIP_DEPLOY
    ) else (
        echo  [v0.4.0] Contratos INACTIVOS o estado corrompido - ejecutando deploy completo.
    )
) else (
    echo  [v0.4.0] Sin .anvil_state.json - primera vez o estado perdido.
    echo         Ejecuta SETUP_ANVIL_STATE.bat para configuracion inicial con persistencia.
)

:DO_DEPLOY
REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 5: Compilando contratos Solidity                          ^|
echo  +-----------------------------------------------------------------+
echo.

call npm run compile
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo la compilacion de contratos Solidity.
    echo         Ejecuta manualmente: npm run compile
    pause & exit /b 1
)
echo  [OK] Contratos Solidity compilados correctamente.

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 6: Desplegando Smart Contracts en Hardhat local           ^|
echo  +-----------------------------------------------------------------+
echo.
echo  Desplegando SecurityAudit + AlertRegistry...

call npm run deploy:local
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo el deploy de SecurityAudit.
    echo         Verifica que Hardhat este corriendo en :8545.
    pause & exit /b 1
)

echo  Desplegando ARCAT Multicontratos SBT...
call npm run deploy:arcat:local
if %errorlevel% neq 0 (
    echo  [ERROR] Fallo el deploy de ARCAT.
    echo         Verifica que Hardhat este corriendo en :8545.
    pause & exit /b 1
)

if not exist "%DEPLOY_JSON%" (
    echo  [ERROR] deployments\localhost.json no generado. Deploy fallido.
    pause & exit /b 1
)
echo.
echo  [OK] Todos los Smart Contracts desplegados exitosamente.
goto :AFTER_DEPLOY

:SKIP_DEPLOY
REM ── Rama de restauracion: contratos ya activos on-chain ─────────────
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 5-6-7 SALTADOS [v0.4.0]: Estado Anvil restaurado OK      ^|
echo  +-----------------------------------------------------------------+
echo.
echo  [v0.4.0] Los SBT ya acunados siguen activos en blockchain.
echo  [v0.4.0] Restaurando solo datos off-chain del Gateway...
echo.
powershell -ExecutionPolicy Bypass -Command "& '%PROJECT_DIR%\RESTORE_STAFF_DATA.ps1' -SoloAntivirus -NoAutoArcat"
echo.
echo  [v0.4.0] Restauracion off-chain completada. Continuando arranque...
goto :SETUP_GW_ENV

:AFTER_DEPLOY

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 7: Sincronizando addresses en archivos .env               ^|
echo  +-----------------------------------------------------------------+
echo.

powershell -ExecutionPolicy Bypass -File "%SYNC_SCRIPT%"
if %errorlevel% neq 0 (
    echo  [ERROR] sync_contracts.ps1 fallo. Revisa el script.
    pause & exit /b 1
)

:SETUP_GW_ENV
REM Leer las addresses desde .env (tanto en deploy nuevo como en restauracion)
set "ADDR_SECURITY="
set "ADDR_REGISTRY="
set "ADDR_ARCAT_ROOT="
set "ADDR_ARCAT_REGISTRY="
for /f "usebackq tokens=1,2 delims==" %%i in ("%PROJECT_DIR%\.env") do (
    if "%%i"=="CONTRACT_SECURITY_AUDIT" set "ADDR_SECURITY=%%j"
    if "%%i"=="CONTRACT_ALERT_REGISTRY" set "ADDR_REGISTRY=%%j"
    if "%%i"=="CONTRACT_ARCAT_ROOT"     set "ADDR_ARCAT_ROOT=%%j"
    if "%%i"=="CONTRACT_ARCAT_REGISTRY" set "ADDR_ARCAT_REGISTRY=%%j"
)

echo.
echo  [OK] Direcciones cargadas:
echo       SecurityAudit  : !ADDR_SECURITY!
echo       AlertRegistry  : !ADDR_REGISTRY!
echo       ArcatRoot      : !ADDR_ARCAT_ROOT!
echo       ArcatRegistry  : !ADDR_ARCAT_REGISTRY!

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 7.5: Verificacion Sistematica del Nodo Blockchain         ^|
echo  +-----------------------------------------------------------------+
echo.
node scripts/verify-anvil.js
if !errorlevel! neq 0 (
    echo  [AVISO] La verificacion sistematica de blockchain fallo o advirtio un problema.
)

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 8: Compilando Gateway Rust (si es necesario)   [v0.3.0]  ^|
echo  +-----------------------------------------------------------------+
echo.
REM v0.3.0: Compilar SOLO si --rebuild o si no existe el binario release.
REM   Usa build.bat que configura INCLUDE/LIB directamente para MSVC
REM   (no necesita vcvarsall.bat que puede no estar en el PATH).

if "!FORCE_REBUILD!"=="1" (
    echo  Compilando cybersec-gateway en modo release...
    echo  Esto puede tardar 1-2 minutos la primera vez...
    echo.

    if exist "%BUILD_BAT%" (
        echo  Usando build.bat - configuracion MSVC probada...
        call "%BUILD_BAT%"
        if !errorlevel! neq 0 (
            echo  [ERROR] Fallo la compilacion del Gateway via build.bat.
            echo         Intenta manualmente: cd rust-gateway ^&^& cargo build --release
            pause & exit /b 1
        )
    ) else (
        echo  [AVISO] build.bat no encontrado. Intentando cargo build directo...
        cd /d "%GATEWAY_DIR%"
        cargo build --release
        if !errorlevel! neq 0 (
            echo  [ERROR] Fallo la compilacion. Instala MSVC Build Tools.
            pause & exit /b 1
        )
        cd /d "%PROJECT_DIR%"
    )
    echo.
    echo  [OK] Gateway compilado correctamente.
) else (
    echo  [OK] Binario existente - omitiendo compilacion.
    echo       Para forzar recompilacion: START_CYBERSEC.bat --rebuild
)
echo.

REM =================================================================
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 9: Iniciando Rust API Gateway (:8080)          [v0.3.0]  ^|
echo  +-----------------------------------------------------------------+
echo.
REM v0.3.0: Binary-first - usa cybersec-gateway.exe precompilado.
REM   Ventajas vs cargo run:
REM     - Arranque en ~2 segundos (vs ~2 minutos compilando)
REM     - El binario incorpora todos los fixes de esta sesion:
REM         * Ruta /api/ip/exposures sin conflicto con /{ip}/reputation
REM         * load_persistent_data tolerante a esquema desactualizado
REM         * Datos simulados Shodan cuando la BD esta vacia
REM         * Shodan mode badge correcto en panel Servicios

REM Liberar el puerto si habia un gateway previo corriendo
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [AVISO] Puerto 8080 ocupado - terminando proceso previo...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    REM Tambien detener por nombre de proceso (v0.3.0)
    taskkill /F /IM cybersec-gateway.exe >nul 2>&1
    ping 127.0.0.1 -n 3 >nul
    echo  [OK] Puerto 8080 liberado.
)

if not exist "%GATEWAY_BIN%" (
    echo  [ERROR] Binario no encontrado: %GATEWAY_BIN%
    echo         Ejecuta: START_CYBERSEC.bat --rebuild
    pause & exit /b 1
)

echo  Iniciando Gateway con binario precompilado (v0.3.0 binary-first)...
start "Rust Gateway :8080" cmd /k "title Rust Gateway :8080 [binary v0.3.0] && cd /d "%GATEWAY_DIR%" && "%GATEWAY_BIN%""
echo  [OK] Gateway iniciado en modo binario (~2s de arranque esperado).

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 10: Iniciando Frontend Dashboard Vite (:5173)             ^|
echo  +-----------------------------------------------------------------+
echo.

netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Frontend Vite ya estaba corriendo - omitiendo inicio.
    goto :SKIP_VITE
)

start "Frontend Vite :5173" cmd /k "title Frontend Vite :5173 && cd /d "%PROJECT_DIR%" && npm run dev:frontend"
echo  [OK] Frontend Vite iniciado en puerto 5173.

:SKIP_VITE

REM =================================================================
echo.
echo  +-----------------------------------------------------------------+
echo  ^|  PASO 11: Esperando que el Gateway este operativo    [v0.3.0]  ^|
echo  +-----------------------------------------------------------------+
echo.
REM v0.3.0: Polling cada 2 segundos (binario arranca en ~2s).
REM   Maximo 30 intentos = 60 segundos de espera total.
echo  Polling al Gateway cada 2s (max 30 intentos = 60s)...
echo.

set "GW_READY=0"
set "GW_ATTEMPTS=0"
set "SHODAN_MODE=Modo simulado (sin SHODAN_API_KEY)"

:GW_WAIT_LOOP
    set /a GW_ATTEMPTS+=1
    if !GW_ATTEMPTS! gtr 30 goto :GW_TIMEOUT
    ping 127.0.0.1 -n 3 >nul
    curl.exe -s --max-time 2 -o "%TEMP%\gw_body.txt" -w "%%{http_code}" http://localhost:8080/api/health > "%TEMP%\gw_check.txt" 2>nul
    set "GW_CODE="
    set /p GW_CODE=<"%TEMP%\gw_check.txt"
    if "!GW_CODE!"=="200" (
        set "GW_READY=1"
        goto :GW_READY
    )
    echo  [!GW_ATTEMPTS!/30] Gateway: HTTP !GW_CODE! - esperando arranque...
    goto :GW_WAIT_LOOP

:GW_TIMEOUT
echo.
echo  [AVISO] Gateway no respondio en 60s.
echo          Puede seguir inicializando en segundo plano.
echo          Verifica: http://localhost:8080/api/health
echo          Si falla: ejecuta START_CYBERSEC.bat --clean-db
goto :SUMMARY

:GW_READY
echo  [OK] Rust Gateway operativo en el intento !GW_ATTEMPTS! (HTTP 200)

REM ---- Verificar modo Shodan via health check ----------------------
curl.exe -s --max-time 3 http://localhost:8080/api/health > "%TEMP%\gw_health.txt" 2>nul
findstr /c:"\"shodan\":true" "%TEMP%\gw_health.txt" >nul 2>&1
if %errorlevel%==0 (
    set "SHODAN_MODE=API Key configurada - datos reales"
) else (
    set "SHODAN_MODE=Modo simulado - agregar SHODAN_API_KEY en .env"
)

REM ---- Verificar endpoint /api/ip/exposures (fix v0.3.0) ----------
curl.exe -s --max-time 3 -o "%TEMP%\shodan_body.txt" -w "%%{http_code}" http://localhost:8080/api/ip/exposures > "%TEMP%\shodan_check.txt" 2>nul
set "SHODAN_CODE="
set /p SHODAN_CODE=<"%TEMP%\shodan_check.txt"
if "!SHODAN_CODE!"=="200" (
    echo  [OK] Endpoint /api/ip/exposures: HTTP 200 - perimetral Shodan activo
) else (
    echo  [AVISO] Endpoint /api/ip/exposures respondio HTTP !SHODAN_CODE!
    echo          Considera ejecutar: START_CYBERSEC.bat --rebuild
)

REM ---- Registrar SYSTEM_START en blockchain -----------------------
echo.
echo  Registrando evento SYSTEM_START en la blockchain...

echo {> "%TEMP%\bc_init_body.json"
echo   "event_type": "SYSTEM_START",>> "%TEMP%\bc_init_body.json"
echo   "severity": "INFO",>> "%TEMP%\bc_init_body.json"
echo   "description": "Stack CyberSec DApp v0.3.0 iniciado - Gateway binary-first, Shodan perimetral activo">> "%TEMP%\bc_init_body.json"
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
    echo  [AVISO] No se pudo registrar on-chain - la blockchain puede estar sincronizando.
)

REM =================================================================
:SUMMARY
echo.
echo  ================================================================
echo.
echo    CYBERSECURITY DAPP v0.4.0 -- STACK INICIADO
echo.
echo    BLOCKCHAIN
if defined ADDR_SECURITY (
    echo      SecurityAudit  : !ADDR_SECURITY!
    echo      AlertRegistry  : !ADDR_REGISTRY!
    echo      ArcatRoot      : !ADDR_ARCAT_ROOT!
    echo      ArcatRegistry  : !ADDR_ARCAT_REGISTRY!
) else (
    echo      Ver: deployments\localhost.json
)
echo      Red            : Chain ID !CHAIN_ID!  Anvil/Hardhat local
echo.
echo    SERVICIOS
echo      Blockchain Node: !ETH_RPC_URL!
echo      Rust Gateway   : http://localhost:8080  [binary-first v0.3.0]
echo      Health Check   : http://localhost:8080/api/health
echo      Shodan Perim.  : http://localhost:8080/api/ip/exposures
echo      Dashboard      : http://localhost:5173
echo.
echo    SHODAN.IO MONITOR
echo      Estado         : !SHODAN_MODE!
echo      Para API real  : agregar SHODAN_API_KEY en rust-gateway\.env
echo.
echo    MEJORAS v0.4.0 ACTIVAS
echo      [+] Gateway binary-first  (arranque en ~2s vs ~2min)
echo      [+] DB tolerante a esquema desactualizado (no mas crashes)
echo      [+] Ruta /api/ip/exposures corregida (sin conflicto Axum)
echo      [+] Datos simulados Shodan cuando la BD esta vacia
echo      [+] Panel Servicios: badge Shodan siempre activo
echo      [+] Persistencia real SBT: Anvil --state-file (v0.4.0)
echo      [+] Deploy condicional: no re-despliega si estado OK
echo      [+] SETUP_ANVIL_STATE.bat para configuracion inicial
echo.
echo    COMANDOS UTILES
echo      Parar stack    : STOP_CYBERSEC.bat
echo      Estado puertos : STATUS_CYBERSEC.bat
echo      Limpiar DB GW  : START_CYBERSEC.bat --clean-db
echo      Recompilar GW  : START_CYBERSEC.bat --rebuild
echo.
echo  ================================================================
echo.

echo  Abriendo Dashboard en el navegador...
ping 127.0.0.1 -n 4 >nul
start "" "http://localhost:5173"

echo  Esta ventana se cerrara automaticamente en 15 segundos.
ping 127.0.0.1 -n 16 >nul
endlocal
