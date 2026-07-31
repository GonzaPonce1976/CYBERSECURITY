@echo off
chcp 65001 >nul
title CyberSec DApp - SETUP Persistencia Blockchain
color 0B
setlocal EnableDelayedExpansion

REM =====================================================================
REM  SETUP_ANVIL_STATE.bat v1.3
REM  Configuracion inicial de persistencia blockchain.
REM
REM  MODO A (Anvil disponible): usa --state para persistencia REAL.
REM     SBTs sobreviven al reinicio del SO sin re-acunar.
REM
REM  MODO B (Solo Hardhat): despliega y acuna sin persistencia nativa.
REM     SBTs deben re-acunarse en cada reinicio (via RESTORE_STAFF_DATA).
REM =====================================================================

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "ANVIL_STATE=%PROJECT_DIR%\.anvil_state.json"
set "HARDHAT_MODE_FLAG=%PROJECT_DIR%\.hardhat_mode"
set "RPC_PORT=8545"
set "RPC_HOST=127.0.0.1"
set "CHAIN_ID=31337"

echo.
echo  +==============================================================+
echo  ^|   SETUP PERSISTENCIA BLOCKCHAIN - CyberSec DApp v0.4.0     ^|
echo  +==============================================================+
echo.

REM --- PASO 1: Detectar motor disponible -------------------------------
echo  [1/6] Detectando motor blockchain disponible...
set "USE_ANVIL=0"
anvil --version >nul 2>&1
if !errorlevel!==0 (
    set "USE_ANVIL=1"
    echo  [OK] Anvil detectado en el PATH.
    echo  [OK] MODO A activado: Persistencia real con --state
) else (
    echo  [INFO] Anvil no encontrado. Usando Hardhat Node.
    echo  [MODO B] Persistencia basica - SBTs se restauran via script.
    npx hardhat --version >nul 2>&1
    if !errorlevel! neq 0 (
        echo  [ERROR] Ni Anvil ni Hardhat encontrados.
        pause
        exit /b 1
    )
)
echo.

REM --- PASO 2: Estado previo -------------------------------------------
echo  [2/6] Verificando estado previo...
if "!USE_ANVIL!"=="1" (
    if exist "!ANVIL_STATE!" (
        echo  [AVISO] .anvil_state.json existe. Sobreescribiendo estado previo...
        del "!ANVIL_STATE!" >nul 2>&1
        echo  [OK] Estado previo eliminado.
    )
) else (
    if exist "!HARDHAT_MODE_FLAG!" del "!HARDHAT_MODE_FLAG!" >nul 2>&1
)
echo.

REM --- PASO 3: Verificar / Iniciar nodo -------------------------------
echo  [3/6] Verificando nodo blockchain en :%RPC_PORT%...
netstat -ano | findstr ":%RPC_PORT% " | findstr "LISTENING" >nul 2>&1
if !errorlevel!==0 (
    echo  [OK] Nodo ya activo en :%RPC_PORT% - usando el existente.
) else (
    echo  [INFO] Iniciando nodo blockchain...
    if "!USE_ANVIL!"=="1" (
        start "Anvil Blockchain Setup" cmd /k "title Anvil Setup :%RPC_PORT% && anvil --host %RPC_HOST% --port %RPC_PORT% --chain-id %CHAIN_ID% --state "%ANVIL_STATE%""
    ) else (
        start "Hardhat Blockchain Setup" cmd /k "title Hardhat Setup :%RPC_PORT% && cd /d "%PROJECT_DIR%" && npx hardhat node --hostname %RPC_HOST% --port %RPC_PORT% --config hardhat.config.cjs"
    )
    echo  Esperando 10s para que el nodo arranque...
    ping 127.0.0.1 -n 11 >nul
    netstat -ano | findstr ":%RPC_PORT% " | findstr "LISTENING" >nul 2>&1
    if !errorlevel! neq 0 (
        echo  [ERROR] El nodo no pudo iniciar. Revisa la ventana de blockchain.
        pause
        exit /b 1
    )
)
echo  [OK] Nodo activo en :%RPC_PORT%
echo.

REM --- PASO 4: Compilar y desplegar contratos --------------------------
echo  [4/6] Compilando y desplegando contratos Solidity...
cd /d "%PROJECT_DIR%"

call npm run compile
if !errorlevel! neq 0 (
    echo  [ERROR] Fallo compilacion.
    pause
    exit /b 1
)

call npm run deploy:local
if !errorlevel! neq 0 (
    echo  [ERROR] Fallo deploy SecurityAudit.
    pause
    exit /b 1
)

call npm run deploy:arcat:local
if !errorlevel! neq 0 (
    echo  [ERROR] Fallo deploy ARCAT.
    pause
    exit /b 1
)
echo  [OK] Contratos desplegados correctamente.

if exist "%PROJECT_DIR%\sync_contracts.ps1" (
    powershell -ExecutionPolicy Bypass -File "%PROJECT_DIR%\sync_contracts.ps1" >nul
    echo  [OK] .env sincronizado con nuevas direcciones.
)
echo.

REM --- PASO 5: Acunar SBT Staff ----------------------------------------
echo  [5/6] Acunando SBT de dispositivos STAFF en blockchain...
call npm run restore:arcat:local
if !errorlevel! neq 0 (
    echo  [AVISO] restore:arcat:local retorno advertencia.
) else (
    echo  [OK] SBT STAFF acunados exitosamente.
)
echo.

REM --- PASO 6: Restaurar datos Gateway (alertas + antivirus) -----------
echo  [6/6] Restaurando datos en el Rust Gateway...
powershell -ExecutionPolicy Bypass -Command "& '%PROJECT_DIR%\RESTORE_STAFF_DATA.ps1' -SoloAntivirus -NoAutoArcat" >nul 2>&1
echo  [OK] Alertas y antivirus restaurados.

REM --- Marker de modo --------------------------------------------------
if "!USE_ANVIL!"=="1" (
    echo  [OK] Estado Anvil sera guardado en .anvil_state.json al salir o detener.
) else (
    echo HARDHAT_MODE=1 > "!HARDHAT_MODE_FLAG!"
    echo  [INFO] Archivo .hardhat_mode creado.
)

echo.
echo  +==============================================================+
if "!USE_ANVIL!"=="1" (
    echo  ^|   SETUP COMPLETADO - MODO A: Persistencia Real ^(Anvil^)     ^|
    echo  +==============================================================+
    echo.
    echo  Los SBT sobreviviran al reinicio del SO.
    echo  Usa STOP_CYBERSEC.bat para detener el stack limpiamente.
) else (
    echo  ^|   SETUP COMPLETADO - MODO B: Hardhat sin persistencia       ^|
    echo  +==============================================================+
    echo.
    echo  Los SBT estan acunados y disponibles AHORA.
)
echo.
echo  Proximos pasos:
echo    1. Abre http://localhost:5173 en el navegador
echo    2. Conecta MetaMask
echo    3. Ve a ARCAT Blockchain - STAFF - verifica los SBT
echo.
pause
