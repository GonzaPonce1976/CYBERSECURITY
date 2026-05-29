:: ============================================================
:: FIX_CLIENTE_192.168.18.35.bat
:: Ejecutar como Administrador en la PC CLIENTE (192.168.18.35)
:: Corrige la variable CENTRAL_GATEWAY_URL y reinicia el servicio
:: ============================================================
@echo off
setlocal

set SERVER_IP=192.168.18.30
set GATEWAY_PORT=8080

echo.
echo === CyberSec Gateway - Fix Rapido Cliente ===
echo Servidor SOC: %SERVER_IP%:%GATEWAY_PORT%
echo.

:: Verificar privilegios de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Ejecutar como Administrador
    pause
    exit /b 1
)

echo [1/5] Corrigiendo variable CENTRAL_GATEWAY_URL...
setx CENTRAL_GATEWAY_URL "http://%SERVER_IP%:%GATEWAY_PORT%" /M
if %errorLevel%==0 (
    echo    [OK] CENTRAL_GATEWAY_URL=http://%SERVER_IP%:%GATEWAY_PORT%
) else (
    echo    [ERROR] No se pudo actualizar la variable
)

echo [2/5] Actualizando archivo .env del gateway...
set ENV_FILE=C:\Program Files\CybersecGateway\.env
if exist "%ENV_FILE%" (
    :: Eliminar linea existente si hay
    powershell -Command "(Get-Content '%ENV_FILE%') | Where-Object {$_ -notmatch 'CENTRAL_GATEWAY_URL'} | Set-Content '%ENV_FILE%'"
    :: Agregar la linea correcta
    echo CENTRAL_GATEWAY_URL=http://%SERVER_IP%:%GATEWAY_PORT%>> "%ENV_FILE%"
    echo    [OK] .env actualizado en %ENV_FILE%
) else (
    echo    [WARN] Archivo .env no encontrado en ruta esperada
)

echo [3/5] Deteniendo el servicio CybersecGateway...
sc stop CybersecGateway >nul 2>&1
timeout /t 3 /nobreak >nul
echo    [OK] Servicio detenido

echo [4/5] Iniciando el servicio con la nueva configuracion...
sc start CybersecGateway >nul 2>&1
timeout /t 4 /nobreak >nul
echo    [OK] Servicio iniciado

echo [5/5] Verificando estado del servicio y conectividad...
sc query CybersecGateway | findstr /i "STATE"
echo.

:: Test de conectividad al gateway local
echo Probando gateway local (localhost:8080)...
powershell -Command "try { $r = Invoke-RestMethod -Uri 'http://localhost:8080/api/health' -TimeoutSec 5; Write-Host '   [OK] Gateway local responde: ok' -ForegroundColor Green } catch { Write-Host '   [ERROR] Gateway local no responde: $_' -ForegroundColor Red }"

:: Test de conectividad al servidor central
echo Probando conexion al servidor central (%SERVER_IP%:%GATEWAY_PORT%)...
powershell -Command "try { $r = Invoke-RestMethod -Uri 'http://%SERVER_IP%:%GATEWAY_PORT%/api/health' -TimeoutSec 5; Write-Host '   [OK] Servidor central alcanzable: ' $r.status -ForegroundColor Green } catch { Write-Host '   [ERROR] Servidor central NO alcanzable. Verificar firewall en el servidor. Error: $_' -ForegroundColor Red }"

echo.
echo === COMPLETADO ===
echo Si el servidor central es alcanzable, la proxima alerta sera visible en el dashboard.
echo Para generar una alerta de prueba, ejecute en PowerShell:
echo   powershell -File "C:\Program Files\CybersecGateway\test_alert.ps1"
echo.
pause
