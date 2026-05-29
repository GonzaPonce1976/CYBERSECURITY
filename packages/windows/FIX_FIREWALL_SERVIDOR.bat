:: ============================================================
:: FIX_FIREWALL_SERVIDOR.bat
:: Ejecutar como Administrador en el SERVIDOR (192.168.18.30)
:: Abre el firewall para que los clientes MSI puedan conectarse
:: ============================================================
@echo off
echo.
echo === CyberSec Gateway - Configuracion de Firewall del Servidor ===
echo.

:: Verificar privilegios de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Ejecutar como Administrador
    echo        Clic derecho sobre este archivo -> Ejecutar como administrador
    pause
    exit /b 1
)

echo [1/2] Abriendo puerto 8080 para conexiones de agentes SOC...
netsh advfirewall firewall delete rule name="CyberSec Gateway API 8080" >nul 2>&1
netsh advfirewall firewall add rule name="CyberSec Gateway API 8080" ^
    dir=in action=allow protocol=TCP localport=8080 enable=yes profile=any ^
    description="Permite que los agentes endpoint envien alertas al gateway central SOC"
if %errorLevel%==0 (
    echo    [OK] Puerto 8080 abierto
) else (
    echo    [ERROR] No se pudo abrir el puerto 8080
)

echo [2/2] Abriendo puerto 5173 para acceso al dashboard desde la LAN...
netsh advfirewall firewall delete rule name="CyberSec Dashboard 5173" >nul 2>&1
netsh advfirewall firewall add rule name="CyberSec Dashboard 5173" ^
    dir=in action=allow protocol=TCP localport=5173 enable=yes profile=any ^
    description="Permite acceso al dashboard CyberSec desde la LAN"
if %errorLevel%==0 (
    echo    [OK] Puerto 5173 abierto
) else (
    echo    [ERROR] No se pudo abrir el puerto 5173
)

echo.
echo === Verificando reglas creadas ===
netsh advfirewall firewall show rule name="CyberSec Gateway API 8080" | findstr /i "Enabled\|LocalPort\|Direction"
netsh advfirewall firewall show rule name="CyberSec Dashboard 5173" | findstr /i "Enabled\|LocalPort\|Direction"

echo.
echo === COMPLETADO ===
echo El servidor ahora acepta conexiones de clientes en puertos 8080 y 5173
echo Los clientes MSI podran enviar alertas a http://192.168.18.30:8080
echo.
pause
