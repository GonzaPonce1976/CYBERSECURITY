@echo off
chcp 65001 >nul
title Reiniciar Rust Gateway ARCAT
color 0A
setlocal EnableDelayedExpansion

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "GATEWAY_DIR=%PROJECT_DIR%\rust-gateway"

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   Reiniciar Rust Gateway — con variables ARCAT SBT      ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

REM Detener proceso previo en el puerto 8080
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo  [AVISO] Puerto 8080 ocupado — terminando proceso previo...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8080 " ^| findstr "LISTENING"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    ping 127.0.0.1 -n 3 >nul
    echo  [OK] Puerto 8080 liberado.
) else (
    echo  [INFO] Puerto 8080 libre.
)

echo.
echo  Buscando toolchain MSVC de Visual Studio...

set "VSTOOLS="
set "VC_PATHS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat""

for %%P in (%VC_PATHS%) do (
    if exist %%P (
        set "VSTOOLS=%%~P"
        goto :FOUND_VC
    )
)
:FOUND_VC

echo.
if defined VSTOOLS (
    echo  [OK] Usando MSVC: !VSTOOLS!
    echo  Iniciando Rust Gateway con MSVC toolchain...
    start "Rust Gateway :8080 [ARCAT activo]" cmd /k "title Rust Gateway :8080 [ARCAT activo] && call "!VSTOOLS!" x64 && cd /d "%GATEWAY_DIR%" && cargo run"
) else (
    echo  [INFO] MSVC no encontrado, usando toolchain por defecto de Rust...
    start "Rust Gateway :8080 [ARCAT activo]" cmd /k "title Rust Gateway :8080 [ARCAT activo] && cd /d "%GATEWAY_DIR%" && cargo run"
)

echo.
echo  Esperando a que el Gateway arranque (hasta 60s)...
set GW_ATTEMPTS=0
:GW_WAIT_LOOP
    set /a GW_ATTEMPTS+=1
    if !GW_ATTEMPTS! gtr 20 goto :GW_TIMEOUT
    ping 127.0.0.1 -n 4 >nul
    curl.exe -s --max-time 2 -o nul -w "%%{http_code}" http://localhost:8080/api/health > "%TEMP%\gw_check.txt" 2>nul
    set "GW_CODE="
    set /p GW_CODE<"%TEMP%\gw_check.txt"
    if "!GW_CODE!"=="200" (
        echo  [OK] Gateway operativo (intento !GW_ATTEMPTS!) - HTTP 200
        goto :GW_READY
    )
    echo  [Intento !GW_ATTEMPTS!/20] Esperando... HTTP !GW_CODE!
    goto :GW_WAIT_LOOP

:GW_TIMEOUT
echo  [AVISO] El Gateway tarda mas de lo esperado — puede seguir compilando en background.
goto :END

:GW_READY
echo.
echo  Verificando contratos ARCAT en el Gateway...
curl.exe -s http://localhost:8080/api/arcat/overview > "%TEMP%\arcat_check.txt" 2>nul
findstr /c:"\"configured\":true" "%TEMP%\arcat_check.txt" >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Contratos ARCAT configurados correctamente en el Gateway.
    echo.
    echo  Ahora en el Dashboard presiona Ctrl+F5 para recargar la pagina.
) else (
    echo  [AVISO] El Gateway aun reporta contratos ARCAT no configurados.
    echo  Verificar que se ejecuto deploy:arcat:local antes de reiniciar.
    type "%TEMP%\arcat_check.txt"
)

:END
echo.
echo  Abriendo Dashboard en el navegador...
start "" "http://localhost:5173"
echo.
pause
endlocal
