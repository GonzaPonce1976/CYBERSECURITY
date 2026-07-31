@echo off
title CyberSecurity DApp - Git Push Automatico
color 0B
echo.
echo ==============================================================
echo Subiendo commits locales al repositorio remoto (gonza main)...
echo ==============================================================
echo.

cd /d "%~dp0"
git push gonza main

echo.
echo ==============================================================
echo Operacion finalizada.
echo ==============================================================
echo.
pause
