@echo off
set "PROJECT_DIR=C:\Users\USUARIO\Desktop\curso-primera\CYBERSECURITY_Dapp_VersionNew"
for /f "usebackq tokens=1,2 delims==" %%i in ("%PROJECT_DIR%\.env") do (
    if "%%i"=="CONTRACT_SECURITY_AUDIT" set "ADDR_SECURITY=%%j"
    if "%%i"=="CONTRACT_ALERT_REGISTRY" set "ADDR_REGISTRY=%%j"
)
echo SecurityAudit: %ADDR_SECURITY%
echo AlertRegistry: %ADDR_REGISTRY%
