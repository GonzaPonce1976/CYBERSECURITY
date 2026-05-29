$ErrorActionPreference = "Stop"
$ScriptDir = "c:\Users\USUARIO\Desktop\curso-primera\CYBERSECURITY_Dapp_VersionNew\packages\windows"
$WixDir    = Join-Path $ScriptDir "wix314-binaries"
$Candle    = Join-Path $WixDir "candle.exe"
$Light     = Join-Path $WixDir "light.exe"
$WxsFile   = Join-Path $ScriptDir "gateway-installer.wxs"
$WixObj    = Join-Path $ScriptDir "gateway-installer-network.wixobj"
$OutputMsi = Join-Path $ScriptDir "cybersec-gateway-network.msi"

Write-Host "=== CyberSec Gateway - MSI Red LAN ===" -ForegroundColor Cyan
Write-Host "Servidor destino: 192.168.18.30" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $Candle)) { throw "candle.exe no encontrado" }
if (-not (Test-Path $Light))  { throw "light.exe no encontrado" }
Write-Host "[OK] WiX encontrado" -ForegroundColor Green

$GatewayExe = "c:\Users\USUARIO\Desktop\curso-primera\CYBERSECURITY_Dapp_VersionNew\rust-gateway\target\release\cybersec-gateway.exe"
if (-not (Test-Path $GatewayExe)) { throw "cybersec-gateway.exe no encontrado" }
Write-Host "[OK] Binario Rust encontrado" -ForegroundColor Green
Write-Host ""

# Cargar dinámicamente los contratos desplegados en localhost
$DeployFile = "c:\Users\USUARIO\Desktop\curso-primera\CYBERSECURITY_Dapp_VersionNew\deployments\localhost.json"
if (-not (Test-Path $DeployFile)) { throw "deployments/localhost.json no encontrado - ejecuta primero: npm run deploy:local" }
$DeployJson = Get-Content $DeployFile | ConvertFrom-Json
$AuditAddr = $DeployJson.contracts.SecurityAudit
$RegistryAddr = $DeployJson.contracts.AlertRegistry

Write-Host "Contratos inyectados en el instalador:" -ForegroundColor Gray
Write-Host "  SecurityAudit -> $AuditAddr" -ForegroundColor Gray
Write-Host "  AlertRegistry -> $RegistryAddr" -ForegroundColor Gray
Write-Host ""

Write-Host "[1/2] candle.exe compilando WXS..." -ForegroundColor Yellow
& $Candle -nologo $WxsFile -out $WixObj -ext WixUtilExtension -ext WixUIExtension `
    -dCONTRACT_SECURITY_AUDIT=$AuditAddr -dCONTRACT_ALERT_REGISTRY=$RegistryAddr
if ($LASTEXITCODE -ne 0) { Write-Host "FALLO candle" -ForegroundColor Red; exit 1 }
Write-Host "      OK" -ForegroundColor Gray

Write-Host "[2/2] light.exe enlazando MSI..." -ForegroundColor Yellow
& $Light $WixObj -out $OutputMsi -ext WixUtilExtension -ext WixUIExtension
if ($LASTEXITCODE -ne 0) { Write-Host "FALLO light" -ForegroundColor Red; exit 1 }

if (Test-Path $OutputMsi) {
    $SizeMB = [math]::Round((Get-Item $OutputMsi).Length / 1MB, 2)
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor Green
    Write-Host "  MSI generado exitosamente!" -ForegroundColor Green
    Write-Host "  cybersec-gateway-network.msi" -ForegroundColor Green
    Write-Host "  Tamano: $SizeMB MB" -ForegroundColor Green
    Write-Host "===========================================" -ForegroundColor Green
} else {
    Write-Host "ERROR: MSI no generado" -ForegroundColor Red
    exit 1
}
