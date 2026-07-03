$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$WixDir    = Join-Path $ScriptDir "wix314-binaries"
$Candle    = Join-Path $WixDir "candle.exe"
$Light     = Join-Path $WixDir "light.exe"
$WxsFile   = Join-Path $ScriptDir "cybersec-antivirus-agent.wxs"
$WixObj    = Join-Path $ScriptDir "cybersec-antivirus-agent.wixobj"
$OutputMsi = Join-Path $ScriptDir "cybersec-antivirus-agent.msi"

Write-Host "=== CyberSec Antivirus Agent - MSI Build Pipeline ===" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $Candle)) { throw "candle.exe no encontrado en: $Candle" }
if (-not (Test-Path $Light))  { throw "light.exe no encontrado en: $Light" }
Write-Host "[OK] WiX encontrado" -ForegroundColor Green

# Verificar scripts
$InstallScript = Join-Path $ScriptDir "install_clamav.ps1"
$ScanScript = Join-Path $ScriptDir "scan_and_report.ps1"
if (-not (Test-Path $InstallScript)) { throw "install_clamav.ps1 no encontrado" }
if (-not (Test-Path $ScanScript)) { throw "scan_and_report.ps1 no encontrado" }
Write-Host "[OK] Scripts de PowerShell verificados" -ForegroundColor Green
Write-Host ""

Write-Host "[1/2] candle.exe compilando WXS..." -ForegroundColor Yellow
& $Candle -nologo $WxsFile -out $WixObj -ext WixUtilExtension -ext WixUIExtension
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
    Write-Host "  cybersec-antivirus-agent.msi" -ForegroundColor Green
    Write-Host "  Tamano: $SizeMB MB" -ForegroundColor Green
    Write-Host "===========================================" -ForegroundColor Green
} else {
    Write-Host "ERROR: MSI no generado" -ForegroundColor Red
    exit 1
}
