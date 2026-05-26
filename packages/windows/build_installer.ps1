# Unified Build Script — CyberSec DApp Windows Installer
# Automates the entire process of compiling the binary and compiling the MSI.

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path "..\.."
$WindowsPackageDir = Get-Location
$GatewayDir = Join-Path $ProjectRoot "rust-gateway"
$GatewayExe = Join-Path $GatewayDir "target\release\cybersec-gateway.exe"
$WixToolsDir = Join-Path $WindowsPackageDir "wix314-binaries"
$MsiOutput = Join-Path $WindowsPackageDir "cybersec-gateway.msi"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CyberSec DApp Windows Installer Build Pipeline" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Rust Release Binary
Write-Host "`n[1/3] Verifying Rust Release Binary..." -ForegroundColor Green
if (-not (Test-Path $GatewayExe)) {
    Write-Host "Rust Release Binary not found at: $GatewayExe" -ForegroundColor Yellow
    Write-Host "Starting compilation (using build.bat)..." -ForegroundColor Yellow
    
    Push-Location $GatewayDir
    try {
        & .\build.bat
    } finally {
        Pop-Location
    }
    
    if (-not (Test-Path $GatewayExe)) {
        throw "Compilation completed, but release binary was not found at $GatewayExe"
    }
}
Write-Host "-> Rust Release Binary verified successfully: $GatewayExe" -ForegroundColor Gray

# 2. Verify WiX Toolset
Write-Host "`n[2/3] Verifying WiX Toolset..." -ForegroundColor Green
if (-not (Test-Path (Join-Path $WixToolsDir "candle.exe")) -or -not (Test-Path (Join-Path $WixToolsDir "light.exe"))) {
    throw "WiX Toolset binaries not found in $WixToolsDir. Please make sure the folder exists and contains candle.exe and light.exe."
}
Write-Host "-> WiX Toolset verified successfully: $WixToolsDir" -ForegroundColor Gray

# 3. Compile the MSI Installer
Write-Host "`n[3/3] Compiling MSI Installer..." -ForegroundColor Green
Write-Host "Running generate_gateway_msi.ps1 with WiX tools: $WixToolsDir" -ForegroundColor Gray

& .\generate_gateway_msi.ps1 -WIX_TOOLS_PATH $WixToolsDir

if (Test-Path $MsiOutput) {
    Write-Host "`n==========================================================" -ForegroundColor Green
    Write-Host "  SUCCESS: Installer created successfully!" -ForegroundColor Green
    Write-Host "  Location: $MsiOutput" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
} else {
    throw "MSI compilation finished, but output file was not found at $MsiOutput"
}
