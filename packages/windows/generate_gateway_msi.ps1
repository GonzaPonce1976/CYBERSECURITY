param (
    [string]$MSI_NAME = "cybersec-gateway.msi",
    [string]$WIX_TOOLS_PATH = "",
    [string]$SIGN = "no",
    [string]$SIGN_TOOLS_PATH = "",
    [string]$CERTIFICATE_PATH = "",
    [string]$CERTIFICATE_PASSWORD = "",
    [switch]$help
)

$CANDLE_EXE = "candle.exe"
$LIGHT_EXE = "light.exe"
$SIGNTOOL_EXE = "signtool.exe"

if ($help.isPresent) {
    Write-Host "Build the Cybersec Gateway MSI package."
    Write-Host ""
    Write-Host "PARAMETERS:"
    Write-Host "  -MSI_NAME <name>            Output MSI name (default: cybersec-gateway.msi)"
    Write-Host "  -WIX_TOOLS_PATH <path>      Path to WiX tools directory containing candle.exe and light.exe"
    Write-Host "  -SIGN <yes/no>              Sign the final MSI with signtool (default: no)"
    Write-Host "  -SIGN_TOOLS_PATH <path>     Path to signtool.exe"
    Write-Host "  -CERTIFICATE_PATH <path>    Path to the .pfx certificate for signing"
    Write-Host "  -CERTIFICATE_PASSWORD <pw>  Password for the .pfx certificate"
    Write-Host ""
    Write-Host "Example:"
    Write-Host "  ./generate_gateway_msi.ps1 -MSI_NAME cybersec-gateway.msi -WIX_TOOLS_PATH `"C:\Program Files (x86)\WiX Toolset v3.11\bin`" -SIGN no"
    Exit
}

if ($WIX_TOOLS_PATH -ne "") {
    $CANDLE_EXE = Join-Path $WIX_TOOLS_PATH "candle.exe"
    $LIGHT_EXE = Join-Path $WIX_TOOLS_PATH "light.exe"
}

if ($SIGN_TOOLS_PATH -ne "") {
    $SIGNTOOL_EXE = Join-Path $SIGN_TOOLS_PATH "signtool.exe"
}

Write-Host "Building gateway MSI installer: $MSI_NAME"

& $CANDLE_EXE -nologo .\gateway-installer.wxs -out "gateway-installer.wixobj" -ext WixUtilExtension -ext WixUIExtension
if ($LASTEXITCODE -ne 0) { Exit $LASTEXITCODE }

& $LIGHT_EXE "gateway-installer.wixobj" -out $MSI_NAME -ext WixUtilExtension -ext WixUIExtension
if ($LASTEXITCODE -ne 0) { Exit $LASTEXITCODE }

if ($SIGN -eq "yes") {
    Write-Host "Signing $MSI_NAME..."
    $signOptions = @("/fd", "SHA256", "/td", "SHA256", "/tr", "http://timestamp.digicert.com")
    if ($CERTIFICATE_PATH -ne "" -and $CERTIFICATE_PASSWORD -ne "") {
        $signOptions = @("/f", "`"$CERTIFICATE_PATH`"", "/p", "`"$CERTIFICATE_PASSWORD`"", "/fd", "SHA256", "/td", "SHA256", "/tr", "http://timestamp.digicert.com")
    } else {
        $signOptions = @("/a", "/fd", "SHA256", "/td", "SHA256", "/tr", "http://timestamp.digicert.com")
    }
    & $SIGNTOOL_EXE sign @signOptions $MSI_NAME
    if ($LASTEXITCODE -ne 0) { Exit $LASTEXITCODE }
}

Write-Host "Created $MSI_NAME"
