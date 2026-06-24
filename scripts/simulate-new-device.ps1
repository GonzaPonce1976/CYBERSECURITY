# simulate-new-device.ps1 — Simula la detección de un nuevo dispositivo en la LAN
# para probar la acuñación automatizada de SBT en la solapa ARCAT Blockchain.

param (
    [string]$Name = "Servidor DGR-REC-01",
    [string]$Hostname = "dgr-rec-01",
    [string]$Uuid = "",
    [int]$Type = 0 # 0=Server, 1=Workstation, 2=Firewall, 3=Switch
)

$GATEWAY_URL = "http://127.0.0.1:8080"
$WEBHOOK_URL = "$GATEWAY_URL/api/alerts/webhook"

# Si no se provee UUID, generar uno aleatorio
if ([string]::IsNullOrEmpty($Uuid)) {
    $Uuid = "BIOS-" + (Get-Random -Minimum 100000 -Maximum 999999) + "-UUID"
}

Write-Host ""
Write-Host "=== ARCAT - Simulador de Detección de Dispositivo ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Dispositivo a simular:" -ForegroundColor Gray
Write-Host "  Nombre   : $Name" -ForegroundColor White
Write-Host "  Hostname : $Hostname" -ForegroundColor White
Write-Host "  UUID     : $Uuid" -ForegroundColor White
Write-Host "  Tipo     : $Type" -ForegroundColor White
Write-Host ""

# Verificar que el Gateway esté corriendo
try {
    $health = Invoke-RestMethod -Uri "$GATEWAY_URL/api/health" -Method GET -TimeoutSec 5
    Write-Host "[OK] Gateway activo - Versión $($health.version)" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] El Rust Gateway no está activo en $GATEWAY_URL" -ForegroundColor Red
    Write-Host "        Inícialo primero usando START_CYBERSEC.bat o RESTART_GATEWAY.bat" -ForegroundColor Yellow
    exit 1
}

# Construir el payload de la alerta de detección de nuevo dispositivo
$timestamp = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$description = "Nombre: $Name | Hostname: $Hostname | UUID: $Uuid | Tipo: $Type"

$body = @{
    severity      = "INFO"
    description   = $description
    src_ip        = "192.168.1.150"
    agent_name    = $Hostname
    event_type    = "NEW_DEVICE_DETECTED"
    rule_level    = 3
    timestamp     = $timestamp
    mitre_tactics = @()
    mitre_ids     = @()
    on_chain      = $false
    source        = "wazuh-agent-msi-windows"
} | ConvertTo-Json -Depth 5

try {
    $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method POST `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
        -ContentType "application/json; charset=utf-8" -TimeoutSec 10

    Write-Host ""
    Write-Host "⚡ Alerta enviada con éxito al Rust Gateway!" -ForegroundColor Green
    Write-Host "   ID Alerta: $($response.alert_id)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Pasos siguientes:" -ForegroundColor Yellow
    Write-Host "1. Abre la DApp en: http://localhost:5173" -ForegroundColor White
    Write-Host "2. Ve a la solapa ARCAT Blockchain." -ForegroundColor White
    Write-Host "3. Despliega la Dirección General de Rentas (DGR) y selecciona 'De Recaudacion' (UO-REC)." -ForegroundColor White
    Write-Host "4. Haz clic en 'Acuñar Dispositivo (SBT)'." -ForegroundColor White
    Write-Host "5. ¡El dispositivo '$Name' aparecerá en la lista para ser acuñado automáticamente!" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "[FAIL] Error al enviar la alerta: $($_.Exception.Message)" -ForegroundColor Red
}
