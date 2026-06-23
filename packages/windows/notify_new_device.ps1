param(
    [string]$GatewayIp = "192.168.125.250"
)

# Configurar TLS 1.2/1.3 para peticiones externas
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Resolver carpeta de log de forma 100% segura para CustomActions de MSI (donde PSScriptRoot puede ser nulo)
$ScriptFolder = "C:\Program Files\CybersecGateway"
if ($PSScriptRoot) {
    $ScriptFolder = $PSScriptRoot
} elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$LogPath = Join-Path $ScriptFolder "notify_new_device.log"

$hostname = $env:COMPUTERNAME.ToLower()

# Obtener UUID de hardware de forma segura
$uuid = "UNKNOWN-UUID"
try {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
} catch {
    try {
        $uuid = (Get-WmiObject Win32_ComputerSystemProduct).UUID
    } catch {}
}

# Obtener IP local principal
$ip = "127.0.0.1"
try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
} catch {}

# Determinar tipo de dispositivo según el sistema operativo
$os = "Desconocido"
try {
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
} catch {}
$dType = 1 # Workstation por defecto
if ($os -like "*Server*") {
    $dType = 0 # Server
}

# Construir el mensaje formateado con las variables solicitadas
$description = "NUEVO DISPOSITIVO DETECTADO. Se solicita incorporar este dispositivo en el Inventario de Dispositivos Tokenizados (SBT) de la Blockchain (solapa ARCAT Blockchain). Datos para acuñar: Nombre: Dispositivo $env:COMPUTERNAME | Hostname: $hostname | UUID: $uuid | Tipo: $dType (0=Server, 1=Workstation) | Estado: Activo | Threat Score: 0"

# Payload de la alerta
$body = @{
    severity = "HIGH"
    description = $description
    src_ip = $ip
    agent_name = $hostname
    event_type = "NEW_DEVICE_DETECTED"
    rule_level = 12
    mitre_tactics = @("Initial Access")
    mitre_ids = @("T1190")
} | ConvertTo-Json -Compress

# Enviar alerta al Gateway Central
$url = "http://$GatewayIp:8080/api/alerts/webhook"
try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 10
    Set-Content -Path $LogPath -Value "Alerta enviada correctamente a $url. Response: $response"
} catch {
    Set-Content -Path $LogPath -Value "Error enviando alerta a $url: $_"
}

