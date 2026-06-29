<#
.SYNOPSIS
    scan_and_report.ps1 — Scanner ClamAV para endpoints Windows
    CyberSecurity DApp — Reporte de resultados al Gateway Central

.DESCRIPTION
    Ejecuta clamscan.exe sobre los directorios configurados según el modo:
    - Daily:  C:\Users + C:\Windows\Temp (monitoreo en tiempo real, optimizado)
    - Weekly: C:\Program Files (escaneo profundo, solo sábados)
    
    Reporta resultados al gateway via POST /api/antivirus/scan-result
    Los resultados también aparecen en las Alertas Recientes del Dashboard.
    Si se detecta malware, el gateway registra el evento en blockchain.

.PARAMETER GatewayIp
    IP del servidor central del gateway. Default: 192.168.125.250

.PARAMETER ScanMode
    Modo de escaneo: 'Daily' (por defecto) o 'Weekly'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scan_and_report.ps1 -GatewayIp 192.168.125.250 -ScanMode Daily
    powershell -ExecutionPolicy Bypass -File scan_and_report.ps1 -GatewayIp 192.168.125.250 -ScanMode Weekly
#>

param(
    [string]$GatewayIp  = "192.168.125.250",
    [string]$ScanMode   = "Daily"     # Daily | Weekly
)

# ─── Configuración TLS ────────────────────────────────────────────────────────
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ─── Variables base ───────────────────────────────────────────────────────────
$ScriptDir    = if ($PSScriptRoot) { $PSScriptRoot } else { "C:\Program Files\CybersecGateway" }
$LogFile      = Join-Path $ScriptDir "clamav_scan.log"
$ClamInstDir  = "C:\Program Files\ClamAV"
$ClamScanExe  = Join-Path $ClamInstDir "clamscan.exe"

# Paths de escaneo según modo
if ($ScanMode -eq "Weekly") {
    $ScanPaths     = @("C:\Program Files", "C:\Program Files (x86)")
    $ScanModeLabel = "SEMANAL PROFUNDO"
    $ExcludeDirs   = @()
} else {
    # Daily: C:\Users y C:\Windows\Temp — excluye carpetas de sistema pesadas
    $ScanPaths     = @("C:\Users", "C:\Windows\Temp")
    $ScanModeLabel = "DIARIO"
    $ExcludeDirs   = @("AppData\Local\Microsoft\Windows\INetCache", "AppData\Local\Packages")
}

# ─── Funciones auxiliares ─────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Get-DeviceUUID {
    try { return (Get-CimInstance Win32_ComputerSystemProduct).UUID } catch {}
    try { return (Get-WmiObject Win32_ComputerSystemProduct).UUID } catch {}
    return "UNKNOWN-UUID"
}

function Get-LocalIP {
    param([string]$GatewayHost)
    try {
        $sock = New-Object System.Net.Sockets.TcpClient
        $sock.Connect($GatewayHost, 8080)
        $ip = $sock.Client.LocalEndPoint.Address.IPAddressToString
        $sock.Close()
        return $ip
    } catch {}
    try {
        return (Get-NetIPAddress -AddressFamily IPv4 | 
                Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | 
                Select-Object -First 1).IPAddress
    } catch {}
    return "127.0.0.1"
}

# ─── Verificar ClamAV instalado ───────────────────────────────────────────────
Write-Log "═══════════════════════════════════════════════════"
Write-Log "CyberSec DApp — Escaneo Antivirus ClamAV [$ScanModeLabel]"

if (-not (Test-Path $ClamScanExe)) {
    Write-Log "ClamAV no encontrado en: $ClamScanExe" "ERROR"
    Write-Log "Ejecuta install_clamav.ps1 primero para instalarlo" "ERROR"
    
    # Reportar al gateway que ClamAV no está instalado (alerta HIGH)
    $hostname   = $env:COMPUTERNAME.ToLower()
    $deviceUUID = Get-DeviceUUID
    $localIP    = Get-LocalIP -GatewayHost $GatewayIp
    
    $ErrorPayload = @{
        hostname        = $hostname
        device_uuid     = $deviceUUID
        agent_ip        = $localIP
        scan_mode       = $ScanMode
        status          = "ERROR"
        error_message   = "ClamAV no instalado — ejecutar install_clamav.ps1"
        scanner         = "ClamAV (no instalado)"
        scanned_files   = 0
        infected_count  = 0
        infected_files  = @()
        engine_version  = "N/A"
        definitions_date = "N/A"
        scan_paths      = $ScanPaths
    } | ConvertTo-Json -Compress
    
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($ErrorPayload)
        Invoke-RestMethod -Uri "http://${GatewayIp}:8080/api/antivirus/scan-result" `
            -Method Post -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 10
    } catch { }
    exit 1
}

# ─── Obtener versión de ClamAV ────────────────────────────────────────────────
$ClamVersion = "ClamAV Unknown"
try {
    $VersionOutput = & $ClamScanExe --version 2>&1
    $ClamVersion = ($VersionOutput | Select-String "ClamAV" | Select-Object -First 1).ToString().Trim()
} catch { }
Write-Log "Motor: $ClamVersion"

# ─── Obtener fecha de firmas ──────────────────────────────────────────────────
$DefinitionsDate = "Desconocida"
$DbDir = Join-Path $ClamInstDir "database"
if (Test-Path $DbDir) {
    $LatestDb = Get-ChildItem -Path $DbDir -Filter "*.cvd" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($LatestDb) {
        $DefinitionsDate = $LatestDb.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# ─── Recopilar info del dispositivo ──────────────────────────────────────────
$Hostname   = $env:COMPUTERNAME.ToLower()
$DeviceUUID = Get-DeviceUUID
$LocalIP    = Get-LocalIP -GatewayHost $GatewayIp

Write-Log "Dispositivo: $Hostname | UUID: $DeviceUUID | IP: $LocalIP"
Write-Log "Paths a escanear: $($ScanPaths -join ', ')"

# ─── Construir argumentos de clamscan ────────────────────────────────────────
$StartTime = Get-Date
$ScanArgs  = @("--recursive", "--infected", "--no-summary")

# Agregar paths
foreach ($path in $ScanPaths) {
    if (Test-Path $path) {
        $ScanArgs += "`"$path`""
    }
}

# Agregar exclusiones para modo diario (preservar rendimiento)
foreach ($excl in $ExcludeDirs) {
    $ScanArgs += "--exclude-dir=`"$excl`""
}

# Excluir archivos muy grandes (>100MB) para preservar rendimiento
$ScanArgs += "--max-filesize=100M"
$ScanArgs += "--max-scansize=500M"

Write-Log "Iniciando escaneo ClamAV..."

# ─── Ejecutar clamscan ────────────────────────────────────────────────────────
$InfectedFiles   = [System.Collections.Generic.List[string]]::new()
$ScannedCount    = 0
$ScanOutput      = ""
$ScanExitCode    = 0

try {
    $ProcInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcInfo.FileName  = $ClamScanExe
    $ProcInfo.Arguments = $ScanArgs -join " "
    $ProcInfo.RedirectStandardOutput = $true
    $ProcInfo.RedirectStandardError  = $true
    $ProcInfo.UseShellExecute = $false
    $ProcInfo.CreateNoWindow  = $true

    $Proc = New-Object System.Diagnostics.Process
    $Proc.StartInfo = $ProcInfo
    $Proc.Start() | Out-Null

    $ScanOutput = $Proc.StandardOutput.ReadToEnd()
    $Proc.WaitForExit()
    $ScanExitCode = $Proc.ExitCode

    # Parsear output de clamscan:
    # Líneas de infección: "/path/to/file: FOUND" o "/path/to/file: Win.Trojan.xxx FOUND"
    foreach ($line in ($ScanOutput -split "`n")) {
        $line = $line.Trim()
        if ($line -match "FOUND$") {
            $InfectedFiles.Add($line)
        }
        # Contar archivos escaneados del resumen
        if ($line -match "Scanned files:\s+(\d+)") {
            $ScannedCount = [int]$Matches[1]
        }
    }
} catch {
    Write-Log "ERROR ejecutando clamscan: $_" "ERROR"
    $ScanExitCode = -1
}

$EndTime      = Get-Date
$ScanDuration = [int]($EndTime - $StartTime).TotalSeconds
$InfectedCount = $InfectedFiles.Count

# ─── Determinar estado ────────────────────────────────────────────────────────
# ClamAV exit codes: 0=OK/clean, 1=INFECTED, 2=ERROR
$ScanStatus = switch ($ScanExitCode) {
    0  { "CLEAN" }
    1  { "INFECTED" }
    -1 { "ERROR" }
    default { "ERROR" }
}

Write-Log "Escaneo completado en ${ScanDuration}s | Archivos: $ScannedCount | Infectados: $InfectedCount | Estado: $ScanStatus"

if ($InfectedCount -gt 0) {
    Write-Log "⚠️  AMENAZAS DETECTADAS:" "WARN"
    foreach ($threat in $InfectedFiles) {
        Write-Log "   🦠 $threat" "WARN"
    }
}

# ─── Construir payload para el gateway ───────────────────────────────────────
$ScanPayload = @{
    hostname         = $Hostname
    device_uuid      = $DeviceUUID
    agent_ip         = $LocalIP
    src_ip           = $LocalIP
    agent_name       = $Hostname
    scan_mode        = $ScanMode
    status           = $ScanStatus
    scanner          = $ClamVersion
    engine_version   = $ClamVersion
    definitions_date = $DefinitionsDate
    scanned_files    = $ScannedCount
    infected_count   = $InfectedCount
    infected_files   = @($InfectedFiles.ToArray())
    scan_duration_s  = $ScanDuration
    scan_paths       = $ScanPaths
    timestamp        = (Get-Date -Format "o")
} | ConvertTo-Json -Compress -Depth 5

# ─── Enviar resultado al gateway ──────────────────────────────────────────────
$GatewayUrl = "http://${GatewayIp}:8080/api/antivirus/scan-result"
Write-Log "Reportando resultado a: $GatewayUrl"

try {
    $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($ScanPayload)
    $Response = Invoke-RestMethod `
        -Uri $GatewayUrl `
        -Method Post `
        -ContentType "application/json; charset=utf-8" `
        -Body $PayloadBytes `
        -TimeoutSec 15
    Write-Log "✅ Resultado enviado al gateway. Response: $($Response | ConvertTo-Json -Compress)"
} catch {
    Write-Log "⚠️  No se pudo enviar al gateway: $_" "WARN"
    # Guardar resultado localmente para reintentar más tarde
    $LocalResultPath = Join-Path $ScriptDir "pending_scan_result.json"
    Set-Content -Path $LocalResultPath -Value $ScanPayload -Encoding UTF8
    Write-Log "Resultado guardado localmente en: $LocalResultPath" "WARN"
}

# ─── Si hay malware, también enviar alerta HIGH al webhook de alertas ─────────
# Esto permite que la detección aparezca en las Alertas Recientes del Dashboard
if ($ScanStatus -eq "INFECTED") {
    Write-Log "🚨 Enviando alerta HIGH por detección de malware..."
    
    $ThreatsFormatted = ($InfectedFiles.ToArray() | Select-Object -First 10) -join " | "
    $AlertPayload = @{
        severity       = "HIGH"
        description    = "🦠 MALWARE DETECTADO por ClamAV [$ScanModeLabel] en $Hostname. Amenazas encontradas ($InfectedCount): $ThreatsFormatted"
        src_ip         = $LocalIP
        agent_name     = $Hostname
        agent_ip       = $LocalIP
        event_type     = "MALWARE_DETECTED"
        rule_level     = 14
        mitre_tactics  = @("Execution", "Persistence")
        mitre_ids      = @("T1059", "T1547")
        malware_family = "ClamAV-Detection"
        ioc_hashes     = @()
        device_uuid    = $DeviceUUID
        scanner        = $ClamVersion
        infected_files = @($InfectedFiles.ToArray() | Select-Object -First 20)
    } | ConvertTo-Json -Compress -Depth 5

    try {
        $AlertBytes = [System.Text.Encoding]::UTF8.GetBytes($AlertPayload)
        Invoke-RestMethod `
            -Uri "http://${GatewayIp}:8080/api/alerts/webhook" `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body $AlertBytes `
            -TimeoutSec 10
        Write-Log "✅ Alerta HIGH enviada al dashboard"
    } catch {
        Write-Log "⚠️  Error enviando alerta HIGH: $_" "WARN"
    }
}

Write-Log "═══════════════════════════════════════════════════"
Write-Log "Escaneo [$ScanModeLabel] finalizado — Estado: $ScanStatus"
Write-Log "═══════════════════════════════════════════════════"

# Exit con código apropiado para Task Scheduler
exit 0
