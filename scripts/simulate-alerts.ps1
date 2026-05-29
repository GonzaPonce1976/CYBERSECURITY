# simulate-alerts.ps1 — Simulador de alertas Wazuh para CyberSec DApp

$GATEWAY_URL = "http://127.0.0.1:8080"
$WEBHOOK_URL = "$GATEWAY_URL/api/alerts/webhook"

Write-Host ""
Write-Host "=== CyberSec DApp - Simulador de Alertas Wazuh ===" -ForegroundColor Cyan
Write-Host ""

# Verificar que el Gateway este corriendo
try {
    $health = Invoke-RestMethod -Uri "$GATEWAY_URL/api/health" -Method GET -TimeoutSec 5
    Write-Host "[OK] Gateway activo - Version $($health.version) | Uptime: $($health.uptime_seconds)s" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] El Rust Gateway no esta disponible en $GATEWAY_URL" -ForegroundColor Red
    Write-Host "        Ejecuta primero: npm run dev:gateway" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Definir alertas de prueba (sin caracteres especiales)
$alerts = @(
    @{
        severity      = "CRITICAL"
        description   = "Brute force SSH detectado - 1247 intentos fallidos desde IP externa en 5 minutos"
        src_ip        = "185.220.101.42"
        agent_name    = "windows-agent-local"
        event_type    = "authentication_failure"
        rule_level    = 15
        mitre_tactics = @("Credential Access", "Persistence")
        mitre_ids     = @("T1110", "T1078")
    },
    @{
        severity      = "CRITICAL"
        description   = "Malware Emotet detectado - archivo sospechoso svchosts.exe ejecutandose en C:\Users\Public"
        src_ip        = "10.0.0.105"
        agent_name    = "windows-agent-local"
        event_type    = "malware_detected"
        rule_level    = 14
        mitre_tactics = @("Execution", "Persistence")
        mitre_ids     = @("T1059", "T1547")
    },
    @{
        severity      = "HIGH"
        description   = "SQL Injection detectado en endpoint /api/users - payload OR 1=1 detectado"
        src_ip        = "203.0.113.55"
        agent_name    = "windows-agent-local"
        event_type    = "web_attack"
        rule_level    = 12
        mitre_tactics = @("Initial Access", "Exfiltration")
        mitre_ids     = @("T1190", "T1567")
    },
    @{
        severity      = "HIGH"
        description   = "Escalada de privilegios - usuario ejecuto comandos como SYSTEM sin autorizacion"
        src_ip        = "192.168.1.50"
        agent_name    = "windows-agent-local"
        event_type    = "privilege_escalation"
        rule_level    = 13
        mitre_tactics = @("Privilege Escalation")
        mitre_ids     = @("T1068", "T1548")
    },
    @{
        severity      = "HIGH"
        description   = "Escaneo de puertos agresivo Nmap SYN scan detectado desde red externa - 65535 puertos en 30s"
        src_ip        = "45.33.32.156"
        agent_name    = "windows-agent-local"
        event_type    = "port_scan"
        rule_level    = 11
        mitre_tactics = @("Discovery", "Reconnaissance")
        mitre_ids     = @("T1046", "T1595")
    },
    @{
        severity      = "MEDIUM"
        description   = "Acceso fallido repetido al panel /admin - 25 intentos en los ultimos 10 minutos"
        src_ip        = "198.51.100.77"
        agent_name    = "windows-agent-local"
        event_type    = "authentication_failure"
        rule_level    = 8
        mitre_tactics = @("Credential Access")
        mitre_ids     = @("T1110.001")
    },
    @{
        severity      = "MEDIUM"
        description   = "Cryptominer detectado - proceso xmrig.exe consumiendo 98% CPU con conexion a pool minero"
        src_ip        = "10.0.0.105"
        agent_name    = "windows-agent-local"
        event_type    = "cryptominer"
        rule_level    = 9
        mitre_tactics = @("Impact")
        mitre_ids     = @("T1496")
    },
    @{
        severity      = "LOW"
        description   = "Certificado SSL expirado en servicio web interno - dominio: internal.corp.local"
        src_ip        = "10.0.0.1"
        agent_name    = "windows-agent-local"
        event_type    = "configuration_issue"
        rule_level    = 5
        mitre_tactics = @()
        mitre_ids     = @()
    },
    @{
        severity      = "LOW"
        description   = "Modificacion de archivo de sistema detectada - C:\Windows\System32\drivers\etc\hosts"
        src_ip        = "192.168.1.100"
        agent_name    = "windows-agent-local"
        event_type    = "file_integrity"
        rule_level    = 6
        mitre_tactics = @("Defense Evasion")
        mitre_ids     = @("T1565")
    },
    @{
        severity      = "INFO"
        description   = "Agente Wazuh conectado exitosamente al manager - heartbeat OK desde windows-agent-local"
        src_ip        = "127.0.0.1"
        agent_name    = "windows-agent-local"
        event_type    = "agent_connected"
        rule_level    = 3
        mitre_tactics = @()
        mitre_ids     = @()
    }
)

$severityColors = @{
    "CRITICAL" = "Red"
    "HIGH"     = "Yellow"
    "MEDIUM"   = "DarkYellow"
    "LOW"      = "Cyan"
    "INFO"     = "Gray"
}

$sent   = 0
$failed = 0
$total  = $alerts.Count

Write-Host "Enviando $total alertas simuladas al Gateway..." -ForegroundColor White
Write-Host ("-" * 60) -ForegroundColor DarkGray
Write-Host ""

foreach ($alert in $alerts) {
    $timestamp = [System.DateTime]::UtcNow.AddSeconds(-(Get-Random -Minimum 0 -Maximum 900)).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $body = @{
        severity      = $alert.severity
        description   = $alert.description
        src_ip        = $alert.src_ip
        agent_name    = $alert.agent_name
        event_type    = $alert.event_type
        rule_level    = $alert.rule_level
        timestamp     = $timestamp
        mitre_tactics = $alert.mitre_tactics
        mitre_ids     = $alert.mitre_ids
        on_chain      = ($alert.rule_level -ge 12)
        source        = "wazuh-agent-msi-windows"
    } | ConvertTo-Json -Depth 5

    try {
        $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method POST `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
            -ContentType "application/json; charset=utf-8" -TimeoutSec 10

        $color = $severityColors[$alert.severity]
        $icon = switch ($alert.severity) {
            "CRITICAL" { "[!!!]" }
            "HIGH"     { "[!! ]" }
            "MEDIUM"   { "[!  ]" }
            "LOW"      { "[.  ]" }
            default    { "[   ]" }
        }

        $desc = if ($alert.description.Length -gt 62) { $alert.description.Substring(0,62) + "..." } else { $alert.description }
        Write-Host "  $icon [$($alert.severity.PadRight(8))] $desc" -ForegroundColor $color
        Write-Host "         ID: $($response.alert_id.Substring(0,[Math]::Min(16,$response.alert_id.Length)))... | IP: $($alert.src_ip)" -ForegroundColor DarkGray
        $sent++
    } catch {
        Write-Host "  [FAIL] $($alert.severity) - $($alert.description.Substring(0,[Math]::Min(40,$alert.description.Length)))..." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        $failed++
    }

    Start-Sleep -Milliseconds 400
}

Write-Host ""
Write-Host ("-" * 60) -ForegroundColor DarkGray
Write-Host ""
Write-Host "Resultado Final:" -ForegroundColor White
Write-Host "  Enviadas OK : $sent / $total" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "  Fallidas    : $failed / $total" -ForegroundColor Red
}

Start-Sleep -Milliseconds 600
try {
    $check = Invoke-RestMethod -Uri "$GATEWAY_URL/api/alerts" -Method GET
    Write-Host "  En Gateway  : $($check.total) alertas en cache" -ForegroundColor Cyan
} catch {}

Write-Host ""
Write-Host "Dashboard: http://localhost:5173" -ForegroundColor Magenta
Write-Host "Haz clic en Refresh en el dashboard para ver las alertas." -ForegroundColor Gray
Write-Host ""
