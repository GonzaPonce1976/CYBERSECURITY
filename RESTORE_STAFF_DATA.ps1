# ============================================================
#  RESTORE_STAFF_DATA.ps1
#  Restaura los datos de Dependencias Staff ARCAT (STAFF)
#  luego de un reinicio del sistema operativo.
#
#  Acciones:
#   1. Re-registra alertas NEW_DEVICE_DETECTED en Gateway
#      (para que UO-TEC, UO-ADM y UO-RHH tengan dispositivos
#       disponibles para acunar SBT en blockchain).
#   2. Restaura registros Antivirus (scan-results) en Gateway
#      (los dispositivos monitoreados reaparecen en la solapa
#       Antivirus con su estado previo).
#
#  USO:
#    .\RESTORE_STAFF_DATA.ps1
#    .\RESTORE_STAFF_DATA.ps1 -GatewayUrl "http://localhost:8080"
#    .\RESTORE_STAFF_DATA.ps1 -SoloAntivirus
#    .\RESTORE_STAFF_DATA.ps1 -SoloArcat
# ============================================================

param(
    [string]$GatewayUrl   = "http://127.0.0.1:8080",
    [switch]$SoloAntivirus,
    [switch]$SoloArcat,
    [switch]$AutoArcat
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host "  |   RESTORE_STAFF_DATA.ps1 - Restaurador de Datos ARCAT/AV      |" -ForegroundColor Cyan
Write-Host "  |   Dependencias Staff ARCAT (STAFF) + Antivirus Monitoreados    |" -ForegroundColor Cyan
Write-Host "  +================================================================+" -ForegroundColor Cyan
Write-Host ""

# --- Verificar Gateway ----------------------------------------------------------
Write-Host " [1/3] Verificando conectividad con el Rust Gateway..." -ForegroundColor Gray
try {
    $health = Invoke-RestMethod -Uri "$GatewayUrl/api/health" -Method GET -TimeoutSec 8
    Write-Host "       [OK] Gateway activo - v$($health.version) | Uptime: $($health.uptime_seconds)s" -ForegroundColor Green
} catch {
    Write-Host "       [ERROR] No se puede conectar al Gateway en $GatewayUrl" -ForegroundColor Red
    Write-Host "               Ejecuta START_CYBERSEC.bat primero." -ForegroundColor Yellow
    exit 1
}

# --- Funciones auxiliares -------------------------------------------------------
function Send-Alert($payload) {
    try {
        $body  = $payload | ConvertTo-Json -Depth 5
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $resp  = Invoke-RestMethod -Uri "$GatewayUrl/api/alerts/webhook" -Method POST -Body $bytes -ContentType "application/json; charset=utf-8" -TimeoutSec 10
        return $resp.alert_id
    } catch {
        Write-Host "         WARN: $_" -ForegroundColor DarkYellow
        return $null
    }
}

function Send-AntivirusScan($payload) {
    try {
        $body  = $payload | ConvertTo-Json -Depth 5
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $resp  = Invoke-RestMethod -Uri "$GatewayUrl/api/antivirus/scan-result" -Method POST -Body $bytes -ContentType "application/json; charset=utf-8" -TimeoutSec 10
        return $true
    } catch {
        Write-Host "         WARN: $_" -ForegroundColor DarkYellow
        return $false
    }
}

$ts = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

# ==============================================================================
#  SECCION A - ARCAT: Dispositivos STAFF (UO-TEC, UO-ADM, UO-RHH)
# ==============================================================================
if (-not $SoloAntivirus) {

    Write-Host ""
    Write-Host " [2/3] Restaurando dispositivos ARCAT - Dependencias Staff ARCAT..." -ForegroundColor Cyan
    Write-Host ""

    # Dispositivos UO-TEC (De Tecnologias / Sistemas)
    $devicesStaffTec = @(
        @{ ip="192.168.125.250"; hostname="srv-tec-gw-01";    uuid="BIOS-TEC-2026-GW01-UUID";           tipo=0 },
        @{ ip="192.168.125.142"; hostname="dell-aio-fg";      uuid="4C4C4544-0033-5A10-8043-C2C04F4E4432"; tipo=1 },
        @{ ip="192.168.125.148"; hostname="laptop-tec-dev01"; uuid="BIOS-TEC-2026-LP01-UUID";           tipo=1 },
        @{ ip="192.168.125.151"; hostname="srv-tec-backup";   uuid="BIOS-TEC-2026-BAK1-UUID";           tipo=0 }
    )

    # Dispositivos UO-ADM (De Administracion)
    $devicesStaffAdm = @(
        @{ ip="192.168.125.160"; hostname="pc-adm-01"; uuid="BIOS-ADM-2026-PC01-UUID"; tipo=1 },
        @{ ip="192.168.125.161"; hostname="pc-adm-02"; uuid="BIOS-ADM-2026-PC02-UUID"; tipo=1 }
    )

    # Dispositivos UO-RHH (De Capital Humano)
    $devicesStaffRhh = @(
        @{ ip="192.168.125.170"; hostname="pc-rhh-01"; uuid="BIOS-RHH-2026-PC01-UUID"; tipo=1 }
    )

    $allStaff = $devicesStaffTec + $devicesStaffAdm + $devicesStaffRhh
    $countOk  = 0; $countFail = 0

    foreach ($d in $allStaff) {
        $payload = @{
            severity      = "INFO"
            description   = "Nombre: $($d.ip) | Hostname: $($d.hostname) | UUID: $($d.uuid) | Tipo: $($d.tipo)"
            src_ip        = $d.ip
            agent_name    = $d.hostname
            event_type    = "NEW_DEVICE_DETECTED"
            rule_level    = 3
            timestamp     = $ts
            mitre_tactics = @()
            mitre_ids     = @()
            on_chain      = $false
            source        = "restore-staff-data"
        }
        $alertId = Send-Alert $payload
        if ($alertId) {
            Write-Host "       [OK] $($d.hostname) ($($d.ip)) -> alert_id: $alertId" -ForegroundColor Green
            $countOk++
        } else {
            Write-Host "       [FAIL] $($d.hostname)" -ForegroundColor Red
            $countFail++
        }
        Start-Sleep -Milliseconds 150
    }

    Write-Host ""
    Write-Host "       Alertas NEW_DEVICE_DETECTED: $countOk ok, $countFail fallidas" -ForegroundColor $(if($countFail -gt 0){"Yellow"}else{"Green"})
    Write-Host ""
    if ($AutoArcat) {
        Write-Host "  [AUTO] Ejecutando restauracion ARCAT on-chain automática..." -ForegroundColor Yellow
        Write-Host "         npm run restore:arcat:local" -ForegroundColor Gray
        try {
            npm run restore:arcat:local | Write-Host
        } catch {
            Write-Host "         ERROR: Falló la restauración automática de ARCAT." -ForegroundColor Red
            Write-Host "         Ejecuta manualmente: npm run restore:arcat:local" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  PASO MANUAL REQUERIDO (ARCAT Blockchain):" -ForegroundColor Yellow
        Write-Host "  1. Ve a la solapa 'ARCAT Blockchain' en la DApp" -ForegroundColor White
        Write-Host "  2. Expande 'Dependencias Staff ARCAT (STAFF)'" -ForegroundColor White
        Write-Host "  3. Selecciona 'De Tecnologias / Sistemas (UO-TEC)'" -ForegroundColor White
        Write-Host "  4. Haz clic en 'Acunar Dispositivo (SBT)' y elige cada dispositivo" -ForegroundColor White
        Write-Host "  5. Repite para UO-ADM y UO-RHH" -ForegroundColor White
        Write-Host ""
        Write-Host "  NOTA: Hardhat Node NO persiste estado entre reinicios del SO." -ForegroundColor DarkCyan
        Write-Host "  Los SBT deben re-acunarse tras cada reinicio de Hardhat/Anvil." -ForegroundColor DarkCyan
    }
}

# ==============================================================================
#  SECCION B - ANTIVIRUS: Dispositivos Monitoreados
# ==============================================================================
if (-not $SoloArcat) {

    Write-Host ""
    Write-Host " [3/3] Restaurando Dispositivos Monitoreados - Solapa Antivirus..." -ForegroundColor Cyan
    Write-Host ""

    $avDevices = @(
        @{
            hostname="dell-aio-fg"; device_uuid="4C4C4544-0033-5A10-8043-C2C04F4E4432"
            agent_ip="192.168.125.142"; scan_mode="Weekly"; status="CLEAN"
            scanned_files=43680; infected_count=0; infected_files=@()
            scanner="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            engine_version="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            definitions_date="2026-07-03 12:42:16"; scan_duration_s=5437
            scan_paths=@("C:\Program Files","C:\Program Files (x86)")
        },
        @{
            hostname="laptop-tec-dev01"; device_uuid="BIOS-TEC-2026-LP01-UUID"
            agent_ip="192.168.125.148"; scan_mode="Daily"; status="CLEAN"
            scanned_files=28430; infected_count=0; infected_files=@()
            scanner="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            engine_version="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            definitions_date="2026-07-03 12:42:16"; scan_duration_s=3120
            scan_paths=@("C:\Users","C:\Program Files")
        },
        @{
            hostname="pc-adm-01"; device_uuid="BIOS-ADM-2026-PC01-UUID"
            agent_ip="192.168.125.160"; scan_mode="Daily"; status="CLEAN"
            scanned_files=19870; infected_count=0; infected_files=@()
            scanner="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            engine_version="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            definitions_date="2026-07-03 12:42:16"; scan_duration_s=2450
            scan_paths=@("C:\Users","C:\Program Files")
        },
        @{
            hostname="pc-adm-02"; device_uuid="BIOS-ADM-2026-PC02-UUID"
            agent_ip="192.168.125.161"; scan_mode="Daily"; status="CLEAN"
            scanned_files=21340; infected_count=0; infected_files=@()
            scanner="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            engine_version="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            definitions_date="2026-07-03 12:42:16"; scan_duration_s=2780
            scan_paths=@("C:\Users","C:\Program Files")
        },
        @{
            hostname="pc-rhh-01"; device_uuid="BIOS-RHH-2026-PC01-UUID"
            agent_ip="192.168.125.170"; scan_mode="Daily"; status="CLEAN"
            scanned_files=17560; infected_count=0; infected_files=@()
            scanner="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            engine_version="ClamAV 1.4.2/28053/Tue Jul  7 03:24:37 2026"
            definitions_date="2026-07-03 12:42:16"; scan_duration_s=2100
            scan_paths=@("C:\Users","C:\Program Files")
        }
    )

    $avOk=0; $avFail=0

    foreach ($dev in $avDevices) {
        $payload = @{
            hostname         = $dev.hostname
            device_uuid      = $dev.device_uuid
            agent_ip         = $dev.agent_ip
            scan_mode        = $dev.scan_mode
            status           = $dev.status
            scanned_files    = $dev.scanned_files
            infected_count   = $dev.infected_count
            infected_files   = $dev.infected_files
            scanner          = $dev.scanner
            engine_version   = $dev.engine_version
            definitions_date = $dev.definitions_date
            scan_duration_s  = $dev.scan_duration_s
            scan_paths       = $dev.scan_paths
        }
        $ok = Send-AntivirusScan $payload
        if ($ok) {
            Write-Host "       [OK] $($dev.hostname) ($($dev.agent_ip)) -> $($dev.status)" -ForegroundColor Green
            $avOk++
        } else {
            Write-Host "       [FAIL] $($dev.hostname)" -ForegroundColor Red
            $avFail++
        }
        Start-Sleep -Milliseconds 200
    }

    Write-Host ""
    Write-Host "       Dispositivos antivirus restaurados: $avOk ok, $avFail fallidos" -ForegroundColor $(if($avFail -gt 0){"Yellow"}else{"Green"})
}

# --- Resumen final --------------------------------------------------------------
Write-Host ""
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host "  |   RESTAURACION COMPLETADA                                      |" -ForegroundColor Green
Write-Host "  +================================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Proximos pasos:" -ForegroundColor White
Write-Host ""
Write-Host "  ANTIVIRUS: DApp -> solapa 'Antivirus'" -ForegroundColor Cyan
Write-Host "     Los dispositivos monitoreados deben aparecer nuevamente." -ForegroundColor Gray
Write-Host ""
Write-Host "  ARCAT: DApp -> solapa 'ARCAT Blockchain' -> STAFF -> UO-TEC" -ForegroundColor Cyan
Write-Host "     Haz clic en 'Acunar Dispositivo (SBT)' para re-acunar." -ForegroundColor Gray
Write-Host ""
Write-Host "  RECOMENDACION FUTURA: Usa Anvil con '--state-file state.json'" -ForegroundColor Yellow
Write-Host "  para persistir el estado blockchain entre reinicios del SO." -ForegroundColor Yellow
Write-Host ""
