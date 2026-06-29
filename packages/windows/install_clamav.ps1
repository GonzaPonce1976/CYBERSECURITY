#Requires -RunAsAdministrator
<#
.SYNOPSIS
    install_clamav.ps1 — Instalador silencioso de ClamAV para endpoints Windows
    CyberSecurity DApp — Módulo de Protección contra Malware

.DESCRIPTION
    1. Detecta si ClamAV ya está instalado
    2. Descarga la última versión estable desde el mirror oficial de ClamAV
    3. Instala silenciosamente via msiexec
    4. Configura freshclam.conf para actualización periódica de firmas
    5. Registra tarea programada para escaneo diario (scan_and_report.ps1)
    6. Registra tarea programada para escaneo semanal profundo (C:\Program Files)

.PARAMETER GatewayIp
    IP del servidor central del gateway. Default: 192.168.125.250

.PARAMETER InstallDir
    Directorio de instalación de ClamAV. Default: C:\Program Files\ClamAV

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_clamav.ps1 -GatewayIp 192.168.125.250
#>

param(
    [string]$GatewayIp   = "192.168.125.250",
    [string]$InstallDir  = "C:\Program Files\ClamAV"
)

# ─── Configuración TLS ────────────────────────────────────────────────────────
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ─── Variables ────────────────────────────────────────────────────────────────
$ScriptDir      = if ($PSScriptRoot) { $PSScriptRoot } else { "C:\Program Files\CybersecGateway" }
$LogFile        = Join-Path $ScriptDir "install_clamav.log"
$ClamAvVersion  = "1.4.2"
$ClamAvMsi      = "ClamAV-$ClamAvVersion.win.x64.msi"
# Mirror oficial de ClamAV
$ClamAvUrl      = "https://www.clamav.net/downloads/production/$ClamAvMsi"
$TempMsi        = Join-Path $env:TEMP $ClamAvMsi
$ScanScript     = Join-Path $ScriptDir "scan_and_report.ps1"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

Write-Log "════════════════════════════════════════════════════"
Write-Log "CyberSec DApp — Instalador ClamAV v$ClamAvVersion"
Write-Log "Gateway: $GatewayIp"
Write-Log "════════════════════════════════════════════════════"

# ─── Verificar si ClamAV ya está instalado ────────────────────────────────────
$ClamScan = Join-Path $InstallDir "clamscan.exe"
if (Test-Path $ClamScan) {
    $InstalledVersion = & $ClamScan --version 2>&1 | Select-String "ClamAV" | Select-Object -First 1
    Write-Log "ClamAV ya está instalado: $InstalledVersion" "INFO"
    Write-Log "Saltando instalación. Continuando con configuración de tareas programadas." "INFO"
} else {
    # ─── Descargar ClamAV MSI ─────────────────────────────────────────────────
    Write-Log "Descargando ClamAV desde: $ClamAvUrl"
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ClamAvUrl -OutFile $TempMsi -UseBasicParsing -TimeoutSec 120
        Write-Log "Descarga completada: $TempMsi"
    } catch {
        Write-Log "ERROR al descargar ClamAV: $_" "ERROR"
        Write-Log "Descarga manual requerida desde: https://www.clamav.net/downloads" "WARN"
        exit 1
    }

    # ─── Instalar silenciosamente ─────────────────────────────────────────────
    Write-Log "Instalando ClamAV (modo silencioso)..."
    try {
        $InstallArgs = "/i `"$TempMsi`" /qn /norestart INSTALLDIR=`"$InstallDir`""
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-Log "ERROR: msiexec retornó código $($proc.ExitCode)" "ERROR"
            exit 1
        }
        Write-Log "ClamAV instalado correctamente en: $InstallDir"
    } catch {
        Write-Log "ERROR durante instalación: $_" "ERROR"
        exit 1
    }

    # Limpiar archivo temporal
    Remove-Item -Path $TempMsi -Force -ErrorAction SilentlyContinue
}

# ─── Configurar freshclam.conf ────────────────────────────────────────────────
$FreshclamConf  = Join-Path $InstallDir "freshclam.conf"
$FreshclamExe   = Join-Path $InstallDir "freshclam.exe"

if (Test-Path (Join-Path $InstallDir "freshclam.conf.sample")) {
    Copy-Item -Path (Join-Path $InstallDir "freshclam.conf.sample") -Destination $FreshclamConf -Force
    Write-Log "freshclam.conf creado desde sample"
}

if (Test-Path $FreshclamConf) {
    $FreshclamContent = Get-Content $FreshclamConf
    # Activar DatabaseMirror y configurar actualizaciones cada 4 horas
    $FreshclamContent = $FreshclamContent -replace "#?DatabaseDirectory.*", "DatabaseDirectory `"$InstallDir\database`""
    $FreshclamContent = $FreshclamContent -replace "#?Checks.*", "Checks 6"
    $FreshclamContent = $FreshclamContent -replace "^Example$", ""
    Set-Content -Path $FreshclamConf -Value $FreshclamContent -Encoding UTF8
    Write-Log "freshclam.conf configurado (actualizaciones cada 4h)"
}

# ─── Actualizar firmas por primera vez ────────────────────────────────────────
if (Test-Path $FreshclamExe) {
    Write-Log "Actualizando base de firmas ClamAV (primera vez)..."
    try {
        & $FreshclamExe --config-file="$FreshclamConf" 2>&1 | ForEach-Object { Write-Log $_ }
        Write-Log "Firmas actualizadas correctamente"
    } catch {
        Write-Log "Advertencia: No se pudo actualizar firmas ahora: $_" "WARN"
        Write-Log "Se reintentará en el próximo ciclo programado" "WARN"
    }
}

# ─── Registrar Tarea Programada: Escaneo Diario (C:\Users + C:\Windows\Temp) ──
Write-Log "Registrando tarea programada de escaneo diario..."
try {
    $DailyAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" -GatewayIp `"$GatewayIp`" -ScanMode Daily"

    $DailyTrigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"

    $Principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $Settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName "CyberSec_ClamAV_DailyScan" `
        -Description "CyberSec DApp — Escaneo antivirus diario (C:\Users + C:\Windows\Temp)" `
        -Action $DailyAction `
        -Trigger $DailyTrigger `
        -Principal $Principal `
        -Settings $Settings `
        -Force | Out-Null

    Write-Log "Tarea 'CyberSec_ClamAV_DailyScan' registrada (02:00 AM diario)"
} catch {
    Write-Log "ERROR al registrar tarea diaria: $_" "ERROR"
}

# ─── Registrar Tarea Programada: Escaneo Semanal Profundo (C:\Program Files) ──
Write-Log "Registrando tarea programada de escaneo semanal profundo..."
try {
    $WeeklyAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" -GatewayIp `"$GatewayIp`" -ScanMode Weekly"

    $WeeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At "03:00AM"

    Register-ScheduledTask `
        -TaskName "CyberSec_ClamAV_WeeklyScan" `
        -Description "CyberSec DApp — Escaneo profundo semanal (C:\Program Files) — Sábados 03:00 AM" `
        -Action $WeeklyAction `
        -Trigger $WeeklyTrigger `
        -Principal $Principal `
        -Settings $Settings `
        -Force | Out-Null

    Write-Log "Tarea 'CyberSec_ClamAV_WeeklyScan' registrada (Sábados 03:00 AM)"
} catch {
    Write-Log "ERROR al registrar tarea semanal: $_" "ERROR"
}

# ─── Registrar Tarea: Actualización de Firmas (cada 4 horas) ──────────────────
Write-Log "Registrando tarea de actualización de firmas..."
try {
    $UpdateAction = New-ScheduledTaskAction `
        -Execute $FreshclamExe `
        -Argument "--config-file=`"$FreshclamConf`""

    $UpdateTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 4) -Once -At (Get-Date)

    Register-ScheduledTask `
        -TaskName "CyberSec_ClamAV_UpdateSignatures" `
        -Description "CyberSec DApp — Actualización periódica de firmas ClamAV (cada 4h)" `
        -Action $UpdateAction `
        -Trigger $UpdateTrigger `
        -Principal $Principal `
        -Settings $Settings `
        -Force | Out-Null

    Write-Log "Tarea 'CyberSec_ClamAV_UpdateSignatures' registrada (cada 4h)"
} catch {
    Write-Log "ERROR al registrar tarea de actualización: $_" "ERROR"
}

Write-Log "════════════════════════════════════════════════════"
Write-Log "✅ Instalación y configuración de ClamAV completada"
Write-Log "   - Escaneo diario: 02:00 AM (C:\Users + C:\Windows\Temp)"
Write-Log "   - Escaneo semanal: Sábados 03:00 AM (C:\Program Files)"
Write-Log "   - Actualización firmas: cada 4 horas"
Write-Log "   - Gateway de reportes: http://${GatewayIp}:8080"
Write-Log "════════════════════════════════════════════════════"
