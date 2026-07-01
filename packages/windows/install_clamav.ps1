<#
.SYNOPSIS
    install_clamav.ps1 - Instalador silencioso de ClamAV para endpoints Windows
    CyberSecurity DApp - Módulo de Protección contra Malware

.DESCRIPTION
    Compatible con: Windows 10, Windows 11, Windows Server 2016/2019/2022
    
    1. Auto-eleva privilegios de Administrador si es necesario
    2. Detecta si ClamAV ya está instalado (incluyendo subcarpetas)
    3. Descarga e instala desde GitHub Releases oficial de Cisco-Talos
    4. Configura freshclam.conf (codificación ASCII, sin BOM)
    5. Descarga las firmas de virus iniciales
    6. Registra tareas programadas (con fallback a schtasks.exe en Server)

.PARAMETER GatewayIp
    IP del servidor central del gateway. Default: 192.168.125.250

.PARAMETER InstallDir
    Directorio de instalación de ClamAV. Default: C:\Program Files\ClamAV

.PARAMETER ScanScriptPath
    Ruta al script scan_and_report.ps1. Default: mismo directorio que este script.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install_clamav.ps1 -GatewayIp 192.168.125.250
    powershell -ExecutionPolicy Bypass -File install_clamav.ps1 -GatewayIp 192.168.125.250 -InstallDir "D:\ClamAV"
#>

param(
    [string]$GatewayIp       = "192.168.125.250",
    [string]$InstallDir      = "C:\Program Files\ClamAV",
    [string]$ScanScriptPath  = "",
    [switch]$SkipAdminCheck  = $false
)

# ============================================================
# ACCION 1: AUTO-ELEVACION DE PRIVILEGIOS DE ADMINISTRADOR
# Si no se ejecuta como Admin, el script se relanza a si mismo
# con privilegios elevados mostrando el prompt de UAC de Windows.
# ============================================================
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]$CurrentIdentity
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

if (-not $IsAdmin -and -not $SkipAdminCheck -and $env:CLAMAV_SKIP_ELEVATION -ne "1") {
    Write-Host "[ELEVACION] Este script requiere privilegios de Administrador." -ForegroundColor Yellow
    Write-Host "[ELEVACION] Solicitando elevacion via UAC..." -ForegroundColor Yellow
    
    $ScriptPath = $MyInvocation.MyCommand.Path
    $ArgList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -GatewayIp `"$GatewayIp`" -InstallDir `"$InstallDir`""
    if ($ScanScriptPath -ne "") {
        $ArgList += " -ScanScriptPath `"$ScanScriptPath`""
    }
    
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList $ArgList -Wait
    } catch {
        Write-Host "[ERROR] No se pudo elevar privilegios: $_" -ForegroundColor Red
        Write-Host "Por favor ejecute manualmente como Administrador." -ForegroundColor Red
        Read-Host "Presione Enter para salir"
    }
    exit 0
}

# ============================================================
# Configuracion TLS para descargas seguras
# ============================================================
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ============================================================
# Directorios de destino para Cybersec Agent
# ============================================================
$TargetScriptDir = "C:\Program Files\CybersecGateway"

if (-not (Test-Path $TargetScriptDir)) {
    try {
        New-Item -ItemType Directory -Path $TargetScriptDir -Force | Out-Null
        Write-Host "Directorio creado: $TargetScriptDir" -ForegroundColor Green
    } catch {
        Write-Host "Error creando directorio ${TargetScriptDir}: $_" -ForegroundColor Yellow
    }
}

# Copiar scripts locales al directorio de destino en Program Files
$CurrentScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$SourceScanScript = Join-Path $CurrentScriptDir "scan_and_report.ps1"
$SourceInstallScript = $MyInvocation.MyCommand.Path

$DestScanScript = Join-Path $TargetScriptDir "scan_and_report.ps1"
$DestInstallScript = Join-Path $TargetScriptDir "install_clamav.ps1"

if (Test-Path $SourceScanScript) {
    try {
        Copy-Item -Path $SourceScanScript -Destination $DestScanScript -Force
        Write-Host "Copiado: scan_and_report.ps1 -> $DestScanScript" -ForegroundColor Green
    } catch {
        Write-Host "No se pudo copiar scan_and_report.ps1 a ${TargetScriptDir}: $_" -ForegroundColor Yellow
    }
}
if (Test-Path $SourceInstallScript) {
    try {
        if ($SourceInstallScript -ne $DestInstallScript) {
            Copy-Item -Path $SourceInstallScript -Destination $DestInstallScript -Force
            Write-Host "Copiado: install_clamav.ps1 -> $DestInstallScript" -ForegroundColor Green
        }
    } catch {
        Write-Host "No se pudo copiar install_clamav.ps1 a ${TargetScriptDir}: $_" -ForegroundColor Yellow
    }
}

# ============================================================
# Variables del instalador
# ============================================================
$ScriptDir      = $TargetScriptDir
$LogFile        = Join-Path $env:TEMP "install_clamav.log"
$ClamAvVersion  = "1.4.2"
$ClamAvZip      = "clamav-$ClamAvVersion.win.x64.zip"
$ClamAvUrl      = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$ClamAvVersion/$ClamAvZip"
$TempZip        = Join-Path $env:TEMP $ClamAvZip
$ScanScript     = if ($ScanScriptPath -ne "") { $ScanScriptPath } else { $DestScanScript }

# Deteccion del sistema operativo
$OsInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
$OsCaption = if ($OsInfo) { $OsInfo.Caption } else { [System.Environment]::OSVersion.VersionString }

# ============================================================
# Funcion de logging
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Write-Host $Line -ForegroundColor $(switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "Cyan" } })
    try { Add-Content -Path $LogFile -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

# ============================================================
# Inicio del instalador
# ============================================================
Write-Log "===================================================="
Write-Log "CyberSec DApp - Instalador ClamAV v$ClamAvVersion"
Write-Log "Sistema Operativo: $OsCaption"
Write-Log "Gateway: $GatewayIp"
Write-Log "Directorio instalacion: $InstallDir"
Write-Log "Script de escaneo: $ScanScript"
Write-Log "Log de instalacion: $LogFile"
Write-Log "===================================================="

# ============================================================
# DETECCION DE CLAMAV INSTALADO (busqueda recursiva robusta)
# ============================================================
$ClamScan = Join-Path $InstallDir "clamscan.exe"

# Busqueda recursiva si no esta en la raiz del directorio
if (-not (Test-Path $ClamScan) -and (Test-Path $InstallDir)) {
    Write-Log "Buscando clamscan.exe recursivamente en: $InstallDir"
    $SubDirExe = Get-ChildItem -Path $InstallDir -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($SubDirExe) {
        $ClamScan   = $SubDirExe.FullName
        $InstallDir = $SubDirExe.DirectoryName
        Write-Log "clamscan.exe encontrado en: $ClamScan"
    }
}

# Busqueda adicional en rutas estandar de Windows
if (-not (Test-Path $ClamScan)) {
    $SearchPaths = @(
        "C:\Program Files\ClamAV",
        "C:\Program Files (x86)\ClamAV",
        "C:\ClamAV",
        "D:\ClamAV"
    )
    foreach ($searchPath in $SearchPaths) {
        if (Test-Path $searchPath) {
            $found = Get-ChildItem -Path $searchPath -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                $ClamScan   = $found.FullName
                $InstallDir = $found.DirectoryName
                Write-Log "clamscan.exe encontrado en ruta alternativa: $ClamScan"
                break
            }
        }
    }
}

if (Test-Path $ClamScan) {
    $InstalledVersion = & $ClamScan --version 2>&1 | Select-String "ClamAV" | Select-Object -First 1
    Write-Log "ClamAV ya esta instalado: $InstalledVersion" "INFO"
    Write-Log "Saltando descarga MSI. Continuando con configuracion de tareas." "INFO"
} else {
    # ============================================================
    # DESCARGA E INSTALACION DESDE GITHUB RELEASES (ZIP Portatil)
    # ============================================================
    Write-Log "Descargando ClamAV v$ClamAvVersion (ZIP portatil) desde GitHub Releases..."
    Write-Log "URL: $ClamAvUrl"
    
    try {
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $ClamAvUrl -OutFile $TempZip -UseBasicParsing -TimeoutSec 180
        $DownloadSize = (Get-Item $TempZip).Length
        Write-Log "Descarga completada: $TempZip ($([Math]::Round($DownloadSize/1MB, 1)) MB)"
    } catch {
        Write-Log "ERROR al descargar ClamAV: $_" "ERROR"
        Write-Log "Descarga manual disponible en: https://www.clamav.net/downloads" "WARN"
        Write-Log "O directamente: $ClamAvUrl" "WARN"
        exit 1
    }
    
    Write-Log "Extrayendo ClamAV portatil a: $InstallDir..."
    try {
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        
        # Expandir archivo zip
        Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
        Write-Log "ClamAV extraido correctamente en: $InstallDir"
        
        # Eliminar archivo temporal
        Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "ERROR durante la extraccion de ClamAV: $_" "ERROR"
        Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
        exit 1
    }
    
    # Re-detectar ejecutable despues de instalacion
    $ClamScan = Join-Path $InstallDir "clamscan.exe"
    if (-not (Test-Path $ClamScan)) {
        $SubDirExe = Get-ChildItem -Path $InstallDir -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($SubDirExe) {
            $ClamScan   = $SubDirExe.FullName
            $InstallDir = $SubDirExe.DirectoryName
        }
    }
}

# ============================================================
# CONFIGURACION DE FRESHCLAM.CONF
# ============================================================
$FreshclamExe  = Join-Path $InstallDir "freshclam.exe"
$FreshclamConf = Join-Path $InstallDir "freshclam.conf"

# Busqueda recursiva de freshclam.exe
if (-not (Test-Path $FreshclamExe)) {
    $SubDirFresh = Get-ChildItem -Path $InstallDir -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $SubDirFresh -and (Test-Path (Split-Path $InstallDir -Parent))) {
        $SubDirFresh = Get-ChildItem -Path (Split-Path $InstallDir -Parent) -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($SubDirFresh) {
        $FreshclamExe  = $SubDirFresh.FullName
        $FreshclamConf = Join-Path $SubDirFresh.DirectoryName "freshclam.conf"
    }
}

# Busqueda del archivo sample en el subdirectorio conf_examples
$SampleFile = Join-Path $InstallDir "freshclam.conf.sample"
if (-not (Test-Path $SampleFile)) {
    $SubDirSample = Get-ChildItem -Path (Split-Path $InstallDir -Parent) -Filter "freshclam.conf.sample" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($SubDirSample) { $SampleFile = $SubDirSample.FullName }
}

# Determinar directorio de base de datos
$DatabaseDir = Join-Path (Split-Path $FreshclamExe -Parent) "database"
if (-not (Test-Path $DatabaseDir)) {
    # Intentar crear el directorio de base de datos
    try {
        New-Item -ItemType Directory -Path $DatabaseDir -Force | Out-Null
        Write-Log "Directorio de base de datos creado: $DatabaseDir"
    } catch {
        $DatabaseDir = Join-Path "C:\Program Files\ClamAV" "database"
    }
}

if ((Test-Path $SampleFile) -and -not (Test-Path $FreshclamConf)) {
    try {
        Copy-Item -Path $SampleFile -Destination $FreshclamConf -Force
        Write-Log "freshclam.conf creado desde sample: $SampleFile"
    } catch {
        Write-Log "No se pudo copiar sample. Creando freshclam.conf minimo." "WARN"
    }
}

# Crear freshclam.conf minimo si no existe
if (-not (Test-Path $FreshclamConf)) {
    $MinimalConf = @"
DatabaseDirectory "$DatabaseDir"
UpdateLogFile "$env:TEMP\freshclam.log"
LogTime yes
LogVerbose no
DatabaseMirror database.clamav.net
Checks 6
"@
    try {
        Set-Content -Path $FreshclamConf -Value $MinimalConf -Encoding ASCII -Force
        Write-Log "freshclam.conf minimo creado: $FreshclamConf"
    } catch {
        Write-Log "ERROR al crear freshclam.conf: $_" "ERROR"
    }
} else {
    # Configurar el archivo existente
    try {
        $FreshclamContent = Get-Content $FreshclamConf -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($FreshclamContent) {
            $FreshclamContent = $FreshclamContent -replace "^Example$", ""
            $FreshclamContent = $FreshclamContent -replace "#?DatabaseDirectory.*", "DatabaseDirectory `"$DatabaseDir`""
            $FreshclamContent = $FreshclamContent -replace "#?Checks\s+.*", "Checks 6"
            # Guardar en ASCII para evitar BOM UTF-8 que rompe freshclam
            Set-Content -Path $FreshclamConf -Value $FreshclamContent -Encoding ASCII -Force
            Write-Log "freshclam.conf configurado correctamente (codificacion ASCII, sin BOM)"
        }
    } catch {
        Write-Log "WARN al configurar freshclam.conf: $_" "WARN"
    }
}

# ============================================================
# ACTUALIZACION DE FIRMAS (primera vez)
# ============================================================
if (Test-Path $FreshclamExe) {
    Write-Log "Actualizando base de firmas ClamAV (puede tardar varios minutos)..."
    try {
        $freshclamArgs = @("--config-file=`"$FreshclamConf`"", "--log=`"$env:TEMP\freshclam.log`"")
        $fproc = Start-Process -FilePath $FreshclamExe -ArgumentList $freshclamArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\freshclam_out.txt" -RedirectStandardError "$env:TEMP\freshclam_err.txt"
        if ($fproc.ExitCode -eq 0 -or $fproc.ExitCode -eq 1) {
            Write-Log "Firmas actualizadas correctamente (exit code: $($fproc.ExitCode))"
        } else {
            Write-Log "freshclam termino con codigo: $($fproc.ExitCode). Verifique $env:TEMP\freshclam_err.txt" "WARN"
        }
    } catch {
        Write-Log "WARN al actualizar firmas: $_" "WARN"
        Write-Log "Las firmas se actualizaran en el proximo ciclo programado" "WARN"
    }
} else {
    Write-Log "freshclam.exe no encontrado en: $FreshclamExe" "WARN"
}

# ============================================================
# REGISTRO DE TAREAS PROGRAMADAS
# ACCION 5: Fallback a schtasks.exe si PowerShell ScheduledTasks falla
# ============================================================

# Funcion de registro de tarea con doble mecanismo
function Register-CyberSecTask {
    param(
        [string]$TaskName,
        [string]$Description,
        [string]$Arguments,
        $Trigger,
        $Principal,
        $Settings
    )
    
    # Intento 1: PowerShell ScheduledTasks (moderno, Win8+)
    try {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arguments
        Register-ScheduledTask -TaskName $TaskName -Description $Description `
            -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings `
            -Force | Out-Null
        Write-Log "Tarea '$TaskName' registrada via ScheduledTasks PowerShell"
        return $true
    } catch {
        Write-Log "ScheduledTasks PowerShell fallo para '$TaskName': $_" "WARN"
    }
    
    # Intento 2: schtasks.exe (fallback universal, compatible con Windows Server y restricciones GPO)
    try {
        $schedule = if ($TaskName -like "*Weekly*") { "WEEKLY /D SAT /ST 03:00" } `
                    elseif ($TaskName -like "*Update*") { "HOURLY /MO 4" } `
                    else { "DAILY /ST 02:00" }
        
        $schtasksArgs = "/Create /TN `"$TaskName`" /SC $schedule /TR `"powershell.exe $Arguments`" /RU SYSTEM /RL HIGHEST /F"
        $result = Start-Process -FilePath "schtasks.exe" -ArgumentList $schtasksArgs -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -eq 0) {
            Write-Log "Tarea '$TaskName' registrada via schtasks.exe (fallback)"
            return $true
        } else {
            Write-Log "schtasks.exe fallo con exit code: $($result.ExitCode)" "WARN"
        }
    } catch {
        Write-Log "schtasks.exe fallo para '$TaskName': $_" "WARN"
    }
    
    Write-Log "No se pudo registrar la tarea '$TaskName'" "ERROR"
    return $false
}

# Parametros comunes de tareas
try {
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 3) `
                     -StartWhenAvailable -MultipleInstances IgnoreNew
} catch {
    Write-Log "No se pudieron crear parametros de tareas via PowerShell. Usando schtasks directo." "WARN"
    $Principal = $null
    $Settings  = $null
}

$BaseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" -GatewayIp `"$GatewayIp`""

Write-Log "Registrando tarea: Escaneo DIARIO (02:00 AM)..."
try {
    $DailyTrigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
    Register-CyberSecTask -TaskName "CyberSec_ClamAV_DailyScan" `
        -Description "CyberSec DApp - Escaneo antivirus diario (Escritorio/Descargas/Documentos + Temp)" `
        -Arguments "$BaseArgs -ScanMode Daily" `
        -Trigger $DailyTrigger -Principal $Principal -Settings $Settings
} catch {
    Write-Log "WARN registrando tarea diaria: $_" "WARN"
    & schtasks.exe /Create /TN "CyberSec_ClamAV_DailyScan" /SC DAILY /ST 02:00 `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" -GatewayIp `"$GatewayIp`" -ScanMode Daily" `
        /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Log $_ }
}

Write-Log "Registrando tarea: Escaneo SEMANAL (Sabados 03:00 AM)..."
try {
    $WeeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At "03:00AM"
    Register-CyberSecTask -TaskName "CyberSec_ClamAV_WeeklyScan" `
        -Description "CyberSec DApp - Escaneo profundo semanal (C:\Program Files) - Sabados 03:00 AM" `
        -Arguments "$BaseArgs -ScanMode Weekly" `
        -Trigger $WeeklyTrigger -Principal $Principal -Settings $Settings
} catch {
    Write-Log "WARN registrando tarea semanal: $_" "WARN"
    & schtasks.exe /Create /TN "CyberSec_ClamAV_WeeklyScan" /SC WEEKLY /D SAT /ST 03:00 `
        /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" -GatewayIp `"$GatewayIp`" -ScanMode Weekly" `
        /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Log $_ }
}

Write-Log "Registrando tarea: Actualizacion de FIRMAS (cada 4 horas)..."
try {
    $UpdateArgs = "--config-file=`"$FreshclamConf`""
    $UpdateAction = New-ScheduledTaskAction -Execute $FreshclamExe -Argument $UpdateArgs
    $UpdateTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 4) -Once -At (Get-Date)
    Register-ScheduledTask -TaskName "CyberSec_ClamAV_UpdateSignatures" `
        -Description "CyberSec DApp - Actualizacion periodica de firmas ClamAV (cada 4h)" `
        -Action $UpdateAction -Trigger $UpdateTrigger -Principal $Principal -Settings $Settings `
        -Force | Out-Null
    Write-Log "Tarea 'CyberSec_ClamAV_UpdateSignatures' registrada (cada 4h)"
} catch {
    Write-Log "WARN registrando tarea de actualizacion: $_" "WARN"
    & schtasks.exe /Create /TN "CyberSec_ClamAV_UpdateSignatures" /SC HOURLY /MO 4 `
        /TR "`"$FreshclamExe`" --config-file=`"$FreshclamConf`"" `
        /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Log $_ }
}

# ============================================================
# REPORTE INICIAL AUTOMÁTICO (Self-Test)
# ============================================================
Write-Log "Ejecutando autodiagnostico inicial (-SelfTest) para autoregistro en el Dashboard..."
try {
    $SelfTestArgs = "-GatewayIp `"$GatewayIp`" -SelfTest -SkipAdminCheck"
    $ProcSelfTest = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScanScript`" $SelfTestArgs" -Wait -NoNewWindow -PassThru
    Write-Log "Autodiagnostico completado con codigo de salida: $($ProcSelfTest.ExitCode)"
} catch {
    Write-Log "No se pudo ejecutar el autodiagnostico de forma automatica: $_" "WARN"
}

# ============================================================
# RESUMEN FINAL
# ============================================================
Write-Log "===================================================="
Write-Log "Instalacion y configuracion de ClamAV completada"
Write-Log "   SO detectado: $OsCaption"
Write-Log "   Ejecutable: $ClamScan"
Write-Log "   Firmas en: $DatabaseDir"
Write-Log "   Escaneo diario: 02:00 AM (Escritorio/Descargas/Documentos)"
Write-Log "   Escaneo semanal: Sabados 03:00 AM (C:\Program Files)"
Write-Log "   Actualizacion firmas: cada 4 horas"
Write-Log "   Gateway: http://${GatewayIp}:8080"
Write-Log "   Log instalacion: $LogFile"
Write-Log "===================================================="
Write-Log "SIGUIENTE PASO: Ejecutar scan_and_report.ps1 -SelfTest para verificar"

# Pausar si se ejecuta de forma interactiva (clic derecho) para que no se cierre la consola inmediatamente
if ([Environment]::UserInteractive -and $env:CLAMAV_SKIP_ELEVATION -ne "1" -and -not $SkipAdminCheck) {
    Write-Host ""
    Read-Host "Instalacion finalizada. Presione Enter para salir"
}
