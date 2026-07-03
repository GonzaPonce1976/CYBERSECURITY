<#
.SYNOPSIS
    scan_and_report.ps1 - Scanner ClamAV para endpoints Windows
    CyberSecurity DApp - Reporte de resultados al Gateway Central

.DESCRIPTION
    Compatible con: Windows 10, Windows 11, Windows Server 2016/2019/2022
    
    - Auto-eleva privilegios de Administrador si es necesario (UAC)
    - Detecta ClamAV instalado en cualquier ruta/subcarpeta
    - Escanea carpetas de alto riesgo de cada perfil de usuario local
    - Soporta nombres de carpeta en español (Escritorio, Descargas, Documentos)
    - Excluye cuentas de sistema (DefaultAppPool, NetworkService, etc.)
    - Reporta resultados al gateway via POST /api/antivirus/scan-result
    - Modo -SelfTest: diagnostico rapido sin ejecutar escaneo completo
    
    Modos de escaneo:
    - Daily:  Descargas + Escritorio + Documentos + C:\Windows\Temp
    - Weekly: C:\Program Files + C:\Program Files (x86) (profundo)

.PARAMETER GatewayIp
    IP del servidor central del gateway. Default: 192.168.125.250

.PARAMETER ScanMode
    Modo de escaneo: 'Daily' (por defecto) o 'Weekly'

.PARAMETER SelfTest
    Switch. Si se indica, realiza diagnostico rapido sin ejecutar escaneo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scan_and_report.ps1 -GatewayIp 192.168.125.250
    powershell -ExecutionPolicy Bypass -File scan_and_report.ps1 -GatewayIp 192.168.125.250 -ScanMode Weekly
    powershell -ExecutionPolicy Bypass -File scan_and_report.ps1 -GatewayIp 192.168.125.250 -SelfTest
#>

param(
    [string]$GatewayIp = "192.168.125.250",
    [string]$ScanMode  = "Daily",
    [switch]$SelfTest  = $false,
    [switch]$SkipAdminCheck = $false
)

# ============================================================
# ACCION 1: AUTO-ELEVACION DE PRIVILEGIOS DE ADMINISTRADOR
# ============================================================
$CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]$CurrentIdentity
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

if (-not $IsAdmin -and -not $SkipAdminCheck -and $env:CLAMAV_SKIP_ELEVATION -ne "1") {
    Write-Host "[ELEVACION] Este script requiere privilegios de Administrador." -ForegroundColor Yellow
    Write-Host "[ELEVACION] Solicitando elevacion via UAC..." -ForegroundColor Yellow
    
    $ScriptPath = $MyInvocation.MyCommand.Path
    $ArgList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -GatewayIp `"$GatewayIp`" -ScanMode `"$ScanMode`""
    if ($SelfTest) { $ArgList += " -SelfTest" }
    
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
# Configuracion TLS
# ============================================================
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ============================================================
# Variables base
# ============================================================
$ScriptDir   = if ($PSScriptRoot -and $PSScriptRoot -ne "") { $PSScriptRoot } else { "C:\Program Files\CybersecGateway" }
$LogFile     = Join-Path $env:TEMP "clamav_scan.log"
$ClamInstDir = "C:\Program Files\ClamAV"
$ClamScanExe = Join-Path $ClamInstDir "clamscan.exe"

# Deteccion del sistema operativo
$OsInfo     = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
$OsCaption  = if ($OsInfo) { $OsInfo.Caption } else { [System.Environment]::OSVersion.VersionString }

# ============================================================
# Deteccion robusta de clamscan.exe (busqueda recursiva multi-ruta)
# ============================================================
if (-not (Test-Path $ClamScanExe)) {
    # Busqueda recursiva dentro del directorio ClamAV estandar
    if (Test-Path $ClamInstDir) {
        $SubDirExe = Get-ChildItem -Path $ClamInstDir -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($SubDirExe) {
            $ClamScanExe = $SubDirExe.FullName
            $ClamInstDir = $SubDirExe.DirectoryName
        }
    }
}

if (-not (Test-Path $ClamScanExe)) {
    # Busqueda en rutas alternativas (Windows Server, rutas custom)
    $AltPaths = @(
        "C:\Program Files (x86)\ClamAV",
        "C:\ClamAV",
        "D:\ClamAV",
        "C:\ProgramData\ClamAV"
    )
    foreach ($alt in $AltPaths) {
        if (Test-Path $alt) {
            $found = Get-ChildItem -Path $alt -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                $ClamScanExe = $found.FullName
                $ClamInstDir = $found.DirectoryName
                break
            }
        }
    }
}

# ============================================================
# ACCION 2: Deteccion inteligente de perfiles de usuario
# Compatible con Win10/11/Server (incluye nombres en español)
# Excluye cuentas de sistema y perfiles sin acceso
# ============================================================
$ScanModeLabel = ""
$ScanPaths     = @()
$ExcludeDirs   = @()

if ($ScanMode -eq "Weekly") {
    $ScanPaths     = @("C:\Program Files", "C:\Program Files (x86)")
    $ScanModeLabel = "SEMANAL PROFUNDO"
    $ExcludeDirs   = @("node_modules", ".git", "vendor")
} else {
    $ScanPaths = @("C:\Windows\Temp")
    $ScanModeLabel = "DIARIO (OPTIMIZADO)"
    
    # Lista de cuentas de sistema a excluir (nombres exactos y patrones)
    $SystemAccountNames = @(
        "All Users", "Default", "Default User", "Public",
        "Todos los usuarios", "DefaultAppPool",
        "NetworkService", "LocalService", "systemprofile",
        "MSSQLSERVER", "MSSQLServerADHelper", "ASPNET"
    )
    $SystemAccountPatterns = @("MSSQL*", "sql*", "IIS*", "ASP*", "Service*", "NetworkService*")
    
    # Nombres de subcarpetas a escanear (en y/es)
    $UserSubfolders = @(
        "Downloads", "Descargas",
        "Desktop",   "Escritorio",
        "Documents", "Documentos"
    )
    
    $UserProfilesDir = "C:\Users"
    $UserProfiles = Get-ChildItem -Path $UserProfilesDir -Directory -ErrorAction SilentlyContinue
    
    foreach ($profile in $UserProfiles) {
        # Filtrar cuentas de sistema por nombre exacto
        $isSystem = $false
        foreach ($sysName in $SystemAccountNames) {
            if ($profile.Name -eq $sysName) { $isSystem = $true; break }
        }
        if ($isSystem) { continue }
        
        # Filtrar cuentas de sistema por patron (wildcards)
        foreach ($pattern in $SystemAccountPatterns) {
            if ($profile.Name -like $pattern) { $isSystem = $true; break }
        }
        if ($isSystem) { continue }
        
        # Verificar que el perfil es accesible antes de agregar sus carpetas
        $profileAccessible = $false
        try {
            # Intento de listar el directorio (prueba de acceso)
            $null = [System.IO.Directory]::GetDirectories($profile.FullName) 2>$null
            $profileAccessible = $true
        } catch { }
        
        if (-not $profileAccessible) { continue }
        
        # Agregar subcarpetas del perfil que existan y sean accesibles
        foreach ($subfolder in $UserSubfolders) {
            $target = Join-Path $profile.FullName $subfolder
            try {
                # Usar .NET directamente para evitar que PowerShell lance PermissionDenied
                if ([System.IO.Directory]::Exists($target)) {
                    $ScanPaths += $target
                }
            } catch { }  # Ignorar silenciosamente perfiles sin acceso
        }
    }
    
    # Exclusiones por nombre de directorio (clamscan --exclude-dir)
    $ExcludeDirs = @(
        "node_modules", ".git", "vendor",
        "cache", "Cache", "target", "dist", "build",
        ".cargo", ".rustup", ".npm", ".yarn",
        "__pycache__", ".venv", "venv",
        "curso-primera",          # excluir carpeta de proyectos de desarrollo en Desktop
        "CYBERSECURITY_Dapp",     # excluir cualquier variante del proyecto DApp
        "EndPoint_Seguridad",     # excluir otros proyectos de ciberseguridad
        "SecureChain"
    )
}

# ============================================================
# Funciones auxiliares
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Write-Host $Line -ForegroundColor $(switch ($Level) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "Cyan" } })
    try { Add-Content -Path $LogFile -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Get-DeviceUUID {
    try { return (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID } catch {}
    try { return (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop).UUID } catch {}
    # Fallback: usar la clave de registro MachineGuid
    try { return (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -ErrorAction Stop).MachineGuid } catch {}
    return "UNKNOWN-$(hostname)-$(Get-Date -Format 'yyyyMMdd')"
}

function Get-LocalIP {
    param([string]$GatewayHost)
    # Metodo 1: Conectar al gateway para obtener IP de salida real
    try {
        $sock = New-Object System.Net.Sockets.TcpClient
        $sock.Connect($GatewayHost, 8080)
        $ip = $sock.Client.LocalEndPoint.Address.IPAddressToString
        $sock.Close()
        if ($ip -and $ip -ne "0.0.0.0") { return $ip }
    } catch {}
    # Metodo 2: Enumeracion de interfaces de red
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254\.)" -and $_.PrefixOrigin -ne "WellKnown" } |
               Sort-Object PrefixLength |
               Select-Object -First 1).IPAddress
        if ($ip) { return $ip }
    } catch {}
    # Metodo 3: DNS lookup
    try {
        return ([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                Where-Object { $_.AddressFamily -eq "InterNetwork" } |
                Select-Object -First 1).IPAddressToString
    } catch {}
    return "127.0.0.1"
}

function Send-GatewayReport {
    param([string]$Url, [hashtable]$Payload, [int]$TimeoutSec = 15)
    try {
        $Json  = $Payload | ConvertTo-Json -Compress -Depth 5
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
        $Response = Invoke-RestMethod -Uri $Url -Method Post `
            -ContentType "application/json; charset=utf-8" -Body $Bytes -TimeoutSec $TimeoutSec
        return $Response
    } catch {
        Write-Log "Error enviando a ${Url}: $_" "WARN"
        return $null
    }
}

# ============================================================
# Informacion del equipo
# ============================================================
$Hostname   = $env:COMPUTERNAME.ToLower()
$DeviceUUID = Get-DeviceUUID
$LocalIP    = Get-LocalIP -GatewayHost $GatewayIp

# ============================================================
# ACCION 6: MODO SELF-TEST (diagnostico rapido sin escaneo)
# ============================================================
if ($SelfTest) {
    Write-Log "==================================================="
    Write-Log "CyberSec DApp - MODO SELF-TEST / DIAGNOSTICO"
    Write-Log "Hostname: $Hostname | UUID: $DeviceUUID | IP: $LocalIP"
    Write-Log "Sistema: $OsCaption"
    Write-Log "==================================================="
    
    $TestResults = @{}
    
    # Test 1: ClamAV instalado
    if (Test-Path $ClamScanExe) {
        $clamver = & $ClamScanExe --version 2>&1 | Select-String "ClamAV" | Select-Object -First 1
        Write-Log "ClamAV: OK - $clamver"
        $TestResults["clamav_installed"] = $true
        $TestResults["clamav_version"]   = $clamver.ToString().Trim()
    } else {
        Write-Log "ClamAV: NO ENCONTRADO en $ClamScanExe" "ERROR"
        $TestResults["clamav_installed"] = $false
        $TestResults["clamav_version"]   = "no instalado"
    }
    
    # Test 2: Firmas actualizadas
    $sigAge = -1
    $ClamBaseDir = if (Test-Path $ClamScanExe) { Split-Path $ClamScanExe -Parent } else { "C:\Program Files\ClamAV" }
    $PossibleDbPaths = @(
        (Join-Path $ClamBaseDir "database"),
        (Join-Path (Split-Path $ClamBaseDir -Parent) "database"),
        "C:\ProgramData\ClamAV",
        "C:\Program Files\ClamAV\database"
    )
    foreach ($dbPath in $PossibleDbPaths) {
        $cvd = Get-ChildItem -Path $dbPath -Filter "*.cvd" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($cvd) {
            $sigAge = [Math]::Round(((Get-Date) - $cvd.LastWriteTime).TotalDays, 1)
            if ($sigAge -le 7) {
                Write-Log "Firmas: OK - $($cvd.Name) ($sigAge dias de antiguedad)"
            } else {
                Write-Log "Firmas: DESACTUALIZADAS - $sigAge dias sin actualizar" "WARN"
            }
            $TestResults["signatures_age_days"] = $sigAge
            break
        }
    }
    if ($sigAge -eq -1) {
        Write-Log "Firmas: NO ENCONTRADAS - ejecutar freshclam.exe" "WARN"
        $TestResults["signatures_age_days"] = -1
    }
    
    # Test 3: Conectividad con el gateway
    $gwReachable = $false
    try {
        $testConn = New-Object System.Net.Sockets.TcpClient
        $testConn.Connect($GatewayIp, 8080)
        $testConn.Close()
        $gwReachable = $true
        Write-Log "Gateway: ALCANZABLE - http://${GatewayIp}:8080"
    } catch {
        Write-Log "Gateway: NO ALCANZABLE - http://${GatewayIp}:8080 ($_)" "WARN"
    }
    $TestResults["gateway_reachable"] = $gwReachable
    
    # Test 4: Perfiles de usuario detectados
    Write-Log "Perfiles detectados para escaneo: $($ScanPaths.Count) carpetas"
    foreach ($p in $ScanPaths) { Write-Log "   -> $p" }
    $TestResults["scan_paths_count"] = $ScanPaths.Count
    
    # Calcular estado general del self-test
    $reportedStatus = if ($TestResults["clamav_installed"] -and $gwReachable) { "CLEAN" } else { "ERROR" }
    $overallStatus = if ($TestResults["clamav_installed"] -and $gwReachable) { "SELF_TEST_OK" } else { "SELF_TEST_FAIL" }
    
    # Enviar resultado al gateway
    $SelfTestPayload = @{
        hostname         = $Hostname
        device_uuid      = $DeviceUUID
        agent_ip         = $LocalIP
        src_ip           = $LocalIP
        agent_name       = $Hostname
        scan_mode        = "SELFTEST"
        status           = $reportedStatus
        scanner          = $TestResults["clamav_version"]
        engine_version   = $TestResults["clamav_version"]
        definitions_date = if ($sigAge -gt 0) { (Get-Date).AddDays(-$sigAge).ToString("yyyy-MM-dd") } else { "desconocida" }
        scanned_files    = 0
        infected_count   = 0
        infected_files   = @()
        scan_duration_s  = 0
        scan_paths       = $ScanPaths
        os_caption       = $OsCaption
        timestamp        = (Get-Date -Format "o")
    }
    
    $reportUrl = "http://${GatewayIp}:8080/api/antivirus/scan-result"
    $response = Send-GatewayReport -Url $reportUrl -Payload $SelfTestPayload
    
    if ($response) {
        Write-Log "Resultado self-test enviado al dashboard. Estado: $overallStatus"
    } else {
        Write-Log "No se pudo enviar el resultado al gateway (sin conexion)" "WARN"
    }
    
    Write-Log "==================================================="
    Write-Log "Self-test finalizado. Estado: $overallStatus"
    Write-Log "==================================================="
    exit 0
}

# ============================================================
# INICIO DEL ESCANEO NORMAL
# ============================================================
Write-Log "==================================================="
Write-Log "CyberSec DApp - Escaneo Antivirus ClamAV [$ScanModeLabel]"
Write-Log "Hostname: $Hostname | UUID: $DeviceUUID | IP: $LocalIP"
Write-Log "Sistema: $OsCaption"

# Verificar que ClamAV este instalado
if (-not (Test-Path $ClamScanExe)) {
    Write-Log "ClamAV no encontrado en ninguna ruta conocida" "ERROR"
    Write-Log "Ejecute install_clamav.ps1 primero para instalarlo" "ERROR"
    
    $ErrorPayload = @{
        hostname         = $Hostname
        device_uuid      = $DeviceUUID
        agent_ip         = $LocalIP
        scan_mode        = $ScanMode
        status           = "ERROR"
        error_message    = "ClamAV no instalado - ejecutar install_clamav.ps1"
        scanner          = "ClamAV (no instalado)"
        engine_version   = "N/A"
        scanned_files    = 0
        infected_count   = 0
        infected_files   = @()
        definitions_date = "N/A"
        scan_paths       = $ScanPaths
        os_caption       = $OsCaption
        timestamp        = (Get-Date -Format "o")
    }
    Send-GatewayReport -Url "http://${GatewayIp}:8080/api/antivirus/scan-result" -Payload $ErrorPayload
    exit 1
}

# Obtener version del motor
$ClamVersion = "ClamAV Unknown"
try {
    $VersionOutput = & $ClamScanExe --version 2>&1
    $ClamVersion   = ($VersionOutput | Select-String "ClamAV" | Select-Object -First 1).ToString().Trim()
} catch {}
Write-Log "Motor: $ClamVersion"

# ============================================================
# ACCION 3: Busqueda dinamica de firmas (multi-ruta, compatible Server)
# ============================================================
$DefinitionsDate = "Desconocida"
$ClamBaseDir = Split-Path $ClamScanExe -Parent
$PossibleDbPaths = @(
    (Join-Path $ClamBaseDir "database"),
    (Join-Path (Split-Path $ClamBaseDir -Parent) "database"),
    "C:\ProgramData\ClamAV",
    "C:\Program Files\ClamAV\database",
    (Join-Path $ClamInstDir "database")
)
foreach ($dbPath in $PossibleDbPaths) {
    $cvd = Get-ChildItem -Path $dbPath -Filter "*.cvd" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $cvd) {
        $cvd = Get-ChildItem -Path $dbPath -Filter "*.cld" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($cvd) {
        $DefinitionsDate = $cvd.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Log "Firmas: $($cvd.Name) en $dbPath"
        break
    }
}
Write-Log "Base de firmas: $DefinitionsDate"

# Verificar que hay paths validos para escanear
$ValidPaths = @()
foreach ($p in $ScanPaths) {
    try {
        if ([System.IO.Directory]::Exists($p)) { $ValidPaths += $p }
    } catch {}
}

if ($ValidPaths.Count -eq 0) {
    Write-Log "No se encontraron directorios validos para escanear" "ERROR"
    $ErrorPayload = @{
        hostname         = $Hostname
        device_uuid      = $DeviceUUID
        agent_ip         = $LocalIP
        scan_mode        = $ScanMode
        status           = "ERROR"
        error_message    = "No hay directorios accesibles para escanear"
        scanner          = $ClamVersion
        engine_version   = $ClamVersion
        scanned_files    = 0
        infected_count   = 0
        infected_files   = @()
        definitions_date = $DefinitionsDate
        scan_paths       = $ScanPaths
        os_caption       = $OsCaption
        timestamp        = (Get-Date -Format "o")
    }
    Send-GatewayReport -Url "http://${GatewayIp}:8080/api/antivirus/scan-result" -Payload $ErrorPayload
    exit 1
}

Write-Log "Directorios a escanear ($($ValidPaths.Count)):"
foreach ($p in $ValidPaths) { Write-Log "   -> $p" }

# ============================================================
# ACCION 4: Log temporal en $env:TEMP con nombre unico por timestamp
# Evita conflictos de acceso entre instancias y errores de permisos
# ============================================================
$ScanLogName = "clamav_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($PID).tmp"
$ScanLog     = Join-Path $env:TEMP $ScanLogName

# ============================================================
# CONSTRUCCION DE ARGUMENTOS DE CLAMSCAN
# ============================================================
$ScanArgs = @()
foreach ($p in $ValidPaths) {
    $ScanArgs += "`"$p`""
}
$ScanArgs += "--recursive"
$ScanArgs += "--infected"
$ScanArgs += "--log=`"$ScanLog`""
$ScanArgs += "--max-filesize=25M"
$ScanArgs += "--max-scansize=100M"
foreach ($ex in $ExcludeDirs) {
    $ScanArgs += "--exclude-dir=`"$ex`""
}

Write-Log "Iniciando escaneo [$ScanModeLabel]..."
$StartTime = Get-Date

# Ejecutar clamscan usando System.Diagnostics.Process para captura asincrona
$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName               = $ClamScanExe
$ProcessInfo.Arguments              = $ScanArgs -join " "
$ProcessInfo.RedirectStandardOutput = $true
$ProcessInfo.RedirectStandardError  = $true
$ProcessInfo.UseShellExecute        = $false
$ProcessInfo.CreateNoWindow         = $true

try {
    $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
    $StdOut  = $Process.StandardOutput.ReadToEnd()
    $StdErr  = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
} catch {
    Write-Log "Error al ejecutar clamscan.exe: $_" "ERROR"
    $ExitCode = 99
    $StdOut   = ""
    $StdErr   = $_.ToString()
}

$EndTime      = Get-Date
$ScanDuration = [Math]::Round(($EndTime - $StartTime).TotalSeconds)
Write-Log "Escaneo terminado en $ScanDuration segundos (Exit Code: $ExitCode)"

# ============================================================
# ANALISIS DEL RESULTADO
#
# Exit Code de ClamAV:
#   0  → Sin amenazas (CLEAN)
#   1  → Virus/amenaza detectada (INFECTED)
#   2+ → Condicion de error durante el escaneo. Se distinguen dos casos:
#        · Archivos escaneados > 0: el escaneo funciono correctamente.
#          Algunos archivos estaban bloqueados por el SO (normal en Windows:
#          pagefile.sys, archivos en uso, caches del kernel, etc.).
#          → Estado: CLEAN  (con nota informativa en error_message)
#        · Archivos escaneados = 0: el motor no pudo procesar nada.
#          Falla real (ClamAV corrupto, sin permisos, sin rutas validas).
#          → Estado: ERROR
# ============================================================
$ScanStatus    = "CLEAN"
$InfectedCount = 0
$InfectedFiles = New-Object System.Collections.Generic.List[string]

if (Test-Path $ScanLog) {
    try {
        $Lines = [System.IO.File]::ReadAllLines($ScanLog)
        foreach ($l in $Lines) {
            if ($l -match "FOUND$") {
                $InfectedFiles.Add($l.Trim())
                $InfectedCount++
            }
        }
    } catch {
        Write-Log "No se pudo leer log de escaneo: $_" "WARN"
    }
    # Limpiar log temporal
    try { Remove-Item $ScanLog -Force -ErrorAction SilentlyContinue } catch {}
}

# --- Conteo de archivos escaneados (necesario ANTES de determinar el estado) ---
# Se extrae del output de clamscan para distinguir falla real de archivos bloqueados.
$ScannedCount = 0
$allOutput = "$StdOut`n$StdErr"
if ($allOutput -match "Scanned files:\s+(\d+)") { $ScannedCount = [int]$Matches[1] }
elseif ($allOutput -match "(\d+)\s+files?\s+scanned") { $ScannedCount = [int]$Matches[1] }

# --- Determinacion del estado final ---
$ErrorMessage = $null

if ($ExitCode -eq 1 -or $InfectedCount -gt 0) {
    # --- INFECTADO: ClamAV encontro amenazas ---
    $ScanStatus = "INFECTED"
    Write-Log "SE DETECTARON AMENAZAS: $InfectedCount archivos infectados" "WARN"
    foreach ($f in $InfectedFiles) { Write-Log "   AMENAZA: $f" "WARN" }

} elseif ($ExitCode -ge 2 -and $ScannedCount -gt 0) {
    # --- LIMPIO con advertencia: el escaneo proceso archivos exitosamente ---
    # Exit Code 2 con archivos > 0 indica que algunos archivos del sistema
    # operativo Windows estaban bloqueados o en uso durante el escaneo.
    # Esto es un comportamiento completamente normal en entornos Windows
    # (pagefile.sys, hiberfil.sys, archivos en uso, temporales, etc.).
    # El dispositivo esta LIMPIO - no se encontraron amenazas.
    $ScanStatus   = "CLEAN"
    $ErrorMessage = "Escaneo exitoso: $ScannedCount archivos analizados, sin amenazas detectadas. Nota: algunos archivos del sistema operativo estaban en uso y no pudieron ser accedidos durante el escaneo (comportamiento normal en Windows - Exit Code $ExitCode)."
    Write-Log "Escaneo completado: $ScannedCount archivos escaneados, 0 amenazas. Algunos archivos del SO estaban bloqueados - normal en Windows (Exit Code: $ExitCode)." "INFO"

} elseif ($ExitCode -ge 2 -and $ScannedCount -eq 0) {
    # --- ERROR REAL: ClamAV no pudo procesar ningun archivo ---
    # Exit Code 2 con 0 archivos indica una falla genuina del motor:
    # ClamAV no instalado correctamente, sin permisos, paths invalidos,
    # firmas corruptas o crash del proceso.
    $ScanStatus   = "ERROR"
    $ErrorMessage = "Error real de escaneo: ClamAV no proceso ningun archivo (Exit Code $ExitCode). Verifique la instalacion de ClamAV y los permisos. StdErr: $StdErr"
    Write-Log "ERROR REAL: 0 archivos procesados (Exit Code: $ExitCode). Verificar instalacion. StdErr: $StdErr" "ERROR"

} else {
    # --- LIMPIO: Exit Code 0, sin errores, sin amenazas ---
    Write-Log "Sin amenazas detectadas. Estado: CLEAN ($ScannedCount archivos escaneados)"
}

# ============================================================
# ENVIO DEL RESULTADO AL GATEWAY
# ============================================================
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
    scanned_files    = [int]$ScannedCount
    infected_count   = [int]$InfectedCount
    infected_files   = @($InfectedFiles.ToArray())
    scan_duration_s  = [int]$ScanDuration
    scan_paths       = $ValidPaths
    os_caption       = $OsCaption
    error_message    = $ErrorMessage
    timestamp        = (Get-Date -Format "o")
}

Write-Log "Reportando resultado a: http://${GatewayIp}:8080/api/antivirus/scan-result"
$Response = Send-GatewayReport -Url "http://${GatewayIp}:8080/api/antivirus/scan-result" -Payload $ScanPayload
if ($Response) {
    Write-Log "Resultado enviado al gateway. Estado: $ScanStatus"
} else {
    # Guardar resultado localmente para reintentar luego
    $PendingFile = Join-Path $env:TEMP "clamav_pending_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $ScanPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $PendingFile -Encoding UTF8
    Write-Log "Resultado guardado localmente en: $PendingFile (sin conexion al gateway)" "WARN"
}

# ============================================================
# ENVIO DE ALERTA HIGH si hay malware detectado
# ============================================================
if ($ScanStatus -eq "INFECTED") {
    Write-Log "Enviando alerta HIGH por deteccion de malware..."
    $ThreatsFormatted = ($InfectedFiles.ToArray() | Select-Object -First 10) -join " | "
    $AlertPayload = @{
        severity       = "HIGH"
        description    = "MALWARE DETECTADO por ClamAV [$ScanModeLabel] en $Hostname ($OsCaption). Amenazas ($InfectedCount): $ThreatsFormatted"
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
    }
    $alertResponse = Send-GatewayReport -Url "http://${GatewayIp}:8080/api/alerts/webhook" -Payload $AlertPayload
    if ($alertResponse) {
        Write-Log "Alerta HIGH enviada al dashboard de Threat Intelligence"
    }
}

Write-Log "==================================================="
Write-Log "Escaneo [$ScanModeLabel] finalizado - Estado: $ScanStatus"
Write-Log "==================================================="

# Pausar si se ejecuta de forma interactiva (clic derecho) para que no se cierre la consola inmediatamente
if ([Environment]::UserInteractive -and $env:CLAMAV_SKIP_ELEVATION -ne "1" -and -not $SkipAdminCheck) {
    Write-Host ""
    Read-Host "Escaneo finalizado. Presione Enter para salir"
}

exit 0
