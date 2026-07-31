# ============================================================
#  BACKUP_ANVIL.ps1  v1.0
#  Sistema de backup inteligente para .anvil_state.json
#
#  Caracteristicas:
#   - Validacion JSON + tamano antes de copiar
#   - Captura numero de bloque blockchain
#   - Hash SHA-256 de integridad
#   - Rotacion automatica: 7 dias recientes + 4 semanas
#   - Manifest centralizado con historial completo
#   - Puede registrar una Tarea Programada de Windows
#
#  USO:
#   .\BACKUP_ANVIL.ps1                        -> backup manual
#   .\BACKUP_ANVIL.ps1 -Trigger STOP_CYBERSEC -> desde stop script
#   .\BACKUP_ANVIL.ps1 -SetupScheduler        -> registrar tarea diaria
#   .\BACKUP_ANVIL.ps1 -ListBackups           -> mostrar historial
# ============================================================

param(
    [string]$ProjectDir     = $PSScriptRoot,
    [string]$BackupSubDir   = "backups\anvil",
    [int]   $KeepDays       = 7,
    [int]   $KeepWeeks      = 4,
    [string]$Trigger        = "manual",
    [string]$RpcUrl         = "http://127.0.0.1:8545",
    [switch]$SetupScheduler,
    [switch]$ListBackups,
    [switch]$Quiet
)

$ErrorActionPreference = "Continue"

# ── Colores y helpers ────────────────────────────────────────
function Write-Ok    { param($m) Write-Host "  [OK]    $m" -ForegroundColor Green  }
function Write-Info  { param($m) Write-Host "  [INFO]  $m" -ForegroundColor Cyan   }
function Write-Warn  { param($m) Write-Host "  [WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "  [ERROR] $m" -ForegroundColor Red    }

# ── Rutas ───────────────────────────────────────────────────
$stateFile    = Join-Path $ProjectDir ".anvil_state.json"
$backupFolder = Join-Path $ProjectDir $BackupSubDir
$manifestFile = Join-Path $backupFolder "manifest.json"

# ── MODO: Registrar Tarea Programada de Windows ─────────────
if ($SetupScheduler) {
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Magenta
    Write-Host "  |   BACKUP_ANVIL - Registrando Tarea Programada de Windows   |" -ForegroundColor Magenta
    Write-Host "  +============================================================+" -ForegroundColor Magenta
    Write-Host ""

    $taskName    = "CyberSecDApp_BackupAnvil"
    $scriptPath  = Join-Path $ProjectDir "BACKUP_ANVIL.ps1"
    $action      = New-ScheduledTaskAction `
                     -Execute "powershell.exe" `
                     -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$scriptPath`" -Trigger Scheduler" `
                     -WorkingDirectory $ProjectDir

    # Todos los dias a las 23:00
    $trigger     = New-ScheduledTaskTrigger -Daily -At "23:00"
    $settings    = New-ScheduledTaskSettingsSet `
                     -StartWhenAvailable `
                     -RunOnlyIfNetworkAvailable:$false `
                     -WakeToRun:$false

    try {
        # Eliminar si ya existe
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        Register-ScheduledTask `
            -TaskName    $taskName `
            -Action      $action `
            -Trigger     $trigger `
            -Settings    $settings `
            -RunLevel    Highest `
            -Description "Backup automatico diario de .anvil_state.json (CyberSec DApp v0.4.0)" | Out-Null

        Write-Ok  "Tarea '$taskName' registrada en el Programador de Tareas."
        Write-Info "Hora de ejecucion: todos los dias a las 23:00 hs."
        Write-Info "Usa 'StartWhenAvailable': si el PC estaba apagado, corre al encenderse."
        Write-Info "Para eliminar: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
    } catch {
        Write-Err "No se pudo registrar la tarea: $_"
        Write-Warn "Ejecuta este script como Administrador para registrar tareas programadas."
    }
    Write-Host ""
    exit 0
}

# ── MODO: Listar backups ─────────────────────────────────────
if ($ListBackups) {
    if (-not (Test-Path $manifestFile)) {
        Write-Warn "No hay backups registrados en manifest.json"
        exit 0
    }
    $mf = Get-Content $manifestFile -Raw | ConvertFrom-Json
    Write-Host ""
    Write-Host "  Historial de backups (.anvil_state.json)" -ForegroundColor Cyan
    Write-Host "  Ubicacion: $backupFolder" -ForegroundColor Gray
    Write-Host ""
    $i = 1
    foreach ($b in $mf.backups) {
        $blk = if ($b.blocks -eq "N/A") { "bloque:?" } else { "bloque:#$($b.blocks)" }
        $trg = $b.trigger.PadRight(15)
        Write-Host ("  [{0,2}] {1}  {2} KB  {3}  [{4}]" -f $i, $b.timestamp, $b.size_kb, $blk, $trg) -ForegroundColor White
        $i++
    }
    Write-Host ""
    Write-Host "  Total: $($mf.total_backups) backup(s) | Ultimo: $($mf.last_updated)" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# ── MODO PRINCIPAL: Hacer backup ─────────────────────────────
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |   BACKUP_ANVIL.ps1 v1.0 - Backup Inteligente Anvil State   |" -ForegroundColor Cyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  Trigger: $Trigger  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""
}

# PASO 1: Verificar existencia
if (-not (Test-Path $stateFile)) {
    Write-Warn ".anvil_state.json no encontrado en $ProjectDir"
    Write-Info "Nada que respaldar. Ejecuta SETUP_ANVIL_STATE.bat primero."
    exit 0
}

# PASO 2: Validar tamano
$fileInfo = Get-Item $stateFile
$fileSize = $fileInfo.Length
if ($fileSize -lt 50) {
    Write-Err "Archivo demasiado pequeno ($fileSize bytes). Posiblemente vacio o corrupto."
    Write-Warn "NO se realiza backup para proteger backups anteriores validos."
    exit 2
}
Write-Ok "Archivo encontrado: $([Math]::Round($fileSize/1024, 1)) KB"

# PASO 3: Validar integridad JSON
$rawJson = Get-Content $stateFile -Raw -Encoding utf8
try {
    $null = $rawJson | ConvertFrom-Json
    Write-Ok "JSON valido."
} catch {
    Write-Err "El archivo NO es JSON valido: $_"
    Write-Warn "NO se realiza backup para proteger backups anteriores validos."
    exit 2
}

# PASO 4: Intentar obtener numero de bloque del nodo (opcional)
$blockNumber = "N/A"
try {
    $rpcBody = '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
    $resp = Invoke-RestMethod -Uri $RpcUrl -Method POST `
              -Body $rpcBody -ContentType "application/json" -TimeoutSec 3
    $blockNumber = [Convert]::ToInt64($resp.result.TrimStart("0x"), 16)
    Write-Ok "Bloque blockchain actual: #$blockNumber"
} catch {
    Write-Info "Nodo blockchain no disponible (puede estar detenido). Bloque: N/A"
}

# PASO 5: Crear carpeta de backups si no existe
if (-not (Test-Path $backupFolder)) {
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null
    Write-Ok "Carpeta de backups creada: $backupFolder"
}

# PASO 6: Generar nombre con timestamp y copiar
$ts         = Get-Date -Format "yyyy-MM-dd_HH-mm"
$backupName = "anvil_$ts.json"
$backupPath = Join-Path $backupFolder $backupName

Copy-Item $stateFile $backupPath -Force
Write-Ok "Backup creado: $backupName"

# PASO 7: Hash SHA-256 de integridad
$hashValue = (Get-FileHash $backupPath -Algorithm SHA256).Hash
Write-Ok "SHA-256: $hashValue"

# PASO 8: Cargar o crear manifest
$manifest = $null
if (Test-Path $manifestFile) {
    try {
        $manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json
        # Convertir backups a ArrayList para poder manipular
        $bkList = [System.Collections.ArrayList]@()
        foreach ($b in $manifest.backups) { [void]$bkList.Add($b) }
        $manifest | Add-Member -NotePropertyName "backups" -NotePropertyValue $bkList -Force
    } catch {
        Write-Warn "manifest.json corrupto, se recreara."
        $manifest = $null
    }
}
if (-not $manifest) {
    $manifest = [PSCustomObject]@{
        created      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        last_updated = ""
        total_backups = 0
        config       = @{ keep_days = $KeepDays; keep_weeks = $KeepWeeks }
        backups      = [System.Collections.ArrayList]@()
    }
}

# PASO 9: Agregar entrada al manifest
$newEntry = [PSCustomObject]@{
    filename    = $backupName
    timestamp   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    date_local  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    size_bytes  = $fileSize
    size_kb     = [Math]::Round($fileSize / 1024, 1)
    blocks      = $blockNumber
    valid       = $true
    trigger     = $Trigger
    hash_sha256 = $hashValue
}
[void]$manifest.backups.Insert(0, $newEntry)

# PASO 10: ROTACION INTELIGENTE
# - Conservar: 1 backup por dia de los ultimos $KeepDays dias
# - Conservar: 1 backup por semana de las ultimas $KeepWeeks semanas (mas antiguas que $KeepDays dias)
# - Eliminar:  el resto

$now        = Get-Date
$cutoffDay  = $now.AddDays(-$KeepDays)
$cutoffWeek = $now.AddDays(-($KeepDays + $KeepWeeks * 7))

$toKeep     = [System.Collections.ArrayList]@()
$seenDays   = @{}
$seenWeeks  = @{}

foreach ($b in $manifest.backups) {
    $bDate    = [DateTime]::Parse($b.timestamp)
    $dayKey   = $bDate.ToString("yyyy-MM-dd")
    $weekKey  = (Get-Date $bDate -UFormat "%Y-W%V")  # ISO week

    if ($bDate -ge $cutoffDay) {
        # Zona "diaria": guardar 1 por dia
        if (-not $seenDays.ContainsKey($dayKey)) {
            $seenDays[$dayKey] = $true
            [void]$toKeep.Add($b)
        } else {
            # Hay otro del mismo dia, eliminar el archivo fisico
            $fp = Join-Path $backupFolder $b.filename
            if (Test-Path $fp) { Remove-Item $fp -Force }
        }
    } elseif ($bDate -ge $cutoffWeek) {
        # Zona "semanal": guardar 1 por semana
        if (-not $seenWeeks.ContainsKey($weekKey)) {
            $seenWeeks[$weekKey] = $true
            [void]$toKeep.Add($b)
        } else {
            $fp = Join-Path $backupFolder $b.filename
            if (Test-Path $fp) { Remove-Item $fp -Force }
        }
    } else {
        # Fuera de rango: eliminar
        $fp = Join-Path $backupFolder $b.filename
        if (Test-Path $fp) {
            Remove-Item $fp -Force
            Write-Info "Backup expirado eliminado: $($b.filename)"
        }
    }
}

$manifest.backups      = $toKeep
$manifest.last_updated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$manifest.total_backups = $toKeep.Count
$manifest.config       = @{ keep_days = $KeepDays; keep_weeks = $KeepWeeks }

# PASO 11: Guardar manifest actualizado
$manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $manifestFile -Encoding utf8
Write-Ok "manifest.json actualizado ($($manifest.total_backups) backups registrados)."

# PASO 12: Resumen
Write-Host ""
Write-Host "  +---------------------------------------------------------+" -ForegroundColor Green
Write-Host "  |   BACKUP COMPLETADO EXITOSAMENTE                        |" -ForegroundColor Green
Write-Host "  +---------------------------------------------------------+" -ForegroundColor Green
Write-Host "  Archivo : $backupName" -ForegroundColor White
Write-Host "  Tamano  : $([Math]::Round($fileSize/1024, 1)) KB" -ForegroundColor White
Write-Host "  Bloque  : #$blockNumber" -ForegroundColor White
Write-Host "  Backups : $($manifest.total_backups) en $backupFolder" -ForegroundColor White
Write-Host "  Rotacion: ultimos $KeepDays dias + $KeepWeeks semanas" -ForegroundColor Gray
Write-Host ""
