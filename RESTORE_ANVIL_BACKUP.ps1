# ============================================================
#  RESTORE_ANVIL_BACKUP.ps1  v1.0
#  Restauracion interactiva de backups de .anvil_state.json
#
#  Muestra el historial del manifest, el usuario elige,
#  hace un pre-backup del estado actual antes de restaurar.
# ============================================================

param(
    [string]$ProjectDir   = $PSScriptRoot,
    [string]$BackupSubDir = "backups\anvil"
)

$ErrorActionPreference = "Continue"

$stateFile    = Join-Path $ProjectDir ".anvil_state.json"
$backupFolder = Join-Path $ProjectDir $BackupSubDir
$manifestFile = Join-Path $backupFolder "manifest.json"

Clear-Host
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Magenta
Write-Host "  |   RESTORE_ANVIL_BACKUP.ps1 v1.0                           |" -ForegroundColor Magenta
Write-Host "  |   Restauracion de .anvil_state.json desde backup           |" -ForegroundColor Magenta
Write-Host "  +============================================================+" -ForegroundColor Magenta
Write-Host ""

# ── Verificar manifest ───────────────────────────────────────
if (-not (Test-Path $manifestFile)) {
    Write-Host "  [ERROR] No se encontro manifest.json en:" -ForegroundColor Red
    Write-Host "          $backupFolder" -ForegroundColor Gray
    Write-Host "  Ejecuta BACKUP_ANVIL.ps1 al menos una vez primero." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

$manifest = Get-Content $manifestFile -Raw | ConvertFrom-Json

if (-not $manifest.backups -or $manifest.backups.Count -eq 0) {
    Write-Host "  [INFO] No hay backups disponibles en el manifest." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 0
}

# ── Listar backups disponibles ───────────────────────────────
Write-Host "  Backups disponibles:" -ForegroundColor Cyan
Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ("  {0,3}  {1,-22} {2,7}  {3,-12}  {4}" -f "#", "Fecha/Hora", "Tamano", "Bloque", "Trigger") -ForegroundColor DarkCyan
Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

$validBackups = [System.Collections.ArrayList]@()
$i = 1
foreach ($b in $manifest.backups) {
    $bPath = Join-Path $backupFolder $b.filename
    if (Test-Path $bPath) {
        $blk = if ($b.blocks -eq "N/A") { "bloque:N/A  " } else { "bloque:#$($b.blocks)".PadRight(12) }
        $sz  = "$($b.size_kb) KB".PadLeft(7)
        $trg = $b.trigger
        Write-Host ("  [{0,2}]  {1,-22} {2}  {3}  {4}" -f $i, $b.date_local, $sz, $blk, $trg) -ForegroundColor White
        [void]$validBackups.Add($b)
        $i++
    } else {
        Write-Host ("  [ - ]  {0,-22}  (archivo no encontrado)" -f $b.date_local) -ForegroundColor DarkGray
    }
}

Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

if ($validBackups.Count -eq 0) {
    Write-Host "  [WARN] Ningun archivo de backup fisico encontrado." -ForegroundColor Yellow
    pause
    exit 1
}

# ── Estado actual ────────────────────────────────────────────
if (Test-Path $stateFile) {
    $currentSize = [Math]::Round((Get-Item $stateFile).Length / 1024, 1)
    Write-Host "  Estado actual: .anvil_state.json ($currentSize KB)" -ForegroundColor Green
} else {
    Write-Host "  Estado actual: .anvil_state.json NO existe" -ForegroundColor Yellow
}
Write-Host ""

# ── Seleccion del usuario ────────────────────────────────────
Write-Host "  Ingresa el numero del backup a restaurar (o 0 para cancelar):" -ForegroundColor Cyan
$selection = Read-Host "  Seleccion"

if ($selection -eq "0" -or $selection -eq "") {
    Write-Host ""
    Write-Host "  Operacion cancelada." -ForegroundColor Gray
    Write-Host ""
    exit 0
}

$selInt = 0
if (-not [int]::TryParse($selection, [ref]$selInt) -or $selInt -lt 1 -or $selInt -gt $validBackups.Count) {
    Write-Host "  [ERROR] Seleccion invalida: '$selection'" -ForegroundColor Red
    pause
    exit 1
}

$chosen     = $validBackups[$selInt - 1]
$chosenPath = Join-Path $backupFolder $chosen.filename

Write-Host ""
Write-Host "  Backup seleccionado:" -ForegroundColor Cyan
Write-Host "    Archivo : $($chosen.filename)" -ForegroundColor White
Write-Host "    Fecha   : $($chosen.date_local)" -ForegroundColor White
Write-Host "    Tamano  : $($chosen.size_kb) KB" -ForegroundColor White
Write-Host "    Bloque  : #$($chosen.blocks)" -ForegroundColor White
Write-Host "    SHA-256 : $($chosen.hash_sha256)" -ForegroundColor DarkGray
Write-Host ""

# ── Verificar hash de integridad ─────────────────────────────
Write-Host "  Verificando integridad del backup..." -ForegroundColor Gray
$currentHash = (Get-FileHash $chosenPath -Algorithm SHA256).Hash
if ($currentHash -ne $chosen.hash_sha256) {
    Write-Host "  [WARN] El hash SHA-256 NO coincide con el registrado en manifest." -ForegroundColor Yellow
    Write-Host "         Archivo puede estar modificado o corrupto." -ForegroundColor Yellow
    Write-Host ""
    $continueAnyway = Read-Host "  Continuar de todas formas? (S/N)"
    if ($continueAnyway -ne "S" -and $continueAnyway -ne "s") {
        Write-Host "  Operacion cancelada." -ForegroundColor Gray
        exit 1
    }
} else {
    Write-Host "  [OK] Integridad verificada. Hash SHA-256 coincide." -ForegroundColor Green
}

# ── Confirmacion final ───────────────────────────────────────
Write-Host ""
Write-Host "  ATENCION: Esta accion reemplazara el .anvil_state.json actual." -ForegroundColor Yellow
Write-Host "  Se hara un pre-backup del estado actual antes de restaurar." -ForegroundColor Cyan
Write-Host ""
$confirm = Read-Host "  Confirmar restauracion? (S/N)"
if ($confirm -ne "S" -and $confirm -ne "s") {
    Write-Host ""
    Write-Host "  Operacion cancelada." -ForegroundColor Gray
    exit 0
}

# ── Pre-backup del estado actual ─────────────────────────────
if (Test-Path $stateFile) {
    Write-Host ""
    Write-Host "  Realizando pre-backup del estado actual..." -ForegroundColor Gray
    & (Join-Path $ProjectDir "BACKUP_ANVIL.ps1") -Trigger "pre-restore" -Quiet
    Write-Host "  [OK] Estado actual respaldado antes de restaurar." -ForegroundColor Green
}

# ── Restaurar ────────────────────────────────────────────────
Copy-Item $chosenPath $stateFile -Force
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   RESTAURACION COMPLETADA                                  |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  Restaurado : $($chosen.filename)" -ForegroundColor White
Write-Host "  Fecha      : $($chosen.date_local)" -ForegroundColor White
Write-Host "  Bloque     : #$($chosen.blocks)" -ForegroundColor White
Write-Host ""
Write-Host "  Proximos pasos:" -ForegroundColor Cyan
Write-Host "   1. Iniciar el stack: START_CYBERSEC.bat" -ForegroundColor White
Write-Host "   2. El sistema detectara el estado restaurado automaticamente." -ForegroundColor White
Write-Host "   3. Los SBT del bloque #$($chosen.blocks) estaran disponibles." -ForegroundColor White
Write-Host ""
pause
