# test_status_logic.ps1 - Tests de logica de estado para scan_and_report.ps1
# CyberSec Antivirus Agent - Fix 2026-07-03
# Encoding: ASCII puro - sin caracteres especiales

param()

$passed = 0
$failed = 0

function Invoke-StatusLogic {
    param(
        [int]   $ExitCode,
        [int]   $ScannedCount,
        [int]   $InfectedCount = 0,
        [string]$StdErr = ""
    )
    # Replica exacta del bloque modificado en scan_and_report.ps1
    $ScanStatus   = "CLEAN"
    $ErrorMessage = $null

    if ($ExitCode -eq 1 -or $InfectedCount -gt 0) {
        $ScanStatus = "INFECTED"

    } elseif ($ExitCode -ge 2 -and $ScannedCount -gt 0) {
        $ScanStatus   = "CLEAN"
        $ErrorMessage = "Escaneo exitoso: $ScannedCount archivos analizados, sin amenazas. " +
                        "Nota: algunos archivos estaban en uso (normal en Windows - Exit Code $ExitCode)."

    } elseif ($ExitCode -ge 2 -and $ScannedCount -eq 0) {
        $ScanStatus   = "ERROR"
        $ErrorMessage = "Error real: ClamAV no proceso ningun archivo (Exit Code $ExitCode). StdErr: $StdErr"

    } else {
        $ScanStatus = "CLEAN"
    }

    return [PSCustomObject]@{
        Status       = $ScanStatus
        ErrorMessage = $ErrorMessage
    }
}

function Test-Equal {
    param([string]$Name, [string]$Expected, [string]$Actual)
    if ($Expected -eq $Actual) {
        Write-Host ("  [PASS] " + $Name) -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red
        Write-Host ("         Esperado : " + $Expected) -ForegroundColor Yellow
        Write-Host ("         Obtenido : " + $Actual)   -ForegroundColor Red
        $script:failed++
    }
}

function Test-Contains {
    param([string]$Name, [string]$Sub, [string]$Actual)
    if ($null -ne $Actual -and $Actual.Contains($Sub)) {
        Write-Host ("  [PASS] " + $Name) -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red
        Write-Host ("         Debe contener: " + $Sub) -ForegroundColor Yellow
        Write-Host ("         Obtenido     : " + $Actual) -ForegroundColor Red
        $script:failed++
    }
}

function Test-Null {
    param([string]$Name, [object]$Actual)
    if ($null -eq $Actual) {
        Write-Host ("  [PASS] " + $Name) -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red
        Write-Host ("         Esperado null, obtenido: " + $Actual) -ForegroundColor Red
        $script:failed++
    }
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  test_status_logic.ps1 - CyberSec Antivirus Agent    " -ForegroundColor Cyan
Write-Host "  Validacion logica de estados - Fix 2026-07-03        " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# --- GRUPO 1: ExitCode 0 (escaneo perfecto) ---
Write-Host "GRUPO 1 - ExitCode 0 (escaneo perfecto, sin excepciones)" -ForegroundColor White
$r = Invoke-StatusLogic -ExitCode 0 -ScannedCount 5000
Test-Equal  "ExitCode=0, 5000 archivos -> CLEAN"          "CLEAN" $r.Status
Test-Null   "ExitCode=0 -> error_message es null"                  $r.ErrorMessage

$r = Invoke-StatusLogic -ExitCode 0 -ScannedCount 0
Test-Equal  "ExitCode=0, 0 archivos -> CLEAN"             "CLEAN" $r.Status
Write-Host ""

# --- GRUPO 2: ExitCode 1 (virus detectado) ---
Write-Host "GRUPO 2 - ExitCode 1 (virus detectado)" -ForegroundColor White
$r = Invoke-StatusLogic -ExitCode 1 -ScannedCount 453 -InfectedCount 2
Test-Equal  "ExitCode=1, 453 archivos, 2 infectados -> INFECTED"   "INFECTED" $r.Status

$r = Invoke-StatusLogic -ExitCode 0 -ScannedCount 1000 -InfectedCount 3
Test-Equal  "ExitCode=0 pero InfectedCount=3 -> INFECTED"          "INFECTED" $r.Status

$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 200 -InfectedCount 1
Test-Equal  "ExitCode=2 pero InfectedCount=1 -> INFECTED"          "INFECTED" $r.Status
Write-Host ""

# --- GRUPO 3: CASO CORREGIDO - ExitCode 2+ con archivos > 0 ---
Write-Host "GRUPO 3 - ExitCode 2 con archivos>0 (BUG FIX: antes daba ERROR)" -ForegroundColor White
$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 5598
Test-Equal   "ExitCode=2, 5598 archivos -> CLEAN (no ERROR)"   "CLEAN" $r.Status
Test-Contains "error_message contiene 'exitoso'"                "exitoso" $r.ErrorMessage
Test-Contains "error_message menciona Exit Code 2"              "Exit Code 2" $r.ErrorMessage

$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 453
Test-Equal   "ExitCode=2, 453 archivos (pc-back248) -> CLEAN"  "CLEAN" $r.Status

$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 1
Test-Equal   "ExitCode=2, 1 solo archivo -> CLEAN"             "CLEAN" $r.Status

$r = Invoke-StatusLogic -ExitCode 3 -ScannedCount 800
Test-Equal   "ExitCode=3, 800 archivos -> CLEAN"               "CLEAN" $r.Status

$r = Invoke-StatusLogic -ExitCode 99 -ScannedCount 1200
Test-Equal   "ExitCode=99 (crash capturado), 1200 archivos -> CLEAN" "CLEAN" $r.Status
Write-Host ""

# --- GRUPO 4: ERROR REAL - ExitCode 2+ con 0 archivos ---
Write-Host "GRUPO 4 - ExitCode 2 con 0 archivos (falla real del motor)" -ForegroundColor White
$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 0 -StdErr "Permission denied"
Test-Equal   "ExitCode=2, 0 archivos -> ERROR (falla real)"    "ERROR" $r.Status
Test-Contains "error_message menciona Exit Code 2"              "Exit Code 2" $r.ErrorMessage
Test-Contains "error_message contiene StdErr"                   "Permission denied" $r.ErrorMessage

$r = Invoke-StatusLogic -ExitCode 99 -ScannedCount 0 -StdErr "Cannot open device"
Test-Equal   "ExitCode=99, 0 archivos -> ERROR"                "ERROR" $r.Status

$r = Invoke-StatusLogic -ExitCode 2 -ScannedCount 0
Test-Equal   "ExitCode=2, 0 archivos, sin stderr -> ERROR"     "ERROR" $r.Status
Write-Host ""

# --- GRUPO 5: Regresion - comportamiento anterior correcto no se rompio ---
Write-Host "GRUPO 5 - Regresion (comportamiento anterior correcto preservado)" -ForegroundColor White
$r = Invoke-StatusLogic -ExitCode 1 -ScannedCount 0 -InfectedCount 1
Test-Equal  "ExitCode=1, 0 archivos, 1 infectado -> INFECTED"  "INFECTED" $r.Status

$r = Invoke-StatusLogic -ExitCode 0 -ScannedCount 10000
Test-Equal  "ExitCode=0, 10000 archivos -> CLEAN"              "CLEAN" $r.Status
Test-Null   "ExitCode=0 exitoso -> sin error_message"                   $r.ErrorMessage
Write-Host ""

# --- RESUMEN ---
$total = $passed + $failed
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  RESULTADO FINAL" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ("  Total  : " + $total + " tests") -ForegroundColor White

if ($failed -eq 0) {
    Write-Host ("  Pasados: " + $passed + " / " + $total) -ForegroundColor Green
    Write-Host ""
    Write-Host "  [ALL PASS] Logica de estados correcta." -ForegroundColor Green
    Write-Host "             Listo para compilar el MSI." -ForegroundColor Green
} else {
    Write-Host ("  Pasados : " + $passed + " / " + $total) -ForegroundColor Yellow
    Write-Host ("  Fallados: " + $failed + " / " + $total) -ForegroundColor Red
    Write-Host ""
    Write-Host "  [FAIL] Hay tests fallando. NO compilar el MSI." -ForegroundColor Red
}
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

exit $failed
