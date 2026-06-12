# sync_contracts.ps1
# Lee deployments/localhost.json y sincroniza las addresses en ambos .env
# Uso: powershell -ExecutionPolicy Bypass -File sync_contracts.ps1

param(
    [string]$ProjectDir = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$deployJson    = Join-Path $ProjectDir "deployments\localhost.json"
$rootEnv       = Join-Path $ProjectDir ".env"
$gatewayEnv    = Join-Path $ProjectDir "rust-gateway\.env"

# ── Leer deploy manifest ──────────────────────────────────────────
if (-not (Test-Path $deployJson)) {
    Write-Host "[ERROR] No se encontro deployments\localhost.json" -ForegroundColor Red
    exit 1
}

$deploy = Get-Content $deployJson | ConvertFrom-Json
$secAudit  = $deploy.contracts.SecurityAudit
$alertReg  = $deploy.contracts.AlertRegistry

if (-not $secAudit -or -not $alertReg) {
    Write-Host "[ERROR] El JSON de deploy no contiene las addresses esperadas." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Addresses extraidas del deploy:" -ForegroundColor Cyan
Write-Host "    SecurityAudit  = $secAudit" -ForegroundColor Green
Write-Host "    AlertRegistry  = $alertReg" -ForegroundColor Green
Write-Host ""

# ── Funcion de actualizacion de .env ─────────────────────────────
function Update-EnvFile {
    param([string]$Path, [string]$SA, [string]$AR)

    if (-not (Test-Path $Path)) {
        Write-Host "  [AVISO] No se encontro: $Path" -ForegroundColor Yellow
        return
    }

    $content = Get-Content $Path -Raw

    # Reemplazar o agregar cada variable
    $vars = @{
        "CONTRACT_SECURITY_AUDIT"      = $SA
        "CONTRACT_ALERT_REGISTRY"      = $AR
        "VITE_CONTRACT_SECURITY_AUDIT" = $SA
        "VITE_CONTRACT_ALERT_REGISTRY" = $AR
    }

    # Sincronizar tambien ABUSECH_AUTH_KEY si esta definida en root .env
    $rootContent = Get-Content $rootEnv -Raw -ErrorAction SilentlyContinue
    if ($rootContent -match "(?m)^ABUSECH_AUTH_KEY=(.+)") {
        $abusechKey = $Matches[1].Trim()
        if ($abusechKey -and $abusechKey -ne "your_abusech_key_here") {
            $vars["ABUSECH_AUTH_KEY"] = $abusechKey
        }
    }

    foreach ($key in $vars.Keys) {
        $val = $vars[$key]
        if ($content -match "(?m)^$key=") {
            $content = $content -replace "(?m)^$key=.*", "$key=$val"
        } else {
            $content += "`n$key=$val"
        }
    }

    # Escribir sin BOM para compatibilidad con Rust/dotenvy
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  [OK] Actualizado: $Path" -ForegroundColor Green
}

# ── Actualizar root .env ──────────────────────────────────────────
Write-Host "  Sincronizando root .env ..."
Update-EnvFile -Path $rootEnv -SA $secAudit -AR $alertReg

# ── Actualizar gateway .env ───────────────────────────────────────
Write-Host "  Sincronizando rust-gateway .env ..."
Update-EnvFile -Path $gatewayEnv -SA $secAudit -AR $alertReg

Write-Host ""
Write-Host "  [OK] Sincronizacion completa. Ambos .env contienen:" -ForegroundColor Green
Write-Host "    CONTRACT_SECURITY_AUDIT = $secAudit"
Write-Host "    CONTRACT_ALERT_REGISTRY = $alertReg"
Write-Host ""

# ── Devolver las addresses como variables de entorno ──────────────
# (para que el bat pueda leerlas via %ERRORLEVEL% no aplica,
#  pero el bat ya las tiene via el JSON — este script solo sincroniza)
exit 0
