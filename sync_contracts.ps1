# sync_contracts.ps1
# Lee deployments/localhost.json y deployments/localhost_arcat.json
# Sincroniza las addresses en ambos .env (raiz y rust-gateway)
# Uso: powershell -ExecutionPolicy Bypass -File sync_contracts.ps1

param(
    [string]$ProjectDir = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$deployJson      = Join-Path $ProjectDir "deployments\localhost.json"
$deployArcatJson = Join-Path $ProjectDir "deployments\localhost_arcat.json"
$rootEnv         = Join-Path $ProjectDir ".env"
$gatewayEnv      = Join-Path $ProjectDir "rust-gateway\.env"

$vars = @{}

# ── Leer deploy manifest base ──────────────────────────────────────
if (Test-Path $deployJson) {
    $deploy = Get-Content $deployJson | ConvertFrom-Json
    $vars["CONTRACT_SECURITY_AUDIT"]      = $deploy.contracts.SecurityAudit
    $vars["CONTRACT_ALERT_REGISTRY"]      = $deploy.contracts.AlertRegistry
    $vars["VITE_CONTRACT_SECURITY_AUDIT"] = $deploy.contracts.SecurityAudit
    $vars["VITE_CONTRACT_ALERT_REGISTRY"] = $deploy.contracts.AlertRegistry
} else {
    Write-Host "[AVISO] No se encontro deployments\localhost.json" -ForegroundColor Yellow
}

# ── Leer deploy manifest ARCAT ─────────────────────────────────────
if (Test-Path $deployArcatJson) {
    $deployArcat = Get-Content $deployArcatJson | ConvertFrom-Json
    
    $vars["CONTRACT_ARCAT_ROOT"]     = $deployArcat.contracts.ArcatRoot
    $vars["CONTRACT_ARCAT_REGISTRY"] = $deployArcat.contracts.ArcatRegistry
    $vars["VITE_ARCAT_ROOT"]         = $deployArcat.contracts.ArcatRoot
    $vars["VITE_ARCAT_REGISTRY"]     = $deployArcat.contracts.ArcatRegistry

    # Direcciones Generales
    foreach ($dgCode in $deployArcat.contracts.DireccionesGenerales.psobject.properties.name) {
        $dgAddr = $deployArcat.contracts.DireccionesGenerales.$dgCode.address
        $key = "CONTRACT_DG_" + $dgCode.Replace("-", "_")
        $vars[$key] = $dgAddr
        $vars["VITE_" + $key] = $dgAddr
    }

    # Unidades Operativas
    foreach ($dgCode in $deployArcat.contracts.UnidadesOperativas.psobject.properties.name) {
        $uos = $deployArcat.contracts.UnidadesOperativas.$dgCode
        foreach ($uoCode in $uos.psobject.properties.name) {
            $uoAddr = $uos.$uoCode.address
            $key = "CONTRACT_" + $uoCode.Replace("-", "_")
            $vars[$key] = $uoAddr
            $vars["VITE_" + $key] = $uoAddr
        }
    }
} else {
    Write-Host "[AVISO] No se encontro deployments\localhost_arcat.json" -ForegroundColor Yellow
}

# ── Sincronizar variables de config adicionales si estan en root .env ──
if (Test-Path $rootEnv) {
    $rootContent = Get-Content $rootEnv -Raw -ErrorAction SilentlyContinue
    if ($rootContent -match "(?m)^ABUSECH_AUTH_KEY=(.+)") {
        $abusechKey = $Matches[1].Trim()
        if ($abusechKey -and $abusechKey -ne "your_abusech_key_here") {
            $vars["ABUSECH_AUTH_KEY"] = $abusechKey
        }
    }
    if ($rootContent -match "(?m)^ETH_RPC_URL=(.+)") {
        $vars["ETH_RPC_URL"] = $Matches[1].Trim()
    }
    if ($rootContent -match "(?m)^DEPLOYER_PRIVATE_KEY=(.+)") {
        $vars["DEPLOYER_PRIVATE_KEY"] = $Matches[1].Trim()
    }
}

# ── Funcion de actualizacion de .env ─────────────────────────────
function Update-EnvFile {
    param(
        [string]$Path,
        [hashtable]$Variables
    )

    if (-not (Test-Path $Path)) {
        Write-Host "  [AVISO] No se encontro: $Path. Creando archivo vacio." -ForegroundColor Yellow
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }

    $content = [System.IO.File]::ReadAllText($Path)

    foreach ($key in $Variables.Keys) {
        $val = $Variables[$key]
        if ($content -match "(?m)^$key=") {
            $content = $content -replace "(?m)^$key=.*", "$key=$val"
        } else {
            $content += "`n$key=$val"
        }
    }

    # Escribir sin BOM
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  [OK] Actualizado: $Path" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Sincronizando root .env ..." -ForegroundColor Cyan
Update-EnvFile -Path $rootEnv -Variables $vars

Write-Host "  Sincronizando rust-gateway .env ..." -ForegroundColor Cyan
Update-EnvFile -Path $gatewayEnv -Variables $vars

Write-Host ""
Write-Host "  [OK] Sincronizacion completa." -ForegroundColor Green
Write-Host ""
exit 0
