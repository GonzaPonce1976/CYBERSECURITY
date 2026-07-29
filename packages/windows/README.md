# Windows Gateway Installer — CyberSec DApp

Instalador MSI para desplegar `cybersec-gateway.exe` como servicio Windows con inicio automático.

## Flujo de pantallas del instalador

```
[Welcome] ─────────────────────────────────────┐
    │                                           │
    ├─ SHOW_ADVANCED=0 (defecto) ──► [GatewayConfigDlg]    ──► [Progress] ──► [Finish]
    │                                  Pantalla informativa
    │                                  (sin parámetros)
    │
    └─ SHOW_ADVANCED=1 (admin)   ──► [GatewayAdminDlg]     ──► [GatewayApiKeysDlg] ──► [Progress] ──► [Finish]
                                      Host / Port / Wazuh URL    API Keys (opcional)
```

Al finalizar la instalación se abre automáticamente `http://localhost:5173` (Dashboard).

## Componentes instalados

| Componente | Destino |
|---|---|
| `cybersec-gateway.exe` | `C:\Program Files\CybersecGateway\` |
| `.env` (configuración) | `C:\Program Files\CybersecGateway\.env` |
| Servicio Windows | `CybersecGateway` — inicio automático |
| Variables de entorno | Sistema (todas las APIs configuradas) |
| Acceso directo | Menú Inicio → CyberSec DApp → CyberSec Dashboard |

## Compilación del instalador

### 1. Compilar el binario Rust en modo release

```powershell
cd rust-gateway
cargo build --release
```

> Nota: El proyecto incluye un archivo `rust-toolchain.toml` en `rust-gateway/` que fija el canal `stable` y el target `x86_64-pc-windows-msvc`. Asegúrate de tener instalado el componente de toolchain MSVC y Visual Studio Build Tools para compilar correctamente en Windows.

### 2. Generar el MSI

```powershell
cd packages/windows

# Instalación mínima (sin firma)
./generate_gateway_msi.ps1 -WIX_TOOLS_PATH "C:\Program Files (x86)\WiX Toolset v3.11\bin"

# Con firma digital
./generate_gateway_msi.ps1 `
  -WIX_TOOLS_PATH "C:\Program Files (x86)\WiX Toolset v3.11\bin" `
  -SIGN yes `
  -CERTIFICATE_PATH "C:\certs\mi-cert.pfx" `
  -CERTIFICATE_PASSWORD "MiPassword"
```

## Modos de instalación

### Modo usuario final (estándar)

```powershell
msiexec /i cybersec-gateway.msi
```
- Muestra pantalla informativa con valores predeterminados
- El usuario no necesita ingresar nada
- El servicio arranca en `:8080` y el dashboard en `:5173`

### Modo administrador (avanzado)

```powershell
msiexec /i cybersec-gateway.msi SHOW_ADVANCED=1
```
- Muestra pantallas para configurar Host, Puerto, Wazuh URL y API Keys
- Las API Keys se guardan como variables de entorno del sistema

### Modo silencioso (CI/CD / despliegue masivo)

```powershell
# Con API Keys configuradas
msiexec /i cybersec-gateway.msi `
  GATEWAY_HOST=0.0.0.0 `
  GATEWAY_PORT=8080 `
  WAZUH_API_URL=https://wazuh.empresa.com:55000 `
  ABUSEIPDB_API_KEY=xxxx `
  VIRUSTOTAL_API_KEY=yyyy `
  GREYNOISE_API_KEY=zzzz `
  /qn /l*v install.log
```

## Gestión del servicio Windows post-instalación

```powershell
# Ver estado
sc query CybersecGateway

# Reiniciar
sc stop CybersecGateway; sc start CybersecGateway

# Ver logs
Get-EventLog -LogName Application -Source CybersecGateway -Newest 50

# Editar configuración (requiere reinicio del servicio)
notepad "C:\Program Files\CybersecGateway\.env"
```

## Desinstalación

```powershell
# Por panel de control o:
msiexec /x cybersec-gateway.msi

# Silenciosa
msiexec /x cybersec-gateway.msi /qn
```

## Requisitos

- **WiX Toolset 3.11+** con `candle.exe` y `light.exe` en el PATH
- **Windows 10/11** x64 (permisos de administrador)
- **Rust** compilado con `cargo build --release` para generar el binario
- *Opcional:* SignTool para firma digital del MSI

## Integración con el Dashboard

La vista **⚙ Servicios** del dashboard en `http://localhost:5173` muestra en tiempo real:
- Estado del Rust Gateway (uptime, cache, APIs configuradas)
- Estado del WebSocket (conexión activa / mensajes recibidos)
- Estado de Anvil/Hardhat (bloque actual, contrato desplegado)
- Estado de Wazuh SIEM (configurado / modo Docker)
- Panel con los comandos MSI disponibles para copiar
