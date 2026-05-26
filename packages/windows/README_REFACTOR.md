# Windows Packages Refactoring & Architecture Reference

This document outlines the architecture and deployment strategy for the Windows Endpoint Client, detailing the active custom installer and the purpose of the legacy reference scripts.

---

## 1. Active Custom Installer: `cybersec-gateway.msi`

The primary installer for our custom DApp is generated from:
- **WiX Configuration:** `gateway-installer.wxs`
- **Build Script:** `generate_gateway_msi.ps1`
- **Service Configuration:** `cybersec-gateway-service.xml`

### What it does:
1. Compiles and packages `cybersec-gateway.exe` (our Rust API Gateway).
2. Automates downloading and packaging the Windows Service Wrapper (WinSW).
3. Deploys the gateway as an automatic Windows Service named `CybersecGateway`.
4. Binds all configuration variables (e.g. host, port, Wazuh API, threat intel keys) as system environment variables.
5. Deploys a Start Menu shortcut that automatically opens the DApp Dashboard at `http://localhost:5173`.

---

## 2. Legacy / Reference Scripts: Wazuh Agent Compilation

The following files are preserved in this directory for **architectural reference only**:
- `generate_wazuh_msi.ps1`
- `generate_compiled_windows_agent.sh`
- `Dockerfile`
- `entrypoint.sh`

### Why they are inactive in this workspace:
- These scripts are designed to build the **official Wazuh Agent from source code**.
- They expect the source code folder structure of the official [Wazuh repository](https://github.com/wazuh/wazuh) to run dependencies and makefiles.
- Running these scripts in this repository will fail because this is our custom **CyberSecurity DApp** repository, not the Wazuh source code.

### Recommended Usage:
If you need to customize or compile a custom Wazuh agent from source:
1. Clone the official Wazuh repository in a separate workspace.
2. Copy these scripts to the `src/win32` or appropriate folder inside the Wazuh repository.
3. Run the scripts there to compile a custom `wazuh-agent.msi`.
4. Otherwise, for standard deployments, **always use the official, pre-compiled Wazuh Agent MSI** provided by Wazuh.
