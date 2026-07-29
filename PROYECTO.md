# 🔐 CyberSecurity DApp — Visión del Proyecto

## ¿Qué es este proyecto?

Una **plataforma descentralizada de inteligencia de amenazas** que combina:

- **Wazuh SIEM** como fuente de datos de seguridad real (vía Docker)
- **Rust** como API Gateway de alto rendimiento y agregación multi-fuente
- **Ethereum / Solidity** para registro inmutable de eventos críticos de seguridad
- **Dashboard Web** con visualización en tiempo real de amenazas globales

## Stack Tecnológico

| Capa | Tecnología |
|---|---|
| SIEM Backend | Wazuh 5.0.0 (Docker) |
| API Gateway | Rust 1.94.1 + Axum |
| Blockchain | Solidity 0.8.28 + Hardhat 3.x |
| Testnet | Ethereum Sepolia |
| Frontend | Vite + Vanilla JS + ethers.js v6 |
| Visualización | Chart.js + D3.js |
| Contenedores | Docker Compose v5.1 |

## APIs Integradas

| API | Propósito |
|---|---|
| Wazuh REST API | Alertas y eventos SIEM reales |
| NVD / NIST CVE API | Base de datos de vulnerabilidades |
| AbuseIPDB | Reputación de IPs maliciosas |
| VirusTotal v3 | Análisis de malware / hashes |
| GreyNoise Community | Clasificación de IPs |
| AlienVault OTX | Indicadores de compromiso (IoCs) |
| MITRE ATT&CK | Framework de tácticas de ataque |
| Shodan | Exposición de servicios en internet |
| Ethereum JSON-RPC | Interacción blockchain (alloy-rs) |

## Arquitectura de Capas

```
[Wazuh Docker] ──► [Rust Axum :8080] ──► [Solidity Contracts]
[9 APIs externas] ──►     ↕                      ↕
                    [WebSocket] ──► [Dashboard + MetaMask]
```

## Fases de Desarrollo

| Fase | Descripción | Estado |
|---|---|---|
| 0 | Scaffolding y estructura | ✅ Completado |
| 1 | Stack Wazuh con Docker | ✅ Completado |
| 2 | Rust API Gateway (clientes + rutas) | ✅ Completado |
| 3 | Smart Contracts Solidity + Tests | ✅ Completado |
| 4 | Frontend Dashboard (Vite + Chart.js + ethers.js) | ✅ Completado |
| 5 | Integración Final y Deploy | ✅ Completado |

## Smart Contracts

- `SecurityAudit.sol` — Registro inmutable de eventos de seguridad global
- `AlertRegistry.sol` — Alertas críticas clasificadas por severidad
- `ThreatIntel.sol` — IoCs verificados (IPs maliciosas, hashes)

### 🏛️ Arquitectura ARCAT Multicontratos SBT (Soulbound Tokens)

Esta arquitectura avanzada jerárquica modela la estructura de ARCAT en la blockchain:
- `ArcatRoot.sol` — Gobernanza central y registro de Direcciones Generales autorizadas
- `DireccionGeneral.sol` — Contrato fábrica (Factory) que gestiona y despliega las Unidades Operativas asociadas
- `UnidadOperativaSBT.sol` — Contrato ERC-721 modificado (Soulbound / No transferible). Cada dispositivo es acuñado como un SBT único con su historial de auditorías particular
- `ArcatRegistry.sol` — Índice global para búsquedas ultra-rápidas por Hostname/UUID de dispositivos

## Comandos Principales

```bash
# Levantar todo el stack
npm run docker:up

# Desarrollar contratos en red local (persistente)
npm run dev:contracts:persist

# Desplegar contratos ARCAT en localhost
npm run deploy:arcat:local

# Restaurar dispositivos ARCAT STAFF on-chain
npm run restore:arcat:local

# Levantar nodo local persistente
npm run dev:contracts:persist

# Si usas Anvil, asegúrate de arrancarlo con --state-file
# para que el estado de blockchain sobreviva un reinicio.

# Levantar el gateway Rust
npm run dev:gateway

# Deploy en testnet Sepolia
npm run deploy:sepolia

# Ejecutar tests
npm test
```

---

*Proyecto iniciado: 2026-05-08 | Versión: 0.2.0 (ARCAT Blockchain Edition)*
