//! Ruta de auditoría blockchain — /api/audit
//! Registro y consulta de eventos on-chain usando alloy-rs

use axum::{extract::State, response::Json, routing::{get, post}, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use sha2::{Digest, Sha256};
use crate::state::AppState;

use alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};

// Definición del Smart Contract usando alloy::sol!
alloy::sol! {
    #[sol(rpc)]
    contract SecurityAudit {
        enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

        struct AuditEvent {
            uint256 id;
            uint256 timestamp;
            Severity severity;
            string eventType;      // "INTRUSION", "MALWARE", "ANOMALY", "COMPLIANCE"
            string description;
            bytes32 dataHash;      // SHA256 del payload completo en Rust
            address reporter;      // Dirección del Rust gateway
            string agentName;      // Nombre del agente Wazuh (opcional)
            string srcIp;          // IP de origen (opcional)
            bool verified;
        }

        function logEvent(
            Severity severity,
            string calldata eventType,
            string calldata description,
            bytes32 dataHash,
            string calldata agentName,
            string calldata srcIp
        ) external returns (uint256 id);

        function getEventsCount() external view returns (uint256);
        function getLatestEvents(uint256 count) external view returns (AuditEvent[] memory);
        function getEvent(uint256 id) external view returns (AuditEvent memory);
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/trail", get(get_audit_trail))
        .route("/log", post(log_event))
}

#[derive(Debug, Deserialize)]
pub struct LogEventRequest {
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub alert_id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub timestamp: String,
    pub blockchain_tx: Option<String>,
}

/// Retorna eventos mock en caso de fallback (cuando la blockchain local no está disponible)
fn get_mock_events() -> Vec<AuditEvent> {
    vec![
        AuditEvent {
            id: "1".to_string(),
            event_type: "THREAT_DETECTED".to_string(),
            severity: "CRITICAL".to_string(),
            description: "Intento de acceso no autorizado detectado desde 45.33.32.156".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x7a2c8b9f7d6a5e4c3b2a1f0e9d8c7b6a5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b".to_string()),
        },
        AuditEvent {
            id: "2".to_string(),
            event_type: "VULNERABILITY_IDENTIFIED".to_string(),
            severity: "HIGH".to_string(),
            description: "CVE-2021-44228 (Log4Shell) detectada en servidor de aplicaciones".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x5f1a3d7c8b9a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d".to_string()),
        },
        AuditEvent {
            id: "3".to_string(),
            event_type: "ALERT_GENERATED".to_string(),
            severity: "MEDIUM".to_string(),
            description: "Reputación sospechosa detectada para IP 93.174.95.106".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x2d4e6f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e".to_string()),
        },
        AuditEvent {
            id: "4".to_string(),
            event_type: "POLICY_VIOLATION".to_string(),
            severity: "HIGH".to_string(),
            description: "Violación de política de seguridad: Multiple failed login attempts".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x8b5c2e1f0d9c8b7a6e5f4d3c2b1a0f9e8d7c6b5a4d3e2f1a0b9c8d7e6f5a4b3c".to_string()),
        },
        AuditEvent {
            id: "5".to_string(),
            event_type: "COMPLIANCE_CHECK".to_string(),
            severity: "LOW".to_string(),
            description: "Verificación de cumplimiento completada - Todos los sistemas en estado compliant".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x3e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e".to_string()),
        },
    ]
}

/// Endpoint de Lectura: Obtiene el trail de auditoría on-chain sincronizado del Smart Contract
async fn get_audit_trail(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rpc_url = &state.eth_rpc_url;
    let contract_addr = &state.contract_security_audit;

    // Si no hay dirección de contrato configurada, usamos fallback
    if contract_addr.is_empty() || !contract_addr.starts_with("0x") {
        tracing::warn!("⚠️ CONTRACT_SECURITY_AUDIT no configurado. Utilizando fallback de demostración.");
        return Json(json!({
            "status": "ok",
            "message": "Audit trail blockchain (Demostración — Contrato no configurado)",
            "data": get_mock_events(),
            "total": 5
        }));
    }

    // Intentar conectar con el proveedor RPC
    let rpc_parsed = match rpc_url.parse() {
        Ok(url) => url,
        Err(e) => {
            tracing::error!("❌ Error parseando ETH_RPC_URL ({}): {}", rpc_url, e);
            return Json(json!({
                "status": "ok",
                "message": "Audit trail blockchain (Demostración — Error en URL RPC)",
                "data": get_mock_events(),
                "total": 5
            }));
        }
    };

    let provider = ProviderBuilder::new().connect_http(rpc_parsed);

    // Parsear dirección del contrato
    let address = match contract_addr.parse::<alloy::primitives::Address>() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("❌ Dirección de contrato inválida ({}): {}", contract_addr, e);
            return Json(json!({
                "status": "ok",
                "message": "Audit trail blockchain (Demostración — Dirección inválida)",
                "data": get_mock_events(),
                "total": 5
            }));
        }
    };

    // Instanciar el Smart Contract para interactuar
    let contract = SecurityAudit::new(address, provider);

    // Consultar los últimos 20 eventos registrados on-chain
    match contract.getLatestEvents(alloy::primitives::U256::from(20)).call().await {
        Ok(events_call) => {
            let mut ui_events = Vec::new();
            for e in events_call {
                let severity_str = match e.severity {
                    SecurityAudit::Severity::INFO => "INFO",
                    SecurityAudit::Severity::LOW => "LOW",
                    SecurityAudit::Severity::MEDIUM => "MEDIUM",
                    SecurityAudit::Severity::HIGH => "HIGH",
                    SecurityAudit::Severity::CRITICAL => "CRITICAL",
                    _ => "INFO",
                };

                let data_hash_str = format!("{}", e.dataHash);

                ui_events.push(json!({
                    "id": e.id.to_string(),
                    "timestamp": chrono::DateTime::from_timestamp(e.timestamp.to::<i64>(), 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "".to_string()),
                    "severity": severity_str,
                    "event_type": e.eventType,
                    "description": e.description,
                    "blockchain_tx": Some(data_hash_str)
                }));
            }

            // Invertir orden para mostrar las más recientes arriba
            ui_events.reverse();

            Json(json!({
                "status": "ok",
                "message": "Audit trail blockchain sincronizado desde Smart Contract",
                "data": ui_events,
                "total": ui_events.len()
            }))
        }
        Err(e) => {
            tracing::warn!("⚠️ No se pudo consultar la Blockchain, activando fallback gracioso: {}", e);
            Json(json!({
                "status": "ok",
                "message": "Audit trail blockchain (Demostración — Nodo local offline)",
                "data": get_mock_events(),
                "total": 5
            }))
        }
    }
}

/// Endpoint de Escritura: Firma criptográficamente y registra un evento crítico en el Smart Contract
async fn log_event(
    State(state): State<Arc<AppState>>,
    axum::extract::Json(payload): axum::extract::Json<LogEventRequest>,
) -> Json<Value> {
    let rpc_url = &state.eth_rpc_url;
    let contract_addr = &state.contract_security_audit;
    let private_key = &state.deployer_private_key;

    if contract_addr.is_empty() || private_key.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Blockchain no configurada en el Gateway. Por favor revisa CONTRACT_SECURITY_AUDIT y DEPLOYER_PRIVATE_KEY"
        }));
    }

    // 1. Configurar firmante local
    let signer: PrivateKeySigner = match private_key.parse() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("❌ Error parsing DEPLOYER_PRIVATE_KEY: {}", e);
            return Json(json!({
                "status": "error",
                "message": format!("Error en firma local: Clave privada inválida: {}", e)
            }));
        }
    };
    let wallet = EthereumWallet::from(signer);

    // 2. Conectar al nodo RPC
    let rpc_parsed = match rpc_url.parse() {
        Ok(url) => url,
        Err(e) => {
            return Json(json!({
                "status": "error",
                "message": format!("Error en conexión RPC: URL inválida: {}", e)
            }));
        }
    };

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_parsed);

    // 3. Parsear dirección de contrato
    let address = match contract_addr.parse::<alloy::primitives::Address>() {
        Ok(addr) => addr,
        Err(e) => {
            return Json(json!({
                "status": "error",
                "message": format!("Dirección de contrato inválida: {}", e)
            }));
        }
    };

    // 4. Instanciar contrato interactivo con permisos de escritura
    let contract = SecurityAudit::new(address, provider);

    // 5. Mapear severidad al enum de Solidity
    let severity = match payload.severity.to_uppercase().as_str() {
        "CRITICAL" => SecurityAudit::Severity::CRITICAL,
        "HIGH"     => SecurityAudit::Severity::HIGH,
        "MEDIUM"   => SecurityAudit::Severity::MEDIUM,
        "LOW"      => SecurityAudit::Severity::LOW,
        _          => SecurityAudit::Severity::INFO,
    };

    // 6. Generar hash SHA256 inmutable del evento
    let mut hasher = Sha256::new();
    hasher.update(payload.description.as_bytes());
    let hash_result = hasher.finalize();
    let data_hash = alloy::primitives::FixedBytes::from_slice(&hash_result);

    let agent_name = "".to_string(); // Campos extendibles (opcionales)
    let src_ip = "".to_string();

    tracing::info!("🔗 Enviando evento on-chain a {}...", contract_addr);

    // 7. Enviar y firmar la transacción en caliente
    match contract.logEvent(
        severity,
        payload.event_type.clone(),
        payload.description.clone(),
        data_hash,
        agent_name,
        src_ip
    ).send().await {
        Ok(tx_builder) => {
            let tx_hash: alloy::primitives::B256 = *tx_builder.tx_hash();
            let tx_hash_str = format!("{}", tx_hash);

            tracing::info!("✅ Transacción registrada on-chain exitosamente! Hash: {}", tx_hash_str);

            Json(json!({
                "status": "ok",
                "message": "Evento registrado exitosamente en la Blockchain",
                "event": {
                    "type": payload.event_type,
                    "severity": payload.severity,
                    "description": payload.description,
                    "alert_id": payload.alert_id,
                },
                "blockchain_tx": tx_hash_str
            }))
        }
        Err(e) => {
            tracing::error!("❌ Error enviando transacción a Hardhat: {}", e);
            Json(json!({
                "status": "error",
                "message": format!("Error enviando transacción a Hardhat: {}", e)
            }))
        }
    }
}
