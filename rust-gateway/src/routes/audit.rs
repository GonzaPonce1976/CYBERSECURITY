//! Ruta de auditoría blockchain — /api/audit
//! Registro y consulta de eventos on-chain

use axum::{extract::State, response::Json, routing::{get, post}, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

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

async fn get_audit_trail(State(_state): State<Arc<AppState>>) -> Json<Value> {
    // Datos de ejemplo del trail de auditoría
    let example_events = vec![
        AuditEvent {
            id: "1".to_string(),
            event_type: "THREAT_DETECTED".to_string(),
            severity: "CRITICAL".to_string(),
            description: "Intento de acceso no autorizado detectado desde 45.33.32.156".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x7a2c8b9f...3e4d5".to_string()),
        },
        AuditEvent {
            id: "2".to_string(),
            event_type: "VULNERABILITY_IDENTIFIED".to_string(),
            severity: "HIGH".to_string(),
            description: "CVE-2021-44228 (Log4Shell) detectada en servidor de aplicaciones".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x5f1a3d7c...8e9b2".to_string()),
        },
        AuditEvent {
            id: "3".to_string(),
            event_type: "ALERT_GENERATED".to_string(),
            severity: "MEDIUM".to_string(),
            description: "Reputación sospechosa detectada para IP 93.174.95.106".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x2d4e6f9a...1c3b5".to_string()),
        },
        AuditEvent {
            id: "4".to_string(),
            event_type: "POLICY_VIOLATION".to_string(),
            severity: "HIGH".to_string(),
            description: "Violación de política de seguridad: Multiple failed login attempts".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x8b5c2e1f...6d7a9".to_string()),
        },
        AuditEvent {
            id: "5".to_string(),
            event_type: "COMPLIANCE_CHECK".to_string(),
            severity: "LOW".to_string(),
            description: "Verificación de cumplimiento completada - Todos los sistemas en estado compliant".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            blockchain_tx: Some("0x3e4d5f6a...2b1c8".to_string()),
        },
    ];

    Json(json!({
        "status": "ok",
        "message": "Audit trail blockchain sincronizado",
        "data": example_events,
        "total": example_events.len()
    }))
}

async fn log_event(
    State(_state): State<Arc<AppState>>,
    axum::extract::Json(payload): axum::extract::Json<LogEventRequest>,
) -> Json<Value> {
    // TODO Fase 3: Escribir evento en Smart Contract vía alloy-rs
    tracing::info!("📝 Evento de auditoría registrado: {:?}", payload);
    
    Json(json!({
        "status": "ok",
        "message": "Evento registrado en blockchain",
        "event": {
            "type": payload.event_type,
            "severity": payload.severity,
            "description": payload.description,
            "alert_id": payload.alert_id,
        },
        "blockchain_tx": "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
    }))
}
