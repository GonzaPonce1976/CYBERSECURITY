//! Ruta de alertas — /api/alerts

use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_alerts))
        .route("/{id}", get(get_alert))
        .route("/webhook", axum::routing::post(receive_webhook))
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertsQuery>,
) -> Json<Value> {
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    // Retornar alertas del cache
    let alerts: Vec<_> = state
        .alerts_cache
        .iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|entry| entry.value().clone())
        .collect();

    Json(json!({
        "status": "ok",
        "total": state.alerts_cache.len(),
        "limit": limit,
        "offset": offset,
        "data": alerts
    }))
}

async fn get_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<Value> {
    match state.alerts_cache.get(&id) {
        Some(alert) => Json(json!({
            "status": "ok",
            "data": alert.value().clone()
        })),
        None => Json(json!({
            "status": "error",
            "message": format!("Alerta '{}' no encontrada", id)
        })),
    }
}

async fn receive_webhook(
    State(state): State<Arc<AppState>>,
    axum::extract::Json(mut payload): axum::extract::Json<Value>,
) -> Json<Value> {
    // Asignar un ID único a la alerta si no lo trae
    let alert_id = payload.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    payload["id"] = json!(alert_id);
    payload["received_at"] = json!(chrono::Utc::now().to_rfc3339());

    // Enriquecer con hostname del agente origen si no viene indicado
    if payload.get("source_agent").is_none() {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown-endpoint".to_string());
        payload["source_agent"] = json!(hostname);
    }

    // Intentar deserializar directamente a Alert; si falla construir uno mínimo
    let alert = match serde_json::from_value::<crate::models::alert::Alert>(payload.clone()) {
        Ok(a) => a,
        Err(_) => {
            use crate::models::alert::{Alert, Severity};
            let description = payload.get("description")
                .or_else(|| payload.get("message"))
                .or_else(|| payload.get("event"))
                .and_then(|v| v.as_str())
                .unwrap_or("Alerta recibida vía webhook")
                .to_string();
            let severity_str = payload.get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("INFO")
                .to_uppercase();
            let severity = match severity_str.as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH"     => Severity::High,
                "MEDIUM"   => Severity::Medium,
                "LOW"      => Severity::Low,
                _          => Severity::Info,
            };
            let event_type = payload.get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("webhook")
                .to_string();
            let mut a = Alert::new(description, severity, event_type);
            a.id = alert_id.clone();
            a.src_ip = payload.get("src_ip").and_then(|v| v.as_str()).map(|s| s.to_string());
            a.agent_name = payload.get("agent_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            a
        }
    };

    // Insertar en caché local
    state.alerts_cache.insert(alert_id.clone(), alert);

    // Persistir en DB local
    if let Ok(conn) = state.db_pool.get() {
        let data_str = serde_json::to_string(&payload).unwrap_or_default();
        let created_at = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO alerts (id, data, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![alert_id, data_str, created_at],
        );
    }

    tracing::info!("🔔 Nueva alerta recibida vía Webhook: {}", alert_id);

    // ── SOC Hub Forwarding ────────────────────────────────────────────────
    // Si CENTRAL_GATEWAY_URL está configurada, reenviar la alerta al servidor
    // central de forma asíncrona (no bloquea la respuesta al cliente).
    if let Some(central_url) = &state.central_gateway_url {
        let forward_url = format!("{}/api/alerts/webhook", central_url.trim_end_matches('/'));
        let client = state.http_client.clone();
        let body = payload.clone();
        let fwd_url = forward_url.clone();

        tokio::spawn(async move {
            match client
                .post(&fwd_url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("✅ Alerta reenviada al hub SOC: {}", fwd_url);
                }
                Ok(resp) => {
                    tracing::warn!("⚠️  Hub SOC respondió con error {}: {}", resp.status(), fwd_url);
                }
                Err(e) => {
                    tracing::warn!("⚠️  No se pudo reenviar alerta al hub SOC {}: {}", fwd_url, e);
                }
            }
        });
    }
    // ─────────────────────────────────────────────────────────────────────

    Json(json!({
        "status": "ok",
        "message": "Alerta recibida exitosamente",
        "alert_id": alert_id
    }))
}

