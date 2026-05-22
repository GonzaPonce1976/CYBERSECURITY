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
    let alert_id = payload.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    payload["id"] = json!(alert_id);
    payload["received_at"] = json!(chrono::Utc::now().to_rfc3339());

    // Insertar en caché
    state.alerts_cache.insert(alert_id.clone(), payload.clone());

    // Intentar guardar en la DB (ignorar errores en caso de no DB)
    if let Ok(conn) = state.db_pool.get() {
        let data_str = serde_json::to_string(&payload).unwrap_or_default();
        let created_at = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO alerts_cache (id, data, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![alert_id, data_str, created_at],
        );
    }

    tracing::info!("🔔 Nueva alerta recibida: {}", alert_id);

    Json(json!({
        "status": "ok",
        "message": "Alerta recibida exitosamente",
        "alert_id": alert_id
    }))
}
