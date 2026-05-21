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
