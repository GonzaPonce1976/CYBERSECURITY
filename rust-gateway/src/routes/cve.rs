//! Ruta de CVEs — /api/cve/:cve_id
//! Consulta NVD/NIST API con cache

use axum::{extract::{Path, State}, http::StatusCode, response::Json, routing::get, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{error, info};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/{cve_id}", get(get_cve))
}

async fn get_cve(
    State(state): State<Arc<AppState>>,
    Path(cve_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Revisar cache
    if let Some(cached) = state.cve_cache.get(&cve_id) {
        return Ok(Json(json!({
            "status": "ok",
            "source": "cache",
            "data": cached.value().clone()
        })));
    }

    info!("🔎 Consultando CVE {} en NVD/NIST", cve_id);

    match state.nvd.get_cve(&cve_id).await {
        Ok(cve) => {
            let result = json!({
                "id": cve.id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "published": cve.published,
                "last_modified": cve.last_modified,
                "references": cve.references,
            });

            state.cve_cache.insert(cve_id.clone(), result.clone());
            if let Err(e) = state.save_cve_data(&cve_id, &result) {
                error!("Error guardando datos de CVE en DB: {}", e);
            }

            Ok(Json(json!({
                "status": "ok",
                "source": "live",
                "data": result
            })))
        }
        Err(e) => {
            let message = e.to_string();
            let status = if message.to_lowercase().contains("no encontrado") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_GATEWAY
            };

            Err((status, Json(json!({
                "status": "error",
                "message": message,
                "cve_id": cve_id
            }))))
        }
    }
}
