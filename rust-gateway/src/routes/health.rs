//! Ruta de health check — /api/health
//! Verifica el estado de todos los servicios conectados

use axum::{extract::State, response::Json, routing::get, Router};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(health_handler))
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let uptime_secs = (Utc::now() - state.started_at).num_seconds();

    Json(json!({
        "status": "ok",
        "service": "CyberSecurity DApp — Rust Gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_secs,
        "started_at": state.started_at,
        "timestamp": Utc::now(),
        "cache": {
            "alerts": state.alerts_cache.len(),
            "ips": state.ip_cache.len(),
            "cves": state.cve_cache.len()
        },
        "apis_configured": {
            "wazuh": !state.wazuh_url.is_empty(),
            "abuseipdb": !state.abuseipdb_key.is_empty(),
            "virustotal": !state.virustotal_key.is_empty(),
            "greynoise": !state.greynoise_key.is_empty(),
            "otx": !state.otx_key.is_empty(),
            "nvd": true,
            "nvd_key_present": state.nvd_key.is_some()
        }
    }))
}
