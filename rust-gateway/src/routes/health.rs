//! Ruta de health check — /api/health
//! Verifica el estado de todos los servicios conectados

use axum::{extract::State, response::Json, routing::get, Router};
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use crate::state::AppState;

use alloy::providers::{Provider, ProviderBuilder};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(health_handler))
        .route("/blockchain", get(blockchain_health_handler))
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

async fn blockchain_health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rpc_url = &state.eth_rpc_url;
    let contract_addr = &state.contract_security_audit;

    if rpc_url.is_empty() {
        return Json(json!({
            "status": "error",
            "online": false,
            "message": "RPC URL no configurada"
        }));
    }

    let rpc_parsed = match rpc_url.parse() {
        Ok(url) => url,
        Err(_) => {
            return Json(json!({
                "status": "error",
                "online": false,
                "message": "RPC URL inválida"
            }));
        }
    };

    let provider = ProviderBuilder::new().connect_http(rpc_parsed);

    match provider.get_block_number().await {
        Ok(block) => {
            Json(json!({
                "status": "ok",
                "online": true,
                "block": block,
                "contract": contract_addr
            }))
        }
        Err(e) => {
            tracing::warn!("⚠️ RPC de Blockchain offline en {}: {}", rpc_url, e);
            Json(json!({
                "status": "error",
                "online": false,
                "message": format!("RPC offline: {}", e)
            }))
        }
    }
}
