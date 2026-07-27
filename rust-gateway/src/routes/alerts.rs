//! Ruta de alertas — /api/alerts

use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::get,
    Router,
};
use alloy::primitives::U256;
use std::str::FromStr;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use crate::state::AppState;

/// Obtiene la IP local (LAN) principal de esta máquina
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

fn resolve_alert_hostname(payload: &Value, remote_ip: Option<String>) -> String {
    payload.get("source_agent")
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("agent_name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .or(remote_ip)
        .unwrap_or_else(|| "unknown".to_string())
}

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
    headers: axum::http::HeaderMap,
    axum::extract::Json(mut payload): axum::extract::Json<Value>,
) -> Json<Value> {
    // Asignar un ID único a la alerta si no lo trae
    let alert_id = payload.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    payload["id"] = json!(alert_id);
    payload["received_at"] = json!(chrono::Utc::now().to_rfc3339());

    // Obtener la IP del remitente desde cabeceras HTTP de proxy/red
    let mut remote_ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
        })
        .map(|s| s.trim().to_string());

    // Si la IP de conexión es loopback/local, resolver a la IP LAN real de esta máquina
    if let Some(ref ip) = remote_ip {
        if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
            if let Some(local_lan) = get_local_ip() {
                remote_ip = Some(local_lan);
            }
        }
    } else {
        remote_ip = get_local_ip();
    }

    // Enriquecer con la IP del agente si no viene explícita
    if payload.get("agent_ip").is_none() {
        let extracted_agent_ip = payload.get("agent")
            .and_then(|a| a.get("ip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| remote_ip.clone())
            .or_else(|| {
                payload.get("src_ip")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .map(|ip| {
                        if ip == "127.0.0.1" || ip == "localhost" {
                            get_local_ip().unwrap_or(ip)
                        } else {
                            ip
                        }
                    })
            });
        
        if let Some(ip) = extracted_agent_ip {
            payload["agent_ip"] = json!(ip);
        }
    }

    // Enriquecer con hostname del agente origen si no viene indicado
    if payload.get("source_agent").is_none() {
        if let Some(agent_name) = payload.get("agent_name").and_then(|v| v.as_str()) {
            payload["source_agent"] = json!(agent_name);
        } else {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown-endpoint".to_string());
            payload["source_agent"] = json!(hostname);
        }
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
            a.source_agent = payload.get("source_agent").and_then(|v| v.as_str()).map(|s| s.to_string());
            a.agent_ip = payload.get("agent_ip").and_then(|v| v.as_str()).map(|s| s.to_string());
            a
        }
    };

    // ─── Enrutamiento ARCAT (Multicontratos SBT) ─────────────────────────────
    let arcat_client = crate::clients::arcat::ArcatClient::new(
        state.eth_rpc_url.clone(),
        state.deployer_private_key.clone(),
        state.contract_arcat_registry.clone(),
        state.contract_arcat_root.clone(),
    );

    if arcat_client.is_configured() {
        let client_arcat = Arc::new(arcat_client);
        let event_type = alert.event_type.clone();
        let severity_str = format!("{:?}", alert.severity).to_uppercase();
        let description = alert.description.clone();
        let malware_family = payload.get("malware_family")
            .or_else(|| payload.get("malware").and_then(|m| m.get("family")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ioc_hashes = payload.get("ioc_hashes")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(Vec::new);
        let src_ip = alert.src_ip.clone().unwrap_or_else(|| "0.0.0.0".to_string());
        let alert_source_agent = alert.source_agent.clone().unwrap_or_else(|| "webhook".to_string());
        let alert_id_clone = alert_id.clone();
        let payload_clone = payload.clone();
        let state_clone = state.clone();

        tokio::spawn(async move {
            let hostname = resolve_alert_hostname(&payload_clone, remote_ip.clone());
            tracing::info!("📡 [ARCAT Webhook] Enrutando alerta '{}' para hostname '{}'...", alert_id_clone, hostname);
            match client_arcat.route_wazuh_alert(
                &hostname,
                &event_type,
                &severity_str,
                &description,
                &malware_family,
                ioc_hashes.clone(),
                &src_ip,
                &alert_id_clone,
            ).await {
                Ok(res) => {
                    tracing::info!("✅ [ARCAT Webhook] Resultado enrutamiento: {}", res);

                    let status = res.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    if status == "ok" || status == "duplicate" {
                        let uo_contract = res.get("uo_contract").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                        let token_id_text = res.get("token_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                        let tx_hash = res.get("tx_hash").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let data_hash = format!(
                            "{:x}",
                            Sha256::digest(format!("{}|{}|{}|{}", description, hostname, alert_id_clone, event_type).as_bytes())
                        );

                        if let Err(e) = state_clone.save_arcat_audit(
                            &alert_id_clone,
                            &token_id_text,
                            &uo_contract,
                            &event_type,
                            &severity_str,
                            &description,
                            &data_hash,
                            &malware_family,
                            &ioc_hashes,
                            &src_ip,
                            &alert_source_agent,
                            tx_hash.as_deref(),
                            &alert_id_clone,
                            true,
                        ) {
                            tracing::warn!("⚠️ No se pudo persistir auditoría ARCAT localmente: {}", e);
                        }

                        if !uo_contract.is_empty() && !token_id_text.is_empty() {
                            if let Ok(token_id) = U256::from_str(&token_id_text) {
                                match client_arcat.get_device_info(&uo_contract, token_id).await {
                                    Ok(device_info) => {
                                        if let Err(e) = state_clone.save_sbt_device(&device_info, &alert_source_agent, Some(&payload_clone)) {
                                            tracing::warn!("⚠️ No se pudo persistir dispositivo SBT localmente: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("⚠️ No se pudo obtener datos del dispositivo ARCAT para persistir espejo: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("❌ [ARCAT Webhook] Fallo enrutamiento: {}", e);
                }
            }
        });
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_alert_hostname_prefers_source_agent() {
        let payload = json!({
            "source_agent": "host-source",
            "agent_name": "host-agent"
        });
        let hostname = resolve_alert_hostname(&payload, Some("127.0.0.1".to_string()));
        assert_eq!(hostname, "host-source");
    }

    #[test]
    fn resolve_alert_hostname_falls_back_to_agent_name() {
        let payload = json!({
            "agent_name": "host-agent"
        });
        let hostname = resolve_alert_hostname(&payload, Some("127.0.0.1".to_string()));
        assert_eq!(hostname, "host-agent");
    }

    #[test]
    fn resolve_alert_hostname_uses_remote_ip_if_no_agent() {
        let payload = json!({});
        let hostname = resolve_alert_hostname(&payload, Some("192.168.0.10".to_string()));
        assert_eq!(hostname, "192.168.0.10");
    }

    #[test]
    fn resolve_alert_hostname_defaults_to_unknown() {
        let payload = json!({});
        let hostname = resolve_alert_hostname(&payload, None);
        assert_eq!(hostname, "unknown");
    }
}

