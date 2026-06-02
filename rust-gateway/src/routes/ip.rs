//! Ruta de reputación de IPs — /api/ip/:ip
//! Agrega datos de AbuseIPDB + GreyNoise + OTX en paralelo

use axum::{extract::{Path, State}, response::Json, routing::get, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{error, info};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/{ip}/reputation", get(ip_reputation))
}

async fn ip_reputation(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Json<Value> {
    // Revisar cache primero
    if let Some(cached) = state.ip_cache.get(&ip) {
        return Json(json!({
            "status": "ok",
            "source": "cache",
            "data": cached.value().clone()
        }));
    }

    info!("🌐 Consultando reputación de IP {} en paralelo (AbuseIPDB + VirusTotal + GreyNoise + OTX + Shodan)", ip);

    // Consultar las cinco APIs en paralelo con tokio::join!
    let (abuse_result, virustotal_result, greynoise_result, otx_result, shodan_result) = tokio::join!(
        state.abuseipdb.check_ip(&ip),
        state.virustotal.check_ip(&ip),
        state.greynoise.check_ip(&ip),
        state.otx.check_ip(&ip),
        state.shodan.check_ip(&ip),
    );

    let abuse = match abuse_result {
        Ok(data) => json!({
            "abuse_score": data.abuse_confidence_score,
            "country_code": data.country_code,
            "is_whitelisted": data.is_whitelisted,
            "isp": data.isp,
            "usage_type": data.usage_type,
            "total_reports": data.total_reports,
            "last_reported_at": data.last_reported_at,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let greynoise = match greynoise_result {
        Ok(data) => json!({
            "noise": data.noise,
            "riot": data.riot,
            "classification": data.classification,
            "name": data.name,
            "last_seen": data.last_seen,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let otx = match otx_result {
        Ok(data) => json!({
            "pulse_count": data.pulse_count,
            "is_malicious": data.is_malicious,
            "malware_families": data.malware_families,
            "mitre_attack_ids": data.mitre_attack_ids,
            "country": data.country,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let virustotal = match virustotal_result {
        Ok(data) => json!({
            "reputation": data.reputation,
            "as_owner": data.as_owner,
            "country": data.country,
            "network": data.network,
            "is_malicious": data.is_malicious,
            "malicious_count": data.malicious_count,
            "total_engines": data.total_engines,
            "name": data.name,
            "tags": data.tags,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let shodan = match shodan_result {
        Ok(data) => json!({
            "ports": data.ports,
            "isp": data.isp,
            "os": data.os,
            "org": data.org,
            "country": data.country,
            "vulnerabilities": data.vulnerabilities,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    };

    let result = json!({
        "ip": ip,
        "abuseipdb": abuse,
        "virustotal": virustotal,
        "greynoise": greynoise,
        "otx": otx,
        "shodan": shodan,
    });

    // Guardar en cache y base de datos
    state.ip_cache.insert(ip.clone(), result.clone());
    if let Err(e) = state.save_ip_data(&ip, &result) {
        error!("Error guardando datos de IP en DB: {}", e);
    }

    Json(json!({
        "status": "ok",
        "source": "live",
        "data": result
    }))
}
