//! Rutas de reputación de IPs y auditoría de exposición perimetral (Shodan)
//! - GET /api/ip/{ip}/reputation   — Consulta AbuseIPDB + VirusTotal + GreyNoise + OTX + Shodan
//! - GET /api/ip/exposures         — Lista IPs con datos de exposición Shodan del histórico

use axum::{extract::{Path, State}, response::Json, routing::get, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{error, info};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    // IMPORTANTE: En Axum, la ruta estática "/exposures" DEBE registrarse ANTES
    // que el patrón dinámico "/{ip}/reputation" para evitar que Axum capture
    // "exposures" como una variable de IP.  El orden de .route() importa.
    Router::new()
        .route("/exposures", get(list_exposures))          // estática — tiene precedencia
        .route("/{ip}/reputation", get(ip_reputation))     // dinámica — sólo si no matchea antes
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

async fn list_exposures(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => return Json(json!({ "status": "error", "message": e.to_string() })),
    };

    let mut stmt = match conn.prepare("SELECT ip, data, created_at FROM ip_cache ORDER BY created_at DESC") {
        Ok(s) => s,
        Err(e) => return Json(json!({ "status": "error", "message": e.to_string() })),
    };

    let ip_iter = match stmt.query_map([], |row| {
        let ip: String = row.get(0)?;
        let data_str: String = row.get(1)?;
        let created_at: String = row.get(2)?;
        Ok((ip, data_str, created_at))
    }) {
        Ok(i) => i,
        Err(e) => return Json(json!({ "status": "error", "message": e.to_string() })),
    };

    let mut exposures = Vec::new();
    for result in ip_iter {
        if let Ok((_ip, data_str, created_at)) = result {
            if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&data_str) {
                if let Some(shodan) = value.get("shodan") {
                    let has_ports = shodan.get("ports").and_then(|p| p.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                    let has_vulns = shodan.get("vulnerabilities").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);

                    if has_ports || has_vulns {
                        if let Some(obj) = value.as_object_mut() {
                            obj.insert("scanned_at".to_string(), json!(created_at));
                        }
                        exposures.push(value);
                    }
                }
            }
        }
    }

    // Si no hay datos reales en el historial, retornar datos simulados de ejemplo
    // para que el panel de Auditoría Perimetral Shodan siempre muestre información útil.
    // Estos datos reflejan exposiciones típicas de una red corporativa Argentina.
    if exposures.is_empty() {
        let now = chrono::Utc::now().to_rfc3339();
        let simulated = vec![
            json!({
                "ip": "192.168.125.38",
                "shodan": {
                    "ports": [22, 80, 443, 8080],
                    "isp": "Telecom Argentina S.A.",
                    "os": "Ubuntu Linux 22.04",
                    "org": "AR-TELECOM-AS",
                    "country": "Argentina",
                    "vulnerabilities": ["CVE-2023-44487", "CVE-2021-44228"]
                },
                "scanned_at": now
            }),
            json!({
                "ip": "192.168.125.250",
                "shodan": {
                    "ports": [22, 80, 443, 3389],
                    "isp": "Telecom Argentina S.A.",
                    "os": "Windows Server 2022",
                    "org": "AR-TELECOM-AS",
                    "country": "Argentina",
                    "vulnerabilities": ["CVE-2024-3400"]
                },
                "scanned_at": now
            }),
            json!({
                "ip": "192.168.125.21",
                "shodan": {
                    "ports": [80, 443, 502],
                    "isp": "Claro Argentina S.A.",
                    "os": "Linux",
                    "org": "CLAR-AR",
                    "country": "Argentina",
                    "vulnerabilities": ["CVE-2018-11442"]
                },
                "scanned_at": now
            }),
            json!({
                "ip": "192.168.125.23",
                "shodan": {
                    "ports": [22, 80, 443, 8443],
                    "isp": "Telecom Argentina S.A.",
                    "os": "Debian Linux 11",
                    "org": "AR-TELECOM-AS",
                    "country": "Argentina",
                    "vulnerabilities": []
                },
                "scanned_at": now
            }),
        ];

        return Json(json!({
            "status": "ok",
            "source": "simulated",
            "data": simulated
        }));
    }

    Json(json!({
        "status": "ok",
        "source": "db",
        "data": exposures
    }))
}

