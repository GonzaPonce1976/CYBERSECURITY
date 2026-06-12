//! Rutas IoC Intelligence — /api/ioc/*
//! Integra MalwareBazaar (abuse.ch) para análisis de hashes de malware
//!
//! Endpoints:
//!   GET  /api/ioc/hash/{sha256}   → lookup de muestra en MalwareBazaar
//!   GET  /api/ioc/feed/recent     → últimas muestras activas en MalwareBazaar
//!   GET  /api/ioc/correlate       → correlación automática con alertas Wazuh en SQLite

use axum::{
    extract::{Path, State},
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{info, warn};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/hash/{sha256}", get(hash_lookup))
        .route("/feed/recent",   get(recent_feed))
        .route("/correlate",     get(correlate_alerts))
        .route("/urlhaus/recent", get(urlhaus_recent))
        .route("/threatfox/recent", get(threatfox_recent))
}

// ─── GET /api/ioc/hash/{sha256} ───────────────────────────────────────────────
/// Consulta MalwareBazaar por hash SHA256 / MD5 / SHA1
async fn hash_lookup(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Json<Value> {
    info!("🦠 IoC hash lookup: {}", &hash[..hash.len().min(16)]);

    match state.malwarebazaar.query_hash(&hash).await {
        Ok(Some(sample)) => Json(json!({
            "status": "ok",
            "found": true,
            "source": "malwarebazaar",
            "data": {
                "sha256_hash":      sample.sha256_hash,
                "md5_hash":         sample.md5_hash,
                "sha1_hash":        sample.sha1_hash,
                "file_name":        sample.file_name,
                "file_type":        sample.file_type,
                "file_size_bytes":  sample.file_size,
                "signature":        sample.signature,
                "tags":             sample.tags,
                "first_seen":       sample.first_seen,
                "last_seen":        sample.last_seen,
                "origin_country":   sample.origin_country,
                "reporter":         sample.reporter,
                "delivery_method":  sample.delivery_method,
                "clamav":           sample.intelligence.as_ref().map(|i| &i.clamav),
                "reference":        format!("https://bazaar.abuse.ch/sample/{}/", hash.trim()),
            }
        })),
        Ok(None) => Json(json!({
            "status": "ok",
            "found": false,
            "source": "malwarebazaar",
            "message": "Hash no encontrado en la base de datos de MalwareBazaar",
            "data": null
        })),
        Err(e) => {
            warn!("Error en IoC hash lookup: {}", e);
            Json(json!({ "status": "error", "message": e.to_string() }))
        }
    }
}

// ─── GET /api/ioc/feed/recent ─────────────────────────────────────────────────
/// Retorna las últimas 20 muestras añadidas a MalwareBazaar
async fn recent_feed(State(state): State<Arc<AppState>>) -> Json<Value> {
    info!("🦠 IoC feed: solicitando últimas muestras");

    match state.malwarebazaar.get_recent(20).await {
        Ok(samples) => {
            let items: Vec<Value> = samples.into_iter().map(|s| json!({
                "sha256_hash":    s.sha256_hash,
                "file_name":      s.file_name,
                "file_type":      s.file_type,
                "signature":      s.signature,
                "tags":           s.tags,
                "first_seen":     s.first_seen,
                "origin_country": s.origin_country,
                "reference":      format!("https://bazaar.abuse.ch/sample/{}/", s.sha256_hash),
            })).collect();

            Json(json!({
                "status": "ok",
                "count": items.len(),
                "source": "malwarebazaar",
                "data": items
            }))
        }
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

// ─── GET /api/ioc/urlhaus/recent ─────────────────────────────────────────────
/// Retorna las últimas URLs añadidas a URLhaus
async fn urlhaus_recent(State(state): State<Arc<AppState>>) -> Json<Value> {
    info!("🔗 IoC feed: solicitando URLs recientes de URLhaus");

    match state.urlhaus.get_recent_urls().await {
        Ok(urls) => {
            Json(json!({
                "status": "ok",
                "count": urls.len(),
                "source": "urlhaus",
                "data": urls
            }))
        }
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

// ─── GET /api/ioc/threatfox/recent ───────────────────────────────────────────
/// Retorna los últimos IoCs añadidos a ThreatFox
async fn threatfox_recent(State(state): State<Arc<AppState>>) -> Json<Value> {
    info!("🦊 IoC feed: solicitando IoCs recientes de ThreatFox");

    match state.threatfox.get_recent_iocs().await {
        Ok(iocs) => {
            Json(json!({
                "status": "ok",
                "count": iocs.len(),
                "source": "threatfox",
                "data": iocs
            }))
        }
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

// ─── GET /api/ioc/correlate ───────────────────────────────────────────────────
/// Cruza las alertas de Wazuh almacenadas en SQLite con MalwareBazaar.
///
/// Estrategia de correlación:
///  1. Lee todas las alertas de la tabla `alerts`
///  2. Extrae patrones de malware conocidos de la descripción
///  3. Consulta MalwareBazaar por tag/firma para cada patrón único
///  4. Retorna las correlaciones con score de confianza
async fn correlate_alerts(State(state): State<Arc<AppState>>) -> Json<Value> {
    info!("🦠 IoC correlate: cruzando alertas con MalwareBazaar");

    // ── Leer alertas desde SQLite ─────────────────────────────────────────────
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => return Json(json!({ "status": "error", "message": format!("DB: {}", e) })),
    };

    let rows: Vec<(String, String)> = {
        let mut stmt = match conn.prepare(
            "SELECT id, data FROM alerts ORDER BY created_at DESC LIMIT 100"
        ) {
            Ok(s) => s,
            Err(e) => return Json(json!({ "status": "error", "message": format!("SQL prepare: {}", e) })),
        };

        let result: Vec<(String, String)> = match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        }) {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!("Error en query_map de alertas: {}", e);
                vec![]
            }
        };
        result
    };

    // ── Extraer patrones de malware de las descripciones ──────────────────────
    // Familias conocidas — se amplía con cada nueva integración
    let known_families: &[(&str, &str, u8)] = &[
        ("emotet",      "Emotet",      95),
        ("xmrig",       "XMRig",       90),
        ("mimikatz",    "Mimikatz",    92),
        ("cobalt",      "CobaltStrike",88),
        ("metasploit",  "Metasploit",  85),
        ("ransomware",  "Ransomware",  80),
        ("cryptominer", "Cryptominer", 78),
        ("trojan",      "Trojan",      70),
        ("backdoor",    "Backdoor",    75),
        ("rootkit",     "Rootkit",     88),
        ("botnet",      "Botnet",      82),
        ("webshell",    "WebShell",    85),
    ];

    // Patrones encontrados: (tag, familia_printable, confianza, alert_ids)
    let mut family_hits: std::collections::HashMap<String, (String, u8, Vec<String>)> = std::collections::HashMap::new();

    for (alert_id, data_json) in &rows {
        if let Ok(parsed) = serde_json::from_str::<Value>(data_json) {
            if let Some(desc) = parsed["description"].as_str() {
                let desc_lower = desc.to_lowercase();
                for &(pattern, family, confidence) in known_families {
                    if desc_lower.contains(pattern) {
                        family_hits
                            .entry(pattern.to_string())
                            .or_insert_with(|| (family.to_string(), confidence, vec![]))
                            .2
                            .push(alert_id.clone());
                    }
                }
            }
        }
    }

    if family_hits.is_empty() {
        return Json(json!({
            "status": "ok",
            "total_alerts_analyzed": rows.len(),
            "correlations_found": 0,
            "message": "No se detectaron familias de malware conocidas en las alertas actuales",
            "data": []
        }));
    }

    // ── Consultar MalwareBazaar por cada familia detectada ────────────────────
    let mut correlations: Vec<Value> = Vec::new();

    for (tag, (family_name, confidence, alert_ids)) in &family_hits {
        match state.malwarebazaar.query_tag(tag, 5).await {
            Ok(samples) => {
                let sample_summary: Vec<Value> = samples.iter().take(3).map(|s| json!({
                    "sha256":         &s.sha256_hash[..16.min(s.sha256_hash.len())],
                    "file_name":      s.file_name,
                    "file_type":      s.file_type,
                    "first_seen":     s.first_seen,
                    "last_seen":      s.last_seen,
                    "origin_country": s.origin_country,
                    "signature":      s.signature,
                    "tags":           &s.tags,
                    "reference":      format!("https://bazaar.abuse.ch/sample/{}/", s.sha256_hash),
                })).collect();

                correlations.push(json!({
                    "malware_family":    family_name,
                    "tag":              tag,
                    "confidence":       confidence,
                    "alerts_matched":   alert_ids.len(),
                    "alert_ids":        alert_ids,
                    "mb_samples_found": sample_summary.len(),
                    "mb_samples":       sample_summary,
                    "mb_reference":     format!("https://bazaar.abuse.ch/browse/tag/{}/", tag),
                }));
            }
            Err(e) => {
                warn!("Error consultando MalwareBazaar tag '{}': {}", tag, e);
                correlations.push(json!({
                    "malware_family": family_name,
                    "tag": tag,
                    "confidence": confidence,
                    "alerts_matched": alert_ids.len(),
                    "alert_ids": alert_ids,
                    "mb_samples_found": 0,
                    "error": e.to_string(),
                }));
            }
        }
    }

    // Ordenar por confianza descendente
    correlations.sort_by(|a, b| {
        let ca = a["confidence"].as_u64().unwrap_or(0);
        let cb = b["confidence"].as_u64().unwrap_or(0);
        cb.cmp(&ca)
    });

    Json(json!({
        "status": "ok",
        "total_alerts_analyzed": rows.len(),
        "correlations_found": correlations.len(),
        "source": "malwarebazaar",
        "data": correlations
    }))
}
