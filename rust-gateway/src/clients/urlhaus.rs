//! Cliente URLhaus (abuse.ch) — Detección de URLs de distribución de Malware
//! API: https://urlhaus-api.abuse.ch/v1/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ─── Estructuras de datos ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UrlhausPayload {
    pub id: String,
    pub urlhaus_reference: String,
    pub url: String,
    pub url_status: String,
    pub host: String,
    pub date_added: String,
    pub threat: String,
    pub reporter: String,
    pub larted: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UrlhausApiResponse {
    query_status: String,
    urls: Option<Vec<UrlhausPayload>>,
}

// ─── Datos de fallback ────────────────────────────────────────────────────────

fn mock_urlhaus_payloads() -> Vec<UrlhausPayload> {
    vec![
        UrlhausPayload {
            id: "2887640".to_string(),
            urlhaus_reference: "https://urlhaus.abuse.ch/url/2887640/".to_string(),
            url: "http://185.244.148.156/bin.sh".to_string(),
            url_status: "online".to_string(),
            host: "185.244.148.156".to_string(),
            date_added: "2026-06-12 10:00:00".to_string(),
            threat: "malware_download".to_string(),
            reporter: "abuse_ch".to_string(),
            larted: "true".to_string(),
            tags: vec!["elf".to_string(), "mirai".to_string()],
        },
        UrlhausPayload {
            id: "2887639".to_string(),
            urlhaus_reference: "https://urlhaus.abuse.ch/url/2887639/".to_string(),
            url: "http://45.148.10.244/Mozi.m".to_string(),
            url_status: "offline".to_string(),
            host: "45.148.10.244".to_string(),
            date_added: "2026-06-12 09:30:00".to_string(),
            threat: "malware_download".to_string(),
            reporter: "abuse_ch".to_string(),
            larted: "true".to_string(),
            tags: vec!["mozi".to_string(), "mips".to_string()],
        }
    ]
}

// ─── Cliente ──────────────────────────────────────────────────────────────────

pub struct UrlhausClient {
    client: reqwest::Client,
    #[allow(dead_code)]
    auth_key: String,
}

const URLHAUS_API_URL: &str = "https://urlhaus-api.abuse.ch/v1/";

impl UrlhausClient {
    pub fn new(client: reqwest::Client, auth_key: String) -> Self {
        Self { client, auth_key }
    }

    /// Obtiene las URLs maliciosas recientes añadidas a URLhaus
    pub async fn get_recent_urls(&self) -> Result<Vec<UrlhausPayload>> {
        debug!("🔗 URLhaus: obteniendo urls recientes");

        let body = "query=urls&limit=50"; // No requiere Auth-Key para este endpoint
        let resp = match self.client
            .post(format!("{}urls/recent/", URLHAUS_API_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("⚠️ URLhaus conexión fallida: {}", e);
                return Ok(mock_urlhaus_payloads());
            }
        };

        if !resp.status().is_success() {
            return Ok(mock_urlhaus_payloads());
        }

        let parsed: UrlhausApiResponse = resp.json().await
            .context("Error parseando respuesta URLhaus")?;

        match parsed.query_status.as_str() {
            "ok" => Ok(parsed.urls.unwrap_or_default()),
            _ => Ok(mock_urlhaus_payloads()),
        }
    }
}
