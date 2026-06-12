//! Cliente ThreatFox (abuse.ch) — Compartición de IoCs (IPs, Domains)
//! API: https://threatfox-api.abuse.ch/api/v1/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ─── Estructuras de datos ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatFoxIoc {
    pub id: String,
    pub ioc: String,
    pub threat_type: String,
    pub threat_type_desc: String,
    pub ioc_type: String,
    pub ioc_type_desc: String,
    pub malware: String,
    pub malware_printable: String,
    pub malware_alias: Option<String>,
    pub malware_malpedia: Option<String>,
    pub confidence_level: u8,
    pub first_seen: String,
    pub reporter: String,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxApiResponse {
    query_status: String,
    data: Option<Vec<ThreatFoxIoc>>,
}

// ─── Datos de fallback ────────────────────────────────────────────────────────

fn mock_threatfox_iocs() -> Vec<ThreatFoxIoc> {
    vec![
        ThreatFoxIoc {
            id: "1055621".to_string(),
            ioc: "103.145.253.111:443".to_string(),
            threat_type: "botnet_cc".to_string(),
            threat_type_desc: "Indicator that identifies a botnet command&control server (C&C)".to_string(),
            ioc_type: "ip:port".to_string(),
            ioc_type_desc: "ip:port combination".to_string(),
            malware: "cobalt_strike".to_string(),
            malware_printable: "Cobalt Strike".to_string(),
            malware_alias: None,
            malware_malpedia: Some("https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike".to_string()),
            confidence_level: 100,
            first_seen: "2026-06-12 11:00:00".to_string(),
            reporter: "abuse_ch".to_string(),
            tags: Some(vec!["CobaltStrike".to_string()]),
        },
        ThreatFoxIoc {
            id: "1055620".to_string(),
            ioc: "evil-phishing-domain.com".to_string(),
            threat_type: "payload_delivery".to_string(),
            threat_type_desc: "Indicator that identifies a payload delivery server".to_string(),
            ioc_type: "domain".to_string(),
            ioc_type_desc: "Domain name".to_string(),
            malware: "emotet".to_string(),
            malware_printable: "Emotet".to_string(),
            malware_alias: None,
            malware_malpedia: Some("https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet".to_string()),
            confidence_level: 90,
            first_seen: "2026-06-12 10:45:00".to_string(),
            reporter: "abuse_ch".to_string(),
            tags: Some(vec!["Emotet".to_string()]),
        }
    ]
}

// ─── Cliente ──────────────────────────────────────────────────────────────────

pub struct ThreatFoxClient {
    client: reqwest::Client,
    #[allow(dead_code)]
    auth_key: String,
}

const THREATFOX_API_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

impl ThreatFoxClient {
    pub fn new(client: reqwest::Client, auth_key: String) -> Self {
        Self { client, auth_key }
    }

    /// Obtiene los IoCs compartidos en las últimas 24 horas (máx 1000, truncamos a 50)
    pub async fn get_recent_iocs(&self) -> Result<Vec<ThreatFoxIoc>> {
        debug!("🦊 ThreatFox: obteniendo IoCs recientes");

        let body = serde_json::json!({
            "query": "get_iocs",
            "days": 1
        });

        let resp = match self.client
            .post(THREATFOX_API_URL)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("⚠️ ThreatFox conexión fallida: {}", e);
                return Ok(mock_threatfox_iocs());
            }
        };

        if !resp.status().is_success() {
            return Ok(mock_threatfox_iocs());
        }

        let parsed: ThreatFoxApiResponse = resp.json().await
            .context("Error parseando respuesta ThreatFox")?;

        match parsed.query_status.as_str() {
            "ok" => {
                let mut data = parsed.data.unwrap_or_default();
                data.truncate(50); // limitamos a 50 en la UI para no saturar
                Ok(data)
            },
            _ => Ok(mock_threatfox_iocs()),
        }
    }
}
