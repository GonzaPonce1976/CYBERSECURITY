//! Cliente AbuseIPDB — Reputación de IPs maliciosas
//! Docs: https://docs.abuseipdb.com/#check-endpoint

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct AbuseIpData {
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u8,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    #[serde(rename = "isWhitelisted")]
    pub is_whitelisted: Option<bool>,
    #[serde(rename = "isp")]
    pub isp: Option<String>,
    #[serde(rename = "usageType")]
    pub usage_type: Option<String>,
    #[serde(rename = "totalReports")]
    pub total_reports: u32,
    #[serde(rename = "lastReportedAt")]
    pub last_reported_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AbuseIpResponse {
    data: AbuseIpData,
}

pub struct AbuseIpDbClient {
    client: reqwest::Client,
    api_key: String,
}

impl AbuseIpDbClient {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }

    /// Verifica la reputación de una IP en AbuseIPDB
    pub async fn check_ip(&self, ip: &str) -> Result<AbuseIpData> {
        if self.api_key.is_empty() {
            warn!("⚠️  AbuseIPDB API key no configurada — saltando consulta");
            anyhow::bail!("AbuseIPDB API key no configurada");
        }

        debug!("🔍 AbuseIPDB: consultando IP {}", ip);

        let response = self
            .client
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .send()
            .await
            .context("Error conectando con AbuseIPDB")?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("AbuseIPDB retornó error: {}", status);
        }

        let parsed: AbuseIpResponse = response
            .json()
            .await
            .context("Error parseando respuesta de AbuseIPDB")?;

        Ok(parsed.data)
    }
}
