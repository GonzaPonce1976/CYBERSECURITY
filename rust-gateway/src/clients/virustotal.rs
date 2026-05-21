//! Cliente VirusTotal v3 — Análisis de hashes de malware
#![allow(dead_code)]
//! Docs: https://developers.virustotal.com/reference/file-info

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct VtStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VtIpAttributes {
    pub address: String,
    pub reputation: Option<i32>,
    pub as_owner: Option<String>,
    pub country: Option<String>,
    pub network: Option<String>,
    #[serde(rename = "last_analysis_stats")]
    pub last_analysis_stats: Option<VtStats>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VtIpData {
    pub attributes: VtIpAttributes,
}

#[derive(Debug, Deserialize)]
struct VtIpResponse {
    data: VtIpData,
}

/// Resultado de reputación de IP para el sistema
#[derive(Debug, Clone)]
pub struct VtIpResult {
    pub reputation: Option<i32>,
    pub as_owner: Option<String>,
    pub country: Option<String>,
    pub network: Option<String>,
    pub is_malicious: bool,
    pub malicious_count: Option<u32>,
    pub total_engines: Option<u32>,
    pub name: Option<String>,
    pub tags: Vec<String>,
}

pub struct VirusTotalClient {
    client: reqwest::Client,
    api_key: String,
}

impl VirusTotalClient {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }

    /// Consulta la reputación de una dirección IP en VirusTotal
    pub async fn check_ip(&self, ip: &str) -> Result<VtIpResult> {
        if self.api_key.is_empty() {
            warn!("⚠️  VirusTotal API key no configurada — saltando consulta");
            anyhow::bail!("VirusTotal API key no configurada");
        }

        debug!("🔍 VirusTotal: consultando IP {}", ip);

        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);

        let response = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .context("Error conectando con VirusTotal")?;

        if response.status() == 404 {
            anyhow::bail!("IP '{}' no encontrada en VirusTotal", ip);
        }

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("VirusTotal retornó error: {}", status);
        }

        let parsed: VtIpResponse = response
            .json()
            .await
            .context("Error parseando respuesta de VirusTotal")?;

        let stats = parsed.data.attributes.last_analysis_stats.as_ref();
        let malicious = stats.map(|s| s.malicious).unwrap_or(0);
        let total = stats.map(|s| s.malicious + s.suspicious + s.undetected + s.harmless + s.timeout);

        Ok(VtIpResult {
            reputation: parsed.data.attributes.reputation,
            as_owner: parsed.data.attributes.as_owner.clone(),
            country: parsed.data.attributes.country.clone(),
            network: parsed.data.attributes.network.clone(),
            is_malicious: malicious > 0,
            malicious_count: stats.map(|s| s.malicious),
            total_engines: total,
            name: parsed.data.attributes.as_owner.clone(),
            tags: parsed.data.attributes.tags.unwrap_or_default(),
        })
    }
}
