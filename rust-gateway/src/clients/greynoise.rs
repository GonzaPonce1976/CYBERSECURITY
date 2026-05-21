//! Cliente GreyNoise — Clasificación de IPs (scanner/malicious/benign)
//! Docs: https://docs.greynoise.io/reference/get_v3-community-ip

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct GreyNoiseData {
    pub noise: bool,
    pub riot: bool,
    pub classification: Option<String>, // "malicious" | "benign" | "unknown"
    pub name: Option<String>,
    pub last_seen: Option<String>,
}

pub struct GreyNoiseClient {
    client: reqwest::Client,
    api_key: String,
}

impl GreyNoiseClient {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }

    /// Consulta la clasificación de una IP en GreyNoise Community API
    pub async fn check_ip(&self, ip: &str) -> Result<GreyNoiseData> {
        if self.api_key.is_empty() {
            warn!("⚠️  GreyNoise API key no configurada — saltando consulta");
            anyhow::bail!("GreyNoise API key no configurada");
        }

        debug!("🔍 GreyNoise: consultando IP {}", ip);

        let url = format!("https://api.greynoise.io/v3/community/{}", ip);

        let response = self
            .client
            .get(&url)
            .header("key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Error conectando con GreyNoise")?;

        if response.status() == 404 {
            // IP no encontrada en GreyNoise — devolver sin clasificar
            return Ok(GreyNoiseData {
                noise: false,
                riot: false,
                classification: Some("unknown".to_string()),
                name: None,
                last_seen: None,
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("GreyNoise retornó error: {}", status);
        }

        let parsed: GreyNoiseData = response
            .json()
            .await
            .context("Error parseando respuesta de GreyNoise")?;

        Ok(parsed)
    }
}
