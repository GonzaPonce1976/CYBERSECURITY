//! Cliente AlienVault OTX — Indicadores de Compromiso (IoCs)
#![allow(dead_code)]
//! Docs: https://otx.alienvault.com/api

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct OtxPulseInfo {
    pub count: u32,
    pub pulses: Vec<OtxPulse>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtxPulse {
    pub malware_families: Vec<OtxMalwareFamily>,
    pub attack_ids: Vec<OtxAttackId>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtxMalwareFamily {
    pub display_name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtxAttackId {
    pub id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtxIpResponse {
    pub pulse_info: OtxPulseInfo,
    pub country_name: Option<String>,
}

/// Resultado simplificado del IoC
#[derive(Debug, Clone)]
pub struct IocResult {
    pub indicator: String,
    pub indicator_type: String, // "ip", "domain", "hash"
    pub pulse_count: u32,
    pub is_malicious: bool,
    pub malware_families: Vec<String>,
    pub mitre_attack_ids: Vec<String>,
    pub country: Option<String>,
}

pub struct OtxClient {
    client: reqwest::Client,
    api_key: String,
}

impl OtxClient {
    pub fn new(client: reqwest::Client, api_key: String) -> Self {
        Self { client, api_key }
    }

    /// Consulta IoC para una IP en AlienVault OTX
    pub async fn check_ip(&self, ip: &str) -> Result<IocResult> {
        if self.api_key.is_empty() {
            warn!("⚠️  OTX API key no configurada — saltando consulta");
            anyhow::bail!("OTX API key no configurada");
        }

        debug!("🔍 OTX: consultando IP {}", ip);

        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general",
            ip
        );

        let response = self
            .client
            .get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .context("Error conectando con OTX API")?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("OTX retornó error: {}", status);
        }

        let parsed: OtxIpResponse = response
            .json()
            .await
            .context("Error parseando respuesta de OTX")?;

        let malware_families: Vec<String> = parsed
            .pulse_info
            .pulses
            .iter()
            .flat_map(|p| p.malware_families.iter().map(|m| m.display_name.clone()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mitre_ids: Vec<String> = parsed
            .pulse_info
            .pulses
            .iter()
            .flat_map(|p| p.attack_ids.iter().map(|a| a.id.clone()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        Ok(IocResult {
            indicator: ip.to_string(),
            indicator_type: "ip".to_string(),
            pulse_count: parsed.pulse_info.count,
            is_malicious: parsed.pulse_info.count > 0,
            malware_families,
            mitre_attack_ids: mitre_ids,
            country: parsed.country_name,
        })
    }

}
