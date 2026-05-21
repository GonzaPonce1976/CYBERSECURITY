//! Cliente REST para la API de Wazuh
#![allow(dead_code)]
//! Autenticación JWT y fetch de alertas

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, error, info};

use crate::models::alert::{Alert, Severity};

/// Respuesta de autenticación de Wazuh
#[derive(Debug, Deserialize)]
struct WazuhAuthResponse {
    data: WazuhAuthData,
}

#[derive(Debug, Deserialize)]
struct WazuhAuthData {
    token: String,
}

/// Respuesta de alertas de Wazuh
#[derive(Debug, Deserialize)]
struct WazuhAlertsResponse {
    data: WazuhAlertsData,
}

#[derive(Debug, Deserialize)]
struct WazuhAlertsData {
    affected_items: Vec<WazuhAlert>,
    total_affected_items: u64,
}

/// Alerta cruda de Wazuh
#[derive(Debug, Deserialize)]
pub struct WazuhAlert {
    pub id: Option<String>,
    pub timestamp: Option<String>,
    pub rule: Option<WazuhRule>,
    pub agent: Option<WazuhAgent>,
    #[serde(rename = "full_log")]
    pub full_log: Option<String>,
    pub location: Option<String>,
    pub src_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WazuhRule {
    pub id: Option<String>,
    pub level: Option<u8>,
    pub description: Option<String>,
    pub mitre: Option<WazuhMitre>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct WazuhMitre {
    pub tactic: Option<Vec<String>>,
    pub technique: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct WazuhAgent {
    pub id: Option<String>,
    pub name: Option<String>,
    pub ip: Option<String>,
}

/// Cliente de la API de Wazuh
pub struct WazuhClient {
    client: reqwest::Client,
    base_url: String,
    username: String,
    password: String,
    token: tokio::sync::RwLock<Option<String>>,
}

impl WazuhClient {
    pub fn new(client: reqwest::Client, base_url: String, username: String, password: String) -> Self {
        Self {
            client,
            base_url,
            username,
            password,
            token: tokio::sync::RwLock::new(None),
        }
    }

    /// Obtiene un token JWT de Wazuh
    pub async fn authenticate(&self) -> Result<String> {
        info!("🔑 Autenticando con Wazuh API...");

        let url = format!("{}/security/user/authenticate", self.base_url);
        let response = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .context("Error conectando con Wazuh API")?;

        if !response.status().is_success() {
            let status = response.status();
            error!("❌ Wazuh auth fallida: {}", status);
            anyhow::bail!("Wazuh authentication failed: {}", status);
        }

        let auth: WazuhAuthResponse = response
            .json()
            .await
            .context("Error parseando respuesta de auth de Wazuh")?;

        let token = auth.data.token;
        *self.token.write().await = Some(token.clone());

        info!("✅ Autenticación Wazuh exitosa");
        Ok(token)
    }

    /// Obtiene el token actual, autenticando si es necesario
    async fn get_token(&self) -> Result<String> {
        let token = self.token.read().await.clone();
        match token {
            Some(t) => Ok(t),
            None => self.authenticate().await,
        }
    }

    /// Obtiene las últimas alertas de Wazuh
    pub async fn get_alerts(&self, limit: u32, offset: u32) -> Result<Vec<Alert>> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/alerts?limit={}&offset={}&sort=-timestamp",
            self.base_url, limit, offset
        );

        debug!("📡 Fetching alertas de Wazuh: {}", url);

        let response = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .context("Error fetching alertas de Wazuh")?;

        if response.status() == 401 {
            // Token expirado — re-autenticar y reintentar
            self.authenticate().await?;
            return Box::pin(self.get_alerts(limit, offset)).await;
        }

        let wazuh_response: WazuhAlertsResponse = response
            .json()
            .await
            .context("Error parseando alertas de Wazuh")?;

        let alerts = wazuh_response
            .data
            .affected_items
            .into_iter()
            .map(Self::map_wazuh_alert)
            .collect();

        Ok(alerts)
    }

    /// Convierte una alerta cruda de Wazuh en nuestro modelo interno
    fn map_wazuh_alert(raw: WazuhAlert) -> Alert {
        let level = raw.rule.as_ref().and_then(|r| r.level);
        let severity = level.map(Severity::from_wazuh_level).unwrap_or(Severity::Info);

        let mut alert = Alert::new(
            raw.rule.as_ref()
                .and_then(|r| r.description.clone())
                .unwrap_or_else(|| "Sin descripción".to_string()),
            severity,
            "wazuh".to_string(),
        );

        alert.wazuh_id = raw.id;
        alert.rule_level = level;
        alert.rule_id = raw.rule.as_ref().and_then(|r| r.id.clone());
        alert.src_ip = raw.src_ip;
        alert.agent_name = raw.agent.as_ref().and_then(|a| a.name.clone());

        if let Some(rule) = &raw.rule {
            if let Some(mitre) = &rule.mitre {
                alert.mitre_tactics = mitre.tactic.clone().unwrap_or_default();
                alert.mitre_techniques = mitre.technique.clone().unwrap_or_default();
            }
        }

        alert
    }
}
