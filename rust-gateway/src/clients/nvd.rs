//! Cliente NVD/NIST — Base de datos de vulnerabilidades (CVEs)
//! Docs: https://nvd.nist.gov/developers/vulnerabilities

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize, Clone)]
pub struct NvdCveItem {
    pub id: String,
    pub published: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    pub cvss_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssMetric {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssData,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssMetricV2 {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssDataV2,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssDataV2 {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NvdReference {
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnWrapper>,
    #[serde(rename = "totalResults")]
    total_results: u64,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCveItem,
}

/// Resultado resumido de un CVE para el sistema
#[derive(Debug, Clone)]
pub struct CveResult {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: Option<String>,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    pub references: Vec<String>,
}

pub struct NvdClient {
    client: reqwest::Client,
    api_key: Option<String>,
}

fn valid_api_key(key: &str) -> bool {
    let trimmed = key.trim();
    !trimmed.is_empty()
        && !trimmed.to_lowercase().contains("replace_with_real")
        && !trimmed.to_lowercase().contains("your_")
}

impl NvdClient {
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        let api_key = api_key.filter(|k| valid_api_key(k));
        Self { client, api_key }
    }

    /// Busca un CVE por ID (ej: "CVE-2023-44487")
    pub async fn get_cve(&self, cve_id: &str) -> Result<CveResult> {
        debug!("🔍 NVD: buscando {}", cve_id);

        let mut request = self
            .client
            .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
            .query(&[("cveId", cve_id)]);

        // API key es opcional pero aumenta el rate limit
        if let Some(key) = &self.api_key {
            if !key.is_empty() {
                request = request.header("apiKey", key);
            }
        }

        let response = request
            .send()
            .await
            .context("Error conectando con NVD API")?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("NVD API retornó error: {}", status);
        }

        let parsed: NvdResponse = response
            .json()
            .await
            .context("Error parseando respuesta de NVD API")?;

        if parsed.total_results == 0 {
            anyhow::bail!("CVE '{}' no encontrado en NVD", cve_id);
        }

        let cve = parsed
            .vulnerabilities
            .into_iter()
            .next()
            .map(|w| w.cve)
            .context("Respuesta NVD vacía")?;

        // Extraer descripción en español o inglés
        let description = cve
            .descriptions
            .iter()
            .find(|d| d.lang == "es")
            .or_else(|| cve.descriptions.iter().find(|d| d.lang == "en"))
            .map(|d| d.value.clone())
            .unwrap_or_else(|| "Sin descripción".to_string());

        // Extraer CVSS score (preferir v3.1 sobre v2)
        let (cvss_score, severity) = if let Some(metrics) = &cve.metrics {
            if let Some(v31) = metrics.cvss_v31.as_ref().and_then(|v| v.first()) {
                (
                    Some(v31.cvss_data.base_score),
                    Some(v31.cvss_data.base_severity.clone()),
                )
            } else if let Some(v2) = metrics.cvss_v2.as_ref().and_then(|v| v.first()) {
                (Some(v2.cvss_data.base_score), None)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(CveResult {
            id: cve.id,
            description,
            cvss_score,
            severity,
            published: cve.published,
            last_modified: cve.last_modified,
            references: cve.references.into_iter().map(|r| r.url).collect(),
        })
    }
}
