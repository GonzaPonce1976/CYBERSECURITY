//! Modelo de Alerta de seguridad
//! Estructura central del sistema — unifica datos de Wazuh + enriquecimiento externo

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Niveles de severidad de una alerta
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Convierte nivel numérico de Wazuh (1-15) a Severity
    pub fn from_wazuh_level(level: u8) -> Self {
        match level {
            13..=15 => Self::Critical,
            10..=12 => Self::High,
            7..=9   => Self::Medium,
            4..=6   => Self::Low,
            _       => Self::Info,
        }
    }

    /// Retorna el color CSS asociado para el frontend
    pub fn color(&self) -> &'static str {
        match self {
            Self::Critical => "#ff3a5c",
            Self::High     => "#ff7b00",
            Self::Medium   => "#ffd700",
            Self::Low      => "#00d4ff",
            Self::Info     => "#00ff9d",
        }
    }
}

/// Alerta de seguridad enriquecida
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// ID único de la alerta en este sistema
    pub id: String,

    /// ID original de Wazuh (si viene de allí)
    pub wazuh_id: Option<String>,

    /// Timestamp del evento
    pub timestamp: DateTime<Utc>,

    /// Nivel de severidad
    pub severity: Severity,

    /// Nivel numérico original de Wazuh (1-15)
    pub rule_level: Option<u8>,

    /// ID de la regla Wazuh
    pub rule_id: Option<String>,

    /// Descripción del evento
    pub description: String,

    /// IP de origen (si aplica)
    pub src_ip: Option<String>,

    /// IP de destino (si aplica)
    pub dst_ip: Option<String>,

    /// Nombre del agente Wazuh que reporta
    pub agent_name: Option<String>,

    /// Nombre real del equipo endpoint (hostname del PC que originó la alerta)
    /// Poblado automáticamente por el gateway sensor al hacer forwarding
    pub source_agent: Option<String>,

    /// Tipo de evento: "intrusion", "malware", "anomaly", "compliance"
    pub event_type: String,

    /// Tácticas MITRE ATT&CK asociadas
    pub mitre_tactics: Vec<String>,

    /// Técnicas MITRE ATT&CK asociadas
    pub mitre_techniques: Vec<String>,

    /// Score de reputación de la IP (0-100, 100=más maliciosa)
    pub ip_abuse_score: Option<u8>,

    /// Resultado de VirusTotal (si hay hash)
    pub vt_malicious: Option<bool>,

    /// Hash SHA256 del evento para registro blockchain
    pub event_hash: Option<String>,

    /// Tx hash de Ethereum si fue registrado on-chain
    pub blockchain_tx: Option<String>,

    /// Si la alerta ya fue enviada a blockchain
    pub on_chain: bool,
}

impl Alert {
    /// Crea una alerta nueva con ID único
    pub fn new(description: String, severity: Severity, event_type: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            wazuh_id: None,
            timestamp: Utc::now(),
            severity,
            rule_level: None,
            rule_id: None,
            description,
            src_ip: None,
            dst_ip: None,
            agent_name: None,
            source_agent: None,
            event_type,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            ip_abuse_score: None,
            vt_malicious: None,
            event_hash: None,
            blockchain_tx: None,
            on_chain: false,
        }
    }
}
