//! Modelo de resultado de escaneo antivirus
//! Representa el resultado de un escaneo ClamAV en un endpoint Windows

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Estado del resultado de escaneo antivirus
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    /// Escaneo completado sin amenazas detectadas
    Clean,
    /// Amenazas/malware detectado en el dispositivo
    Infected,
    /// Error durante el escaneo (ClamAV no instalado, error de acceso, etc.)
    Error,
    /// Escaneo pendiente (dispositivo aún no ha reportado)
    Pending,
}

impl ScanStatus {
    /// Retorna emoji representativo del estado
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Clean    => "🟢",
            Self::Infected => "🔴",
            Self::Error    => "🟠",
            Self::Pending  => "🟡",
        }
    }

    /// Retorna color CSS para el frontend
    pub fn color(&self) -> &'static str {
        match self {
            Self::Clean    => "#00ff9d",
            Self::Infected => "#ff3a5c",
            Self::Error    => "#ff7b00",
            Self::Pending  => "#ffd700",
        }
    }

    /// Retorna si requiere acción inmediata (generar alerta crítica)
    pub fn is_critical(&self) -> bool {
        matches!(self, Self::Infected)
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean    => write!(f, "CLEAN"),
            Self::Infected => write!(f, "INFECTED"),
            Self::Error    => write!(f, "ERROR"),
            Self::Pending  => write!(f, "PENDING"),
        }
    }
}

/// Resultado completo de un escaneo ClamAV en un endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusScanResult {
    /// ID único del reporte (UUID v4)
    pub id: String,

    /// UUID del hardware del dispositivo (Win32_ComputerSystemProduct)
    pub device_uuid: String,

    /// Nombre del equipo (hostname)
    pub hostname: String,

    /// IP del dispositivo en la red LAN
    pub agent_ip: Option<String>,

    /// Modo del escaneo: "Daily" o "Weekly"
    pub scan_mode: String,

    /// Timestamp de recepción en el gateway
    pub timestamp: DateTime<Utc>,

    /// Estado del escaneo
    pub status: ScanStatus,

    /// Lista de archivos infectados (ruta + nombre amenaza)
    pub infected_files: Vec<String>,

    /// Cantidad de archivos infectados
    pub infected_count: u32,

    /// Total de archivos escaneados
    pub scanned_files: u32,

    /// Versión del motor ClamAV (ej: "ClamAV 1.4.2")
    pub scanner: String,

    /// Versión del motor (igual que scanner)
    pub engine_version: String,

    /// Fecha de las firmas de virus utilizadas
    pub definitions_date: String,

    /// Duración del escaneo en segundos
    pub scan_duration_s: Option<u32>,

    /// Paths escaneados
    pub scan_paths: Vec<String>,

    /// Error message si status == Error
    pub error_message: Option<String>,

    /// Hash de la transacción blockchain si hubo infección registrada on-chain
    pub blockchain_tx: Option<String>,

    /// Si el evento fue registrado on-chain
    pub on_chain: bool,
}

impl AntivirusScanResult {
    /// Crea un nuevo resultado de escaneo
    pub fn new(hostname: String, device_uuid: String, scan_mode: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            device_uuid,
            hostname,
            agent_ip: None,
            scan_mode,
            timestamp: Utc::now(),
            status: ScanStatus::Pending,
            infected_files: vec![],
            infected_count: 0,
            scanned_files: 0,
            scanner: "ClamAV".to_string(),
            engine_version: "ClamAV".to_string(),
            definitions_date: "Unknown".to_string(),
            scan_duration_s: None,
            scan_paths: vec![],
            error_message: None,
            blockchain_tx: None,
            on_chain: false,
        }
    }
}

/// Resumen estadístico para el dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusSummary {
    pub total_devices: u32,
    pub clean: u32,
    pub infected: u32,
    pub error: u32,
    pub pending: u32,
    pub total_infected_files: u32,
    pub last_updated: DateTime<Utc>,
}
