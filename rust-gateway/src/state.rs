//! Estado compartido de la aplicación (AppState)
//! Contiene clientes HTTP, caché y configuración global.

use std::sync::Arc;
use dashmap::DashMap;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rusqlite::{Error, types};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::models::alert::Alert;
use crate::clients::{
    abuseipdb::AbuseIpDbClient,
    greynoise::GreyNoiseClient,
    virustotal::VirusTotalClient,
    nvd::NvdClient,
    otx::OtxClient,
};

fn valid_api_key(key: &str) -> bool {
    let trimmed = key.trim();
    !trimmed.is_empty()
        && !trimmed.to_lowercase().contains("replace_with_real")
        && !trimmed.to_lowercase().contains("your_")
}

/// Estado global compartido entre todos los handlers de Axum
pub struct AppState {
    /// Cache de alertas recientes (id → alerta)
    pub alerts_cache: DashMap<String, Alert>,

    /// Cache de reputación de IPs (ip → datos)
    pub ip_cache: DashMap<String, serde_json::Value>,

    /// Cache de CVEs consultados (cve_id → datos)
    pub cve_cache: DashMap<String, serde_json::Value>,

    /// Pool de conexiones a base de datos SQLite para persistencia
    pub db_pool: Pool<SqliteConnectionManager>,

    /// Clientes de APIs externas
    pub abuseipdb: Arc<AbuseIpDbClient>,
    pub greynoise: Arc<GreyNoiseClient>,
    pub virustotal: Arc<VirusTotalClient>,
    pub nvd: Arc<NvdClient>,
    pub otx: Arc<OtxClient>,

    /// Configuración de Wazuh (mantenidas para health check)
    pub wazuh_url: String,

    /// API Keys (mantenidas para health check)
    pub abuseipdb_key: String,
    pub virustotal_key: String,
    pub greynoise_key: String,
    pub otx_key: String,
    pub nvd_key: Option<String>,

    /// Configuración de Blockchain
    pub eth_rpc_url: String,
    pub deployer_private_key: String,
    pub contract_security_audit: String,
    pub contract_alert_registry: String,

    /// Timestamp de inicio del gateway
    pub started_at: DateTime<Utc>,
}

impl AppState {
    /// Inicializa el estado desde variables de entorno y carga datos persistentes
    pub async fn new() -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // Wazuh usa certs auto-firmados
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        // Inicializar pool de conexiones SQLite
        let db_path = std::env::var("DATABASE_URL").unwrap_or_else(|_| "gateway_data.db".to_string());
        // Crear directorio padre si no existe
        if let Some(parent) = std::path::Path::new(&db_path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let manager = SqliteConnectionManager::file(&db_path);
        let db_pool = Pool::new(manager)?;
        Self::init_database(&db_pool)?;


        let wazuh_url = std::env::var("WAZUH_API_URL")
            .unwrap_or_else(|_| "https://localhost:55000".to_string());
        let _wazuh_user = std::env::var("WAZUH_API_USER")
            .unwrap_or_else(|_| "wazuh-wui".to_string());
        let _wazuh_pass = std::env::var("WAZUH_API_PASS")
            .unwrap_or_else(|_| "MyS3cr37P450r.*".to_string());
        let abuseipdb_key = std::env::var("ABUSEIPDB_API_KEY").unwrap_or_default();
        let virustotal_key = std::env::var("VIRUSTOTAL_API_KEY").unwrap_or_default();
        let greynoise_key = std::env::var("GREYNOISE_API_KEY").unwrap_or_default();
        let otx_key = std::env::var("OTX_API_KEY").unwrap_or_default();
        let nvd_key = std::env::var("NVD_API_KEY").ok().filter(|k| valid_api_key(k));

        let abuseipdb = Arc::new(AbuseIpDbClient::new(http_client.clone(), abuseipdb_key.clone()));
        let greynoise = Arc::new(GreyNoiseClient::new(http_client.clone(), greynoise_key.clone()));
        let virustotal = Arc::new(VirusTotalClient::new(http_client.clone(), virustotal_key.clone()));
        let nvd = Arc::new(NvdClient::new(http_client.clone(), nvd_key.clone()));
        let otx = Arc::new(OtxClient::new(http_client.clone(), otx_key.clone()));

        let eth_rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());
        let deployer_private_key = std::env::var("DEPLOYER_PRIVATE_KEY")
            .unwrap_or_else(|_| "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string());
        let contract_security_audit = std::env::var("CONTRACT_SECURITY_AUDIT").unwrap_or_default();
        let contract_alert_registry = std::env::var("CONTRACT_ALERT_REGISTRY").unwrap_or_default();

        let mut state = Self {
            alerts_cache: DashMap::new(),
            ip_cache: DashMap::new(),
            cve_cache: DashMap::new(),
            db_pool,
            abuseipdb,
            greynoise,
            virustotal,
            nvd,
            otx,
            wazuh_url,
            abuseipdb_key,
            virustotal_key,
            greynoise_key,
            otx_key,
            nvd_key,
            eth_rpc_url,
            deployer_private_key,
            contract_security_audit,
            contract_alert_registry,
            started_at: Utc::now(),
        };

        // Cargar datos persistentes en memoria
        state.load_persistent_data()?;

        Ok(state)
    }

    /// Inicializa las tablas de la base de datos
    fn init_database(db_pool: &Pool<SqliteConnectionManager>) -> Result<()> {
        let conn = db_pool.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    /// Carga datos persistentes desde la base de datos a la memoria
    fn load_persistent_data(&mut self) -> Result<()> {
        let conn = self.db_pool.get()?;

        // Cargar alertas
        let mut stmt = conn.prepare("SELECT id, data FROM alerts")?;
        let alert_iter = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let data: String = row.get(1)?;
            let alert: Alert = serde_json::from_str(&data).map_err(|e| Error::FromSqlConversionFailure(0, types::Type::Text, Box::new(e)))?;
            Ok((id, alert))
        })?;

        for result in alert_iter {
            let (id, alert) = result?;
            self.alerts_cache.insert(id, alert);
        }

        // Cargar IP cache
        let mut stmt = conn.prepare("SELECT ip, data FROM ip_cache")?;
        let ip_iter = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            let data: String = row.get(1)?;
            let value: serde_json::Value = serde_json::from_str(&data).map_err(|e| Error::FromSqlConversionFailure(0, types::Type::Text, Box::new(e)))?;
            Ok((ip, value))
        })?;

        for result in ip_iter {
            let (ip, value) = result?;
            self.ip_cache.insert(ip, value);
        }

        // Cargar CVE cache
        let mut stmt = conn.prepare("SELECT cve_id, data FROM cve_cache")?;
        let cve_iter = stmt.query_map([], |row| {
            let cve_id: String = row.get(0)?;
            let data: String = row.get(1)?;
            let value: serde_json::Value = serde_json::from_str(&data).map_err(|e| Error::FromSqlConversionFailure(0, types::Type::Text, Box::new(e)))?;
            Ok((cve_id, value))
        })?;

        for result in cve_iter {
            let (cve_id, value) = result?;
            self.cve_cache.insert(cve_id, value);
        }

        Ok(())
    }

    /// Guarda una alerta en la base de datos
    /// Guarda datos de IP en la base de datos
    pub fn save_ip_data(&self, ip: &str, data: &serde_json::Value) -> Result<()> {
        let conn = self.db_pool.get()?;
        let data_str = serde_json::to_string(data)?;
        let created_at = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO ip_cache (ip, data, created_at) VALUES (?1, ?2, ?3)",
            [ip, &data_str, &created_at],
        )?;
        Ok(())
    }

    /// Guarda datos de CVE en la base de datos
    pub fn save_cve_data(&self, cve_id: &str, data: &serde_json::Value) -> Result<()> {
        let conn = self.db_pool.get()?;
        let data_str = serde_json::to_string(data)?;
        let created_at = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cve_id, data, created_at) VALUES (?1, ?2, ?3)",
            [cve_id, &data_str, &created_at],
        )?;
        Ok(())
    }
}
