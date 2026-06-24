//! Estado compartido de la aplicación (AppState)
//! Contiene clientes HTTP, caché y configuración global.

use std::sync::Arc;
use dashmap::DashMap;
use chrono::{DateTime, Utc};
use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::models::alert::Alert;
use crate::clients::{
    abuseipdb::AbuseIpDbClient,
    greynoise::GreyNoiseClient,
    virustotal::VirusTotalClient,
    nvd::NvdClient,
    otx::OtxClient,
    shodan::ShodanClient,
    malwarebazaar::MalwareBazaarClient,
    urlhaus::UrlhausClient,
    threatfox::ThreatFoxClient,
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

    /// Cliente HTTP reutilizable (conexiones pooled)
    pub http_client: reqwest::Client,

    /// Clientes de APIs externas
    pub abuseipdb: Arc<AbuseIpDbClient>,
    pub greynoise: Arc<GreyNoiseClient>,
    pub virustotal: Arc<VirusTotalClient>,
    pub nvd: Arc<NvdClient>,
    pub otx: Arc<OtxClient>,
    pub shodan: Arc<ShodanClient>,
    pub malwarebazaar: Arc<MalwareBazaarClient>,
    pub urlhaus: Arc<UrlhausClient>,
    pub threatfox: Arc<ThreatFoxClient>,

    /// Configuración de Wazuh (mantenidas para health check)
    pub wazuh_url: String,

    /// API Keys (mantenidas para health check)
    pub abuseipdb_key: String,
    pub virustotal_key: String,
    pub greynoise_key: String,
    pub otx_key: String,
    pub shodan_key: String,
    pub nvd_key: Option<String>,
    pub abusech_key: String,

    /// Configuración de Blockchain
    pub eth_rpc_url: String,
    pub deployer_private_key: String,
    pub contract_security_audit: String,
    pub contract_alert_registry: String,

    /// Contratos ARCAT Multicontratos SBT
    pub contract_arcat_root:     String,
    pub contract_arcat_registry: String,
    pub contract_dg_dgr:         String,
    pub contract_dg_dgc:         String,
    pub contract_dg_dgrpi:       String,
    pub contract_dg_staff:       String,
    // Unidades Operativas
    pub contract_uo_rec:         String,
    pub contract_uo_fis:         String,
    pub contract_uo_san:         String,
    pub contract_uo_car:         String,
    pub contract_uo_reg:         String,
    pub contract_uo_rin:         String,
    pub contract_uo_pub:         String,
    pub contract_uo_adm:         String,
    pub contract_uo_rhh:         String,
    pub contract_uo_tec:         String,
    pub contract_uo_jur:         String,
    pub contract_uo_gre:         String,
    pub contract_uo_aud:         String,
    pub contract_uo_sec:         String,


    /// URL del gateway central para forwarding (modo sensor/relay).
    /// Si está vacía, este gateway opera como servidor central (sin forwarding).
    pub central_gateway_url: Option<String>,

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
        let shodan_key = std::env::var("SHODAN_API_KEY").unwrap_or_default();
        let nvd_key = std::env::var("NVD_API_KEY").ok().filter(|k| valid_api_key(k));
        let abusech_key = std::env::var("ABUSECH_AUTH_KEY").unwrap_or_default();

        let abuseipdb = Arc::new(AbuseIpDbClient::new(http_client.clone(), abuseipdb_key.clone()));
        let greynoise = Arc::new(GreyNoiseClient::new(http_client.clone(), greynoise_key.clone()));
        let virustotal = Arc::new(VirusTotalClient::new(http_client.clone(), virustotal_key.clone()));
        let nvd = Arc::new(NvdClient::new(http_client.clone(), nvd_key.clone()));
        let otx = Arc::new(OtxClient::new(http_client.clone(), otx_key.clone()));
        let shodan = Arc::new(ShodanClient::new(http_client.clone(), shodan_key.clone()));
        let malwarebazaar = Arc::new(MalwareBazaarClient::new(http_client.clone(), abusech_key.clone()));
        let urlhaus = Arc::new(UrlhausClient::new(http_client.clone(), abusech_key.clone()));
        let threatfox = Arc::new(ThreatFoxClient::new(http_client.clone(), abusech_key.clone()));

        let eth_rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());
        let deployer_private_key = std::env::var("DEPLOYER_PRIVATE_KEY")
            .unwrap_or_else(|_| "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string());
        let contract_security_audit = std::env::var("CONTRACT_SECURITY_AUDIT").unwrap_or_default();
        let contract_alert_registry = std::env::var("CONTRACT_ALERT_REGISTRY").unwrap_or_default();

        // Variables ARCAT Multicontratos SBT
        let contract_arcat_root     = std::env::var("CONTRACT_ARCAT_ROOT").unwrap_or_default();
        let contract_arcat_registry = std::env::var("CONTRACT_ARCAT_REGISTRY").unwrap_or_default();
        let contract_dg_dgr         = std::env::var("CONTRACT_DG_DGR").unwrap_or_default();
        let contract_dg_dgc         = std::env::var("CONTRACT_DG_DGC").unwrap_or_default();
        let contract_dg_dgrpi       = std::env::var("CONTRACT_DG_DGRPI").unwrap_or_default();
        let contract_dg_staff       = std::env::var("CONTRACT_DG_STAFF").unwrap_or_default();
        let contract_uo_rec         = std::env::var("CONTRACT_UO_REC").unwrap_or_default();
        let contract_uo_fis         = std::env::var("CONTRACT_UO_FIS").unwrap_or_default();
        let contract_uo_san         = std::env::var("CONTRACT_UO_SAN").unwrap_or_default();
        let contract_uo_car         = std::env::var("CONTRACT_UO_CAR").unwrap_or_default();
        let contract_uo_reg         = std::env::var("CONTRACT_UO_REG").unwrap_or_default();
        let contract_uo_rin         = std::env::var("CONTRACT_UO_RIN").unwrap_or_default();
        let contract_uo_pub         = std::env::var("CONTRACT_UO_PUB").unwrap_or_default();
        let contract_uo_adm         = std::env::var("CONTRACT_UO_ADM").unwrap_or_default();
        let contract_uo_rhh         = std::env::var("CONTRACT_UO_RHH").unwrap_or_default();
        let contract_uo_tec         = std::env::var("CONTRACT_UO_TEC").unwrap_or_default();
        let contract_uo_jur         = std::env::var("CONTRACT_UO_JUR").unwrap_or_default();
        let contract_uo_gre         = std::env::var("CONTRACT_UO_GRE").unwrap_or_default();
        let contract_uo_aud         = std::env::var("CONTRACT_UO_AUD").unwrap_or_default();
        let contract_uo_sec         = std::env::var("CONTRACT_UO_SEC").unwrap_or_default();

        if !contract_arcat_root.is_empty() {
            tracing::info!("🏛️  ARCAT Root:     {}", contract_arcat_root);
            tracing::info!("📋 ARCAT Registry:  {}", contract_arcat_registry);
        } else {
            tracing::warn!("⚠️  Contratos ARCAT no configurados (ejecutar deploy_arcat.js)");
        }


        // Modo SOC Hub: si CENTRAL_GATEWAY_URL está definida, este gateway actúa
        // como sensor/relay y reenvía todas las alertas al servidor central.
        let central_gateway_url = std::env::var("CENTRAL_GATEWAY_URL")
            .ok()
            .filter(|u| !u.trim().is_empty());

        if let Some(ref url) = central_gateway_url {
            tracing::info!("🔀 Modo SENSOR activo — forwarding de alertas a: {}", url);
        } else {
            tracing::info!("🏛️  Modo SERVIDOR CENTRAL — este gateway es el hub SOC");
        }

        let mut state = Self {
            alerts_cache: DashMap::new(),
            ip_cache: DashMap::new(),
            cve_cache: DashMap::new(),
            db_pool,
            http_client,
            abuseipdb,
            greynoise,
            virustotal,
            nvd,
            otx,
            shodan,
            malwarebazaar,
            urlhaus,
            threatfox,
            wazuh_url,
            abuseipdb_key,
            virustotal_key,
            greynoise_key,
            otx_key,
            shodan_key,
            nvd_key,
            abusech_key,
            eth_rpc_url,
            deployer_private_key,
            contract_security_audit,
            contract_alert_registry,
            contract_arcat_root,
            contract_arcat_registry,
            contract_dg_dgr,
            contract_dg_dgc,
            contract_dg_dgrpi,
            contract_dg_staff,
            contract_uo_rec,
            contract_uo_fis,
            contract_uo_san,
            contract_uo_car,
            contract_uo_reg,
            contract_uo_rin,
            contract_uo_pub,
            contract_uo_adm,
            contract_uo_rhh,
            contract_uo_tec,
            contract_uo_jur,
            contract_uo_gre,
            contract_uo_aud,
            contract_uo_sec,

            central_gateway_url,
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

    /// Carga datos persistentes desde la base de datos a la memoria.
    /// Las filas con formato inválido (esquema desactualizado) se omiten con un warning
    /// en lugar de crashear el gateway al arrancar.
    fn load_persistent_data(&mut self) -> Result<()> {
        let conn = self.db_pool.get()?;

        // Cargar alertas — tolerante a rows con esquema antiguo
        let mut stmt = conn.prepare("SELECT id, data FROM alerts")?;
        let alert_rows: Vec<(String, String)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

        let mut alerts_loaded = 0usize;
        let mut alerts_skipped = 0usize;
        for (id, data) in alert_rows {
            match serde_json::from_str::<Alert>(&data) {
                Ok(alert) => {
                    self.alerts_cache.insert(id, alert);
                    alerts_loaded += 1;
                }
                Err(e) => {
                    tracing::warn!("⚠️  Alerta con esquema desactualizado omitida (id={}): {}", id, e);
                    alerts_skipped += 1;
                }
            }
        }
        if alerts_skipped > 0 {
            tracing::warn!("⚠️  {} alertas omitidas por esquema inválido. Ejecuta STOP + START para limpiar la caché.", alerts_skipped);
        }
        tracing::info!("📦 Alertas cargadas desde DB: {} ok, {} omitidas", alerts_loaded, alerts_skipped);

        // Cargar IP cache — tolerante a rows con esquema antiguo
        let mut stmt = conn.prepare("SELECT ip, data FROM ip_cache")?;
        let ip_rows: Vec<(String, String)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

        for (ip, data) in ip_rows {
            match serde_json::from_str::<serde_json::Value>(&data) {
                Ok(value) => { self.ip_cache.insert(ip, value); }
                Err(e) => { tracing::warn!("⚠️  IP cache row omitida ({}): {}", ip, e); }
            }
        }

        // Cargar CVE cache — tolerante a rows con esquema antiguo
        let mut stmt = conn.prepare("SELECT cve_id, data FROM cve_cache")?;
        let cve_rows: Vec<(String, String)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

        for (cve_id, data) in cve_rows {
            match serde_json::from_str::<serde_json::Value>(&data) {
                Ok(value) => { self.cve_cache.insert(cve_id, value); }
                Err(e) => { tracing::warn!("⚠️  CVE cache row omitida ({}): {}", cve_id, e); }
            }
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
