//! Rutas Antivirus — /api/antivirus/*
//!
//! Recibe, almacena y expone resultados de escaneos ClamAV
//! desde endpoints Windows (via scan_and_report.ps1).
//!
//! Endpoints:
//!   POST /api/antivirus/scan-result           → recibe resultado de escaneo
//!   GET  /api/antivirus/results               → lista todos los resultados
//!   GET  /api/antivirus/results/{hostname}    → filtra por hostname
//!   GET  /api/antivirus/summary               → estadísticas agregadas (KPIs)

use axum::{
    extract::{Path, Query, State},
    response::{Json, IntoResponse, Response},
    routing::{get, post},
    Router,
    http::{header, StatusCode},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{info, warn, error};

use crate::state::AppState;
use crate::models::antivirus::{AntivirusScanResult, AntivirusSummary, ScanStatus};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/scan-result",         post(receive_scan_result))
        .route("/results",             get(list_results))
        .route("/results/{hostname}",  get(results_by_hostname))
        .route("/summary",             get(get_summary))
        .route("/download-installer",  get(download_installer))
}

// ─── Query params ──────────────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct ResultsQuery {
    pub limit:  Option<u32>,
    pub offset: Option<u32>,
    pub status: Option<String>,
}

// ─── POST /api/antivirus/scan-result ──────────────────────────────────────────
/// Recibe el resultado de un escaneo ClamAV desde un endpoint Windows
async fn receive_scan_result(
    State(state): State<Arc<AppState>>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    // Extraer campos del payload
    let hostname = payload.get("hostname")
        .or_else(|| payload.get("agent_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-endpoint")
        .to_string();

    let device_uuid = payload.get("device_uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN-UUID")
        .to_string();

    let scan_mode = payload.get("scan_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("Daily")
        .to_string();

    let status_str = payload.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("PENDING")
        .to_uppercase();

    let status = match status_str.as_str() {
        "CLEAN"    => ScanStatus::Clean,
        "INFECTED" => ScanStatus::Infected,
        "ERROR"    => ScanStatus::Error,
        _          => ScanStatus::Pending,
    };

    let infected_files: Vec<String> = payload.get("infected_files")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect())
        .unwrap_or_default();

    let infected_count = payload.get("infected_count")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .unwrap_or(infected_files.len() as u32);

    let scanned_files = payload.get("scanned_files")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .unwrap_or(0);

    let scanner = payload.get("scanner")
        .or_else(|| payload.get("engine_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("ClamAV")
        .to_string();

    let definitions_date = payload.get("definitions_date")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let scan_duration_s = payload.get("scan_duration_s")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);

    let scan_paths: Vec<String> = payload.get("scan_paths")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect())
        .unwrap_or_default();

    let agent_ip = payload.get("agent_ip")
        .or_else(|| payload.get("src_ip"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let error_message = payload.get("error_message")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Construir resultado
    let mut result = AntivirusScanResult::new(hostname.clone(), device_uuid.clone(), scan_mode.clone());
    result.agent_ip        = agent_ip;
    result.status          = status.clone();
    result.infected_files  = infected_files;
    result.infected_count  = infected_count;
    result.scanned_files   = scanned_files;
    result.scanner         = scanner.clone();
    result.engine_version  = scanner;
    result.definitions_date = definitions_date;
    result.scan_duration_s = scan_duration_s;
    result.scan_paths      = scan_paths;
    result.error_message   = error_message;

    let result_id = result.id.clone();

    // ── Logging ────────────────────────────────────────────────────────────────
    info!(
        "🛡️  Resultado ClamAV [{:?}] — {} | {} | {} archivos | {} infectados",
        status, hostname, scan_mode, scanned_files, infected_count
    );

    if status.is_critical() {
        warn!(
            "🚨 MALWARE DETECTADO en '{}' (UUID: {}) — {} amenazas",
            hostname, device_uuid, infected_count
        );
        for f in &result.infected_files {
            warn!("   🦠 {}", f);
        }
    }

    // ── Persistir en SQLite ───────────────────────────────────────────────────
    if let Ok(conn) = state.db_pool.get() {
        let data_str  = serde_json::to_string(&result).unwrap_or_default();
        let created_at = chrono::Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO antivirus_scans (id, hostname, device_uuid, data, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![result_id, hostname, device_uuid, data_str, created_at],
        );
    }

    // ── Guardar en cache in-memory ────────────────────────────────────────────
    // Key: hostname — guardamos el resultado más reciente por dispositivo
    let cache_key = format!("{}:{}", hostname, scan_mode);
    state.antivirus_cache.insert(cache_key, result.clone());

    // ── Registro blockchain si hay malware ────────────────────────────────────
    // El script scan_and_report.ps1 ya envía la alerta HIGH al webhook de alertas,
    // que a su vez llama a ARCAT para el registro on-chain. Aquí registramos
    // adicionalmente en SecurityAudit para trazabilidad de salud del endpoint.
    if status.is_critical() && !state.contract_security_audit.is_empty() {
        let eth_rpc  = state.eth_rpc_url.clone();
        let priv_key = state.deployer_private_key.clone();
        let contract = state.contract_security_audit.clone();
        let hostname_bc = hostname.clone();
        let uuid_bc     = device_uuid.clone();
        let desc_bc     = format!(
            "MALWARE DETECTED by ClamAV on {} (UUID: {}). {} file(s) infected.",
            hostname, device_uuid, infected_count
        );
        let result_id_bc = result_id.clone();

        tokio::spawn(async move {
            info!("⛓️  Registrando detección de malware on-chain para '{}'...", hostname_bc);
            // Reutilizamos la lógica de audit para el registro
            match register_malware_on_chain(
                &eth_rpc, &priv_key, &contract,
                &hostname_bc, &uuid_bc, &desc_bc, &result_id_bc
            ).await {
                Ok(tx_hash) => {
                    info!("✅ Malware registrado on-chain: tx={}", tx_hash);
                }
                Err(e) => {
                    error!("❌ Error registrando malware on-chain: {}", e);
                }
            }
        });
    }

    Json(json!({
        "status": "ok",
        "message": "Resultado de escaneo antivirus recibido",
        "scan_id": result_id,
        "hostname": hostname,
        "scan_status": status.to_string(),
        "infected_count": infected_count
    }))
}

// ─── GET /api/antivirus/results ────────────────────────────────────────────────
/// Lista todos los resultados de escaneos antivirus (paginados)
async fn list_results(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ResultsQuery>,
) -> Json<Value> {
    let limit  = params.limit.unwrap_or(50).min(200) as usize;
    let offset = params.offset.unwrap_or(0) as usize;

    let mut results: Vec<serde_json::Value> = state
        .antivirus_cache
        .iter()
        .map(|entry| serde_json::to_value(entry.value()).unwrap_or(json!(null)))
        .collect();

    // Filtrar por estado si se especifica
    if let Some(ref status_filter) = params.status {
        let status_upper = status_filter.to_uppercase();
        results.retain(|r| {
            r.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s == status_upper)
                .unwrap_or(false)
        });
    }

    // Ordenar por timestamp desc
    results.sort_by(|a, b| {
        let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_b.cmp(ts_a)
    });

    let total  = results.len();
    let paged  = results.into_iter().skip(offset).take(limit).collect::<Vec<_>>();

    Json(json!({
        "status": "ok",
        "total":  total,
        "limit":  limit,
        "offset": offset,
        "data":   paged
    }))
}

// ─── GET /api/antivirus/results/{hostname} ─────────────────────────────────────
/// Filtra resultados de escaneo por hostname del dispositivo
async fn results_by_hostname(
    State(state): State<Arc<AppState>>,
    Path(hostname): Path<String>,
) -> Json<Value> {
    let results: Vec<serde_json::Value> = state
        .antivirus_cache
        .iter()
        .filter(|entry| {
            entry.value().hostname.to_lowercase() == hostname.to_lowercase()
        })
        .map(|entry| serde_json::to_value(entry.value()).unwrap_or(json!(null)))
        .collect();

    if results.is_empty() {
        return Json(json!({
            "status":  "ok",
            "found":   false,
            "message": format!("No hay resultados para el hostname '{}'", hostname),
            "data":    []
        }));
    }

    Json(json!({
        "status": "ok",
        "found":  true,
        "total":  results.len(),
        "data":   results
    }))
}

// ─── GET /api/antivirus/summary ───────────────────────────────────────────────
/// Devuelve estadísticas agregadas para los KPI cards del dashboard (agrupados por hostname)
async fn get_summary(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    use std::collections::HashMap;

    // Estructura para agrupar por hostname (case-insensitive)
    struct DeviceGroup {
        primary: Option<AntivirusScanResult>,
        selftest: Option<AntivirusScanResult>,
    }

    let mut grouped_devices: HashMap<String, DeviceGroup> = HashMap::new();

    for entry in state.antivirus_cache.iter() {
        let r = entry.value();
        let key = r.hostname.to_lowercase();
        let mode = r.scan_mode.to_uppercase();

        let device_entry = grouped_devices.entry(key).or_insert(DeviceGroup {
            primary: None,
            selftest: None,
        });

        if mode == "SELFTEST" {
            if let Some(ref current) = device_entry.selftest {
                if r.timestamp > current.timestamp {
                    device_entry.selftest = Some(r.clone());
                }
            } else {
                device_entry.selftest = Some(r.clone());
            }
        } else {
            if let Some(ref current) = device_entry.primary {
                if r.timestamp > current.timestamp {
                    device_entry.primary = Some(r.clone());
                }
            } else {
                device_entry.primary = Some(r.clone());
            }
        }
    }

    let mut clean    = 0u32;
    let mut infected = 0u32;
    let mut error    = 0u32;
    let mut pending  = 0u32;
    let mut total_infected_files = 0u32;

    for (_hostname, group) in grouped_devices.iter() {
        if let Some(ref r) = group.primary.as_ref().or(group.selftest.as_ref()) {
            total_infected_files += r.infected_count;
            match r.status {
                ScanStatus::Clean    => clean    += 1,
                ScanStatus::Infected => infected += 1,
                ScanStatus::Error    => error    += 1,
                ScanStatus::Pending  => pending  += 1,
            }
        }
    }

    let summary = AntivirusSummary {
        total_devices: clean + infected + error + pending,
        clean,
        infected,
        error,
        pending,
        total_infected_files,
        last_updated: chrono::Utc::now(),
    };

    Json(json!({
        "status": "ok",
        "data":   summary
    }))
}

// ─── Registro on-chain de malware ──────────────────────────────────────────────
/// Registra la detección de malware en el Smart Contract SecurityAudit
async fn register_malware_on_chain(
    eth_rpc: &str,
    private_key: &str,
    contract_address: &str,
    hostname: &str,
    device_uuid: &str,
    description: &str,
    _scan_id: &str,
) -> anyhow::Result<String> {
    use alloy::{
        providers::ProviderBuilder,
        signers::local::PrivateKeySigner,
        network::EthereumWallet,
        sol,
        primitives::FixedBytes,
    };
    use sha2::{Digest, Sha256};

    sol! {
        #[allow(missing_docs)]
        #[sol(rpc)]
        contract SecurityAudit {
            enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
            function logEvent(
                Severity severity,
                string calldata eventType,
                string calldata description,
                bytes32 dataHash,
                string calldata malwareFamily,
                string[] calldata iocHashes,
                string calldata agentName,
                string calldata srcIp
            ) external returns (uint256 id);
        }
    }

    // Firmante y proveedor
    let signer: PrivateKeySigner = private_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let rpc_url = eth_rpc.parse()?;

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url);

    let contract_addr: alloy::primitives::Address = contract_address.parse()?;
    let contract = SecurityAudit::new(contract_addr, provider);

    // Hash SHA256 del evento
    let mut hasher = Sha256::new();
    hasher.update(format!("MALWARE:{}:{}:{}", hostname, device_uuid, description).as_bytes());
    let hash_result = hasher.finalize();
    let data_hash: FixedBytes<32> = FixedBytes::from_slice(&hash_result);

    let agent_str = hostname.to_string();
    let src_ip    = device_uuid.to_string(); // UUID como identificador

    // Enviar transacción on-chain
    let tx_builder = contract.logEvent(
        SecurityAudit::Severity::HIGH,
        "MALWARE_DETECTED".to_string(),
        description.to_string(),
        data_hash,
        "ClamAV-Detection".to_string(),
        vec![],
        agent_str,
        src_ip,
    ).send().await?;

    let tx_hash: alloy::primitives::B256 = *tx_builder.tx_hash();
    Ok(format!("{}", tx_hash))
}

#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    pub agent: Option<String>,
}

/// Sirve el instalador MSI para que el usuario pueda descargarlo directamente desde el dashboard
async fn download_installer(
    Query(params): Query<DownloadQuery>,
) -> impl IntoResponse {
    let agent_type = params.agent.unwrap_or_else(|| "network".to_string());
    let file_path = if agent_type == "antivirus" {
        "packages/windows/cybersec-antivirus-agent.msi"
    } else {
        "packages/windows/cybersec-gateway-network.msi"
    };
    let filename = if agent_type == "antivirus" {
        "cybersec-antivirus-agent.msi"
    } else {
        "cybersec-gateway-network.msi"
    };

    match std::fs::read(file_path) {
        Ok(bytes) => {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename))
                .body(axum::body::Body::from(bytes))
                .unwrap()
        }
        Err(err) => {
            error!("Error leyendo MSI para descarga ({}): {:?}", file_path, err);
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from("Instalador MSI no encontrado. Asegurese de compilarlo antes."))
                .unwrap()
        }
    }
}

