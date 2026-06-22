//! Rutas ARCAT — /api/arcat
//!
//! Endpoints para consultar la jerarquía de contratos ARCAT Multicontratos SBT:
//!
//!   GET /api/arcat/device/:hostname        → Info del dispositivo + threat score
//!   GET /api/arcat/device/uuid/:uuid       → Lookup por UUID
//!   GET /api/arcat/unit/:address/audits    → Historial de auditorías de una UO
//!   GET /api/arcat/unit/:address/devices   → Inventario de dispositivos de una UO
//!   GET /api/arcat/overview                → Estado global del sistema ARCAT
//!   POST /api/arcat/audit                  → Registrar auditoría manual on-chain

use axum::{
    extract::{Path, State},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::state::AppState;
use crate::clients::arcat::ArcatClient;
use alloy::primitives::U256;

// ─── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/device/{hostname}",        get(get_device_by_hostname))
        .route("/device/uuid/{uuid}",       get(get_device_by_uuid))
        .route("/unit/{address}/audits",    get(get_unit_audits))
        .route("/unit/{address}/devices",   get(get_unit_devices))
        .route("/overview",                 get(get_overview))
        .route("/audit",                    post(post_manual_audit))
}

// ─── Helper: construir ArcatClient desde AppState ────────────────────────────

fn make_arcat_client(state: &AppState) -> ArcatClient {
    ArcatClient::new(
        state.eth_rpc_url.clone(),
        state.deployer_private_key.clone(),
        state.contract_arcat_registry.clone(),
        state.contract_arcat_root.clone(),
    )
}

// ─── GET /api/arcat/device/:hostname ─────────────────────────────────────────
//
// Lookup de dispositivo por hostname + ThreatScore + auditorías recientes.
// Ejemplo: GET /api/arcat/device/dgr-bd-01

async fn get_device_by_hostname(
    State(state): State<Arc<AppState>>,
    Path(hostname): Path<String>,
) -> Json<Value> {
    let client = make_arcat_client(&state);

    if !client.is_configured() {
        return Json(json!({
            "status": "not_configured",
            "message": "Contratos ARCAT no configurados. Ejecute deploy_arcat.js primero.",
            "hostname": hostname
        }));
    }

    // 1. Lookup en ArcatRegistry
    let lookup = match client.lookup_by_hostname(&hostname).await {
        Ok(l)  => l,
        Err(e) => {
            tracing::error!("❌ [ARCAT] lookup_by_hostname '{}': {}", hostname, e);
            return Json(json!({
                "status": "error",
                "message": format!("Error consultando el registro ARCAT: {}", e),
                "hostname": hostname
            }));
        }
    };

    if !lookup.found {
        return Json(json!({
            "status": "not_found",
            "message": format!("Dispositivo '{}' no registrado en la red ARCAT", hostname),
            "hostname": hostname
        }));
    }

    let uo_addr   = format!("{}", lookup.uo_contract);
    let token_id  = lookup.token_id;

    // 2. Obtener info del dispositivo
    let dev_info = match client.get_device_info(&uo_addr, token_id).await {
        Ok(d)  => d,
        Err(e) => {
            return Json(json!({
                "status": "error",
                "message": format!("Error obteniendo datos del dispositivo: {}", e),
                "hostname": hostname
            }));
        }
    };

    // 3. Últimas 10 auditorías
    let recent_audits = client.get_latest_audits(&uo_addr, token_id, 10).await
        .unwrap_or_default();

    Json(json!({
        "status": "ok",
        "hostname": hostname,
        "device": dev_info,
        "recent_audits": recent_audits,
        "threat_level": threat_level_from_score(&dev_info.threat_score)
    }))
}

// ─── GET /api/arcat/device/uuid/:uuid ────────────────────────────────────────

async fn get_device_by_uuid(
    State(state): State<Arc<AppState>>,
    Path(uuid): Path<String>,
) -> Json<Value> {
    let client = make_arcat_client(&state);

    if !client.is_configured() {
        return Json(json!({
            "status": "not_configured",
            "message": "Contratos ARCAT no configurados."
        }));
    }

    let lookup = match client.lookup_by_uuid(&uuid).await {
        Ok(l)  => l,
        Err(e) => {
            return Json(json!({
                "status": "error",
                "message": format!("Error en lookup por UUID: {}", e)
            }));
        }
    };

    if !lookup.found {
        return Json(json!({
            "status": "not_found",
            "message": format!("UUID '{}' no registrado en la red ARCAT", uuid)
        }));
    }

    let uo_addr  = format!("{}", lookup.uo_contract);
    let token_id = lookup.token_id;

    match client.get_device_info(&uo_addr, token_id).await {
        Ok(dev) => Json(json!({
            "status": "ok",
            "uuid": uuid,
            "device": dev,
            "threat_level": threat_level_from_score(&dev.threat_score)
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": format!("Error obteniendo datos del dispositivo: {}", e)
        }))
    }
}

// ─── GET /api/arcat/unit/:address/audits ─────────────────────────────────────
//
// Historial de auditorías de todos los dispositivos de una UnidadOperativaSBT.
// Ejemplo: GET /api/arcat/unit/0xABC.../audits

async fn get_unit_audits(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Json<Value> {
    let client = make_arcat_client(&state);

    if !client.is_configured() {
        return Json(json!({
            "status": "not_configured",
            "message": "Contratos ARCAT no configurados."
        }));
    }

    // Obtener cantidad de dispositivos en la UO
    let provider = match client.eth_rpc_url.parse::<url::Url>() {
        Ok(url) => alloy::providers::ProviderBuilder::new().connect_http(url),
        Err(e)  => {
            return Json(json!({ "status": "error", "message": format!("RPC URL inválida: {}", e) }));
        }
    };

    let uo_addr: alloy::primitives::Address = match address.parse() {
        Ok(a)  => a,
        Err(e) => {
            return Json(json!({ "status": "error", "message": format!("Dirección UO inválida: {}", e) }));
        }
    };

    // Leer count de dispositivos
    alloy::sol! {
        #[sol(rpc)]
        contract UOReader {
            function getDevicesCount() external view returns (uint256);
            function name() external view returns (string memory);
            function code() external view returns (string memory);
            function dgName() external view returns (string memory);
        }
    }
    let uo_reader = UOReader::new(uo_addr, provider);

    let uo_name  = uo_reader.name().call().await.unwrap_or_default();
    let uo_code  = uo_reader.code().call().await.unwrap_or_default();
    let dg_name  = uo_reader.dgName().call().await.unwrap_or_default();
    let dev_count = uo_reader.getDevicesCount().call().await.unwrap_or(U256::ZERO);
    let count_u64 = dev_count.to::<u64>();

    // Recolectar auditorías de los últimos 20 dispositivos (paginación futura)
    let limit = count_u64.min(20);
    let mut all_audits: Vec<Value> = Vec::new();

    for token_id in 0..limit {
        let tid = U256::from(token_id);
        if let Ok(audits) = client.get_latest_audits(&address, tid, 5).await {
            for audit in audits {
                all_audits.push(json!({
                    "token_id": token_id,
                    "audit": audit
                }));
            }
        }
    }

    // Ordenar por timestamp descendente (más recientes primero)
    all_audits.sort_by(|a, b| {
        let ta = a["audit"]["timestamp"].as_str().unwrap_or("");
        let tb = b["audit"]["timestamp"].as_str().unwrap_or("");
        tb.cmp(ta)
    });

    Json(json!({
        "status": "ok",
        "uo_contract": address,
        "uo_name": uo_name,
        "uo_code": uo_code,
        "dg_name": dg_name,
        "devices_count": count_u64,
        "audits_shown": all_audits.len(),
        "audits": all_audits
    }))
}

// ─── GET /api/arcat/unit/:address/devices ────────────────────────────────────

async fn get_unit_devices(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Json<Value> {
    let client = make_arcat_client(&state);

    if !client.is_configured() {
        return Json(json!({
            "status": "not_configured",
            "message": "Contratos ARCAT no configurados."
        }));
    }

    let provider = match client.eth_rpc_url.parse::<url::Url>() {
        Ok(url) => alloy::providers::ProviderBuilder::new().connect_http(url),
        Err(e)  => {
            return Json(json!({ "status": "error", "message": format!("RPC URL inválida: {}", e) }));
        }
    };

    let uo_addr: alloy::primitives::Address = match address.parse() {
        Ok(a)  => a,
        Err(_) => {
            return Json(json!({ "status": "error", "message": "Dirección UO inválida" }));
        }
    };

    alloy::sol! {
        #[sol(rpc)]
        contract UOReader2 {
            function getDevicesCount() external view returns (uint256);
            function name() external view returns (string memory);
            function code() external view returns (string memory);
            function dgName() external view returns (string memory);
        }
    }
    let uo_reader = UOReader2::new(uo_addr, provider);
    let uo_name  = uo_reader.name().call().await.unwrap_or_default();
    let uo_code  = uo_reader.code().call().await.unwrap_or_default();
    let dg_name  = uo_reader.dgName().call().await.unwrap_or_default();
    let dev_count = uo_reader.getDevicesCount().call().await.unwrap_or(U256::ZERO);
    let count_u64 = dev_count.to::<u64>();

    let limit = count_u64.min(50); // máximo 50 dispositivos por llamada
    let mut devices: Vec<Value> = Vec::new();

    for token_id in 0..limit {
        let tid = U256::from(token_id);
        match client.get_device_info(&address, tid).await {
            Ok(dev) => {
                let threat_level = threat_level_from_score(&dev.threat_score);
                devices.push(json!({
                    "device": dev,
                    "threat_level": threat_level
                }));
            }
            Err(e) => {
                tracing::warn!("⚠️ [ARCAT] get_device_info token={} error: {}", token_id, e);
            }
        }
    }

    Json(json!({
        "status": "ok",
        "uo_contract": address,
        "uo_name": uo_name,
        "uo_code": uo_code,
        "dg_name": dg_name,
        "total_devices": count_u64,
        "devices": devices
    }))
}

// ─── GET /api/arcat/overview ──────────────────────────────────────────────────
//
// Resumen global del sistema ARCAT: configuración, total de dispositivos,
// contratos activos.

async fn get_overview(State(state): State<Arc<AppState>>) -> Json<Value> {
    let client = make_arcat_client(&state);

    let configured = client.is_configured();
    let total_devices = if configured {
        client.get_total_devices().await.unwrap_or(0)
    } else {
        0
    };

    Json(json!({
        "status": "ok",
        "arcat": {
            "configured": configured,
            "arcat_root":     state.contract_arcat_root,
            "arcat_registry": state.contract_arcat_registry,
            "dg_rentas":      state.contract_dg_dgr,
            "dg_catastro":    state.contract_dg_dgc,
            "dg_dgrpi":       state.contract_dg_dgrpi,
            "dg_staff":       state.contract_dg_staff,
        },
        "stats": {
            "total_indexed_devices": total_devices,
            "blockchain_rpc": state.eth_rpc_url,
        },
        "unidades": {
            "dgr": {
                "uo_recaudacion":   state.contract_uo_rec,
                "uo_fiscalizacion": state.contract_uo_fis,
            },
            "dgc": {
                "uo_saneamiento":         state.contract_uo_san,
                "uo_cartografia":         state.contract_uo_car,
                "uo_registro_territorial": state.contract_uo_reg,
            },
            "dgrpi": {
                "uo_registracion":  state.contract_uo_rin,
                "uo_publicidad":    state.contract_uo_pub,
            },
            "staff": {
                "uo_administracion": state.contract_uo_adm,
                "uo_capital_humano": state.contract_uo_rhh,
                "uo_tecnologias":    state.contract_uo_tec,
                "uo_juridicos":      state.contract_uo_jur,
                "uo_gre":            state.contract_uo_gre,
                "uo_auditoria":      state.contract_uo_aud,
                "uo_secretaria":     state.contract_uo_sec,
            }
        }
    }))
}

// ─── POST /api/arcat/audit ────────────────────────────────────────────────────
//
// Registra una auditoría manual on-chain en el dispositivo indicado.
// Body JSON:
// {
//   "hostname": "dgr-bd-01",
//   "event_type": "MALWARE",
//   "severity": "CRITICAL",
//   "description": "Detección manual de Emotet",
//   "malware_family": "Emotet",
//   "ioc_hashes": ["sha256:abc123"],
//   "src_ip": "192.168.1.100"
// }

#[derive(Debug, Deserialize)]
pub struct ManualAuditRequest {
    pub hostname:       String,
    pub event_type:     String,
    pub severity:       String,
    pub description:    String,
    pub malware_family: Option<String>,
    pub ioc_hashes:     Option<Vec<String>>,
    pub src_ip:         Option<String>,
}

async fn post_manual_audit(
    State(state): State<Arc<AppState>>,
    axum::extract::Json(req): axum::extract::Json<ManualAuditRequest>,
) -> Json<Value> {
    let client = make_arcat_client(&state);

    if !client.is_configured() {
        return Json(json!({
            "status": "not_configured",
            "message": "Contratos ARCAT no configurados. Ejecute deploy_arcat.js primero."
        }));
    }

    let alert_id = format!("manual-{}", chrono::Utc::now().timestamp());

    match client.route_wazuh_alert(
        &req.hostname,
        &req.event_type,
        &req.severity,
        &req.description,
        req.malware_family.as_deref().unwrap_or(""),
        req.ioc_hashes.unwrap_or_default(),
        req.src_ip.as_deref().unwrap_or(""),
        &alert_id,
    ).await {
        Ok(result) => Json(result),
        Err(e) => Json(json!({
            "status": "error",
            "message": format!("Error registrando auditoría on-chain: {}", e)
        }))
    }
}

// ─── Helper: Threat Level ─────────────────────────────────────────────────────

fn threat_level_from_score(score_str: &str) -> &'static str {
    let score: u64 = score_str.parse().unwrap_or(0);
    match score {
        0           => "CLEAN",
        1..=20      => "LOW",
        21..=60     => "MEDIUM",
        61..=150    => "HIGH",
        _           => "CRITICAL",
    }
}
