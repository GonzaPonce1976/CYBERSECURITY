//! Cliente ARCAT para interactuar con los contratos Multicontratos SBT.
//!
//! Provee:
//! - Lookup de dispositivo en `ArcatRegistry` (hostname → uoContract + tokenId)
//! - Registro de auditorías en `UnidadOperativaSBT.logAudit()`
//! - Registro de nuevos dispositivos en `UnidadOperativaSBT.registerDevice()`
//! - Lectura de auditorías y ThreatScore por tokenId
//!
//! Usa el patrón `alloy::sol!` inline (igual que `audit.rs` existente) para
//! máxima compatibilidad sin cambios en las dependencias del proyecto.

use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

// ─── ABIs inline de los contratos ARCAT ──────────────────────────────────────

alloy::sol! {
    #[sol(rpc)]
    contract ArcatRegistry {
        function lookupByHostname(string calldata hostname)
            external view
            returns (address uoContract, uint256 tokenId, bool found);

        function lookupByUUID(string calldata uuid)
            external view
            returns (address uoContract, uint256 tokenId, bool found);

        function adminIndexDevice(
            address uoContract,
            uint256 tokenId,
            string memory hostname,
            string memory uuid,
            string memory dgCode,
            string memory uoCode
        ) external;

        function totalDevices() external view returns (uint256);
    }
}

alloy::sol! {
    #[sol(rpc)]
    contract UnidadOperativaSBT {
        enum DeviceType { SERVER, WORKSTATION, FIREWALL, SWITCH, PRINTER, ROUTER, OTHER }
        enum Severity   { INFO, LOW, MEDIUM, HIGH, CRITICAL }

        struct Device {
            string deviceName;
            string uuid;
            string hostname;
            DeviceType deviceType;
            bool isActive;
            uint256 registeredAt;
            address registeredBy;
        }

        struct AuditEntry {
            uint256 timestamp;
            string eventType;
            Severity severity;
            string description;
            bytes32 dataHash;
            string malwareFamily;
            string[] iocHashes;
            string srcIp;
            address reporter;
        }

        function registerDevice(
            address deviceOwner,
            string memory deviceName,
            string memory uuid,
            string memory hostname,
            DeviceType dType
        ) external returns (uint256 tokenId);

        function logAudit(
            uint256 tokenId,
            string calldata eventType,
            Severity severity,
            string calldata description,
            bytes32 dataHash,
            string calldata malware,
            string[] calldata iocs,
            string calldata srcIp
        ) external;

        function deactivateDevice(uint256 tokenId) external;

        function getDevice(uint256 tokenId) external view returns (Device memory);
        function getAudits(uint256 tokenId) external view returns (AuditEntry[] memory);
        function getLatestAudits(uint256 tokenId, uint256 count) external view returns (AuditEntry[] memory);
        function getAuditsCount(uint256 tokenId) external view returns (uint256);
        function getDevicesCount() external view returns (uint256);
        function getThreatScore(uint256 tokenId) external view returns (uint256);
        function getTokenByHostname(string calldata hostname) external view returns (uint256 tokenId, bool found);
        function getTokenByUUID(string calldata uuid) external view returns (uint256 tokenId, bool found);
        function ownerOf(uint256 tokenId) external view returns (address);

        function name() external view returns (string memory);
        function code() external view returns (string memory);
        function dgName() external view returns (string memory);
    }
}

alloy::sol! {
    #[sol(rpc)]
    contract DireccionGeneral {
        function dgName() external view returns (string memory);
        function dgCode() external view returns (string memory);
        function getUnidadesCount() external view returns (uint256);
        function getAllUnidades() external view returns (address[] memory);
        function getSummary()
            external view
            returns (
                string[] memory names,
                string[] memory codes,
                address[] memory addrs,
                bool[] memory actives,
                uint256[] memory deviceCounts
            );
    }
}

alloy::sol! {
    #[sol(rpc)]
    contract ArcatRoot {
        function isAuthorized(address dg) external view returns (bool);
        function getDireccionesCount() external view returns (uint256);
        function getAllDirecciones() external view returns (address[] memory);
        function gatewayAddress() external view returns (address);
    }
}

// ─── Structs de respuesta ────────────────────────────────────────────────────

/// Resultado de un lookup de dispositivo en el índice global
#[derive(Debug, Clone)]
pub struct DeviceLookup {
    pub uo_contract:  Address,
    pub token_id:     U256,
    pub found:        bool,
}

/// Información de un dispositivo para el API REST
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    pub token_id:      String,
    pub device_name:   String,
    pub uuid:          String,
    pub hostname:      String,
    pub device_type:   String,
    pub is_active:     bool,
    pub registered_at: String,
    pub uo_contract:   String,
    pub threat_score:  String,
    pub audits_count:  String,
}

/// Entrada de auditoría para el API REST
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditInfo {
    pub timestamp:     String,
    pub event_type:    String,
    pub severity:      String,
    pub description:   String,
    pub data_hash:     String,
    pub malware_family: String,
    pub ioc_hashes:    Vec<String>,
    pub src_ip:        String,
    pub reporter:      String,
}

// ─── Cliente ARCAT ────────────────────────────────────────────────────────────

/// Configuración del cliente ARCAT
pub struct ArcatClient {
    pub eth_rpc_url:        String,
    pub deployer_private_key: String,
    pub arcat_registry_addr:  String,
    pub arcat_root_addr:      String,
}

impl ArcatClient {
    pub fn new(
        eth_rpc_url: String,
        deployer_private_key: String,
        arcat_registry_addr: String,
        arcat_root_addr: String,
    ) -> Self {
        Self { eth_rpc_url, deployer_private_key, arcat_registry_addr, arcat_root_addr }
    }

    /// Retorna true si el cliente está configurado con contratos ARCAT
    pub fn is_configured(&self) -> bool {
        !self.arcat_registry_addr.is_empty()
            && self.arcat_registry_addr.starts_with("0x")
            && !self.arcat_root_addr.is_empty()
            && self.arcat_root_addr.starts_with("0x")
    }

    /// Parsea la URL RPC
    fn parse_rpc(&self) -> Result<url::Url> {
        self.eth_rpc_url.parse().map_err(|e| anyhow!("URL RPC inválida: {}", e))
    }

    /// Crea un provider de solo lectura
    fn read_provider(&self) -> Result<impl alloy::providers::Provider + Clone> {
        let url = self.parse_rpc()?;
        Ok(ProviderBuilder::new().connect_http(url))
    }

    /// Crea un provider con firma (escritura)
    fn write_provider(&self) -> Result<impl alloy::providers::Provider + Clone> {
        let signer: PrivateKeySigner = self.deployer_private_key.parse()
            .map_err(|e| anyhow!("Clave privada inválida: {}", e))?;
        let wallet = EthereumWallet::from(signer);
        let url = self.parse_rpc()?;
        Ok(ProviderBuilder::new().wallet(wallet).connect_http(url))
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Busca un dispositivo por hostname en el índice ArcatRegistry.
    /// Retorna { uo_contract, token_id, found }
    pub async fn lookup_by_hostname(&self, hostname: &str) -> Result<DeviceLookup> {
        let provider = self.read_provider()?;
        let addr: Address = self.arcat_registry_addr.parse()
            .map_err(|e| anyhow!("ArcatRegistry address inválida: {}", e))?;
        let registry = ArcatRegistry::new(addr, provider);

        let result = registry.lookupByHostname(hostname.to_string()).call().await
            .map_err(|e| anyhow!("lookupByHostname error: {}", e))?;

        Ok(DeviceLookup {
            uo_contract: result.uoContract,
            token_id:    result.tokenId,
            found:       result.found,
        })
    }

    /// Busca un dispositivo por UUID en el índice ArcatRegistry.
    pub async fn lookup_by_uuid(&self, uuid: &str) -> Result<DeviceLookup> {
        let provider = self.read_provider()?;
        let addr: Address = self.arcat_registry_addr.parse()
            .map_err(|e| anyhow!("ArcatRegistry address inválida: {}", e))?;
        let registry = ArcatRegistry::new(addr, provider);

        let result = registry.lookupByUUID(uuid.to_string()).call().await
            .map_err(|e| anyhow!("lookupByUUID error: {}", e))?;

        Ok(DeviceLookup {
            uo_contract: result.uoContract,
            token_id:    result.tokenId,
            found:       result.found,
        })
    }

    // ── Auditoría ─────────────────────────────────────────────────────────────

    /// Registra una auditoría de seguridad en el contrato UnidadOperativaSBT.
    ///
    /// # Parámetros
    /// - `uo_contract`:    Dirección del contrato UO (obtenida del lookup)
    /// - `token_id`:       ID del token SBT del dispositivo
    /// - `event_type`:     "MALWARE" | "INTRUSION" | "INTEGRITY" | "ANOMALY" | "COMPLIANCE"
    /// - `severity_str`:   "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    /// - `description`:    Descripción legible del evento
    /// - `payload_bytes`:  Bytes del payload completo para SHA256 (anti-duplicado)
    /// - `malware_family`: Nombre de la familia de malware (vacío si no aplica)
    /// - `ioc_hashes`:     Vec de hashes SHA256 de IoCs
    /// - `src_ip`:         IP de origen del ataque
    ///
    /// # Retorna
    /// El hash de la transacción blockchain si tiene éxito.
    pub async fn log_audit(
        &self,
        uo_contract:    &str,
        token_id:       U256,
        event_type:     &str,
        severity_str:   &str,
        description:    &str,
        payload_bytes:  &[u8],
        malware_family: &str,
        ioc_hashes:     Vec<String>,
        src_ip:         &str,
    ) -> Result<String> {
        let provider = self.write_provider()?;
        let addr: Address = uo_contract.parse()
            .map_err(|e| anyhow!("UO contract address inválida: {}", e))?;
        let contract = UnidadOperativaSBT::new(addr, provider);

        // Mapear severidad
        let severity = match severity_str.to_uppercase().as_str() {
            "CRITICAL" => UnidadOperativaSBT::Severity::CRITICAL,
            "HIGH"     => UnidadOperativaSBT::Severity::HIGH,
            "MEDIUM"   => UnidadOperativaSBT::Severity::MEDIUM,
            "LOW"      => UnidadOperativaSBT::Severity::LOW,
            _          => UnidadOperativaSBT::Severity::INFO,
        };

        // Calcular SHA256 del payload completo
        let mut hasher = Sha256::new();
        hasher.update(payload_bytes);
        let hash_result = hasher.finalize();
        let data_hash: FixedBytes<32> = FixedBytes::from_slice(&hash_result);

        let tx = contract.logAudit(
            token_id,
            event_type.to_string(),
            severity,
            description.to_string(),
            data_hash,
            malware_family.to_string(),
            ioc_hashes,
            src_ip.to_string(),
        ).send().await
        .map_err(|e| anyhow!("logAudit transacción fallida: {}", e))?;

        let tx_hash = format!("{}", tx.tx_hash());
        tracing::info!(
            "✅ [ARCAT] Auditoría registrada on-chain | UO={} token={} tx={}",
            uo_contract, token_id, tx_hash
        );
        Ok(tx_hash)
    }

    /// Pipeline completo Wazuh → ARCAT:
    ///  1. Lookup del dispositivo por hostname en ArcatRegistry
    ///  2. Si existe → llama a `logAudit()` en su UnidadOperativaSBT
    ///  3. Retorna { tx_hash, token_id, uo_contract, found }
    pub async fn route_wazuh_alert(
        &self,
        hostname:       &str,
        event_type:     &str,
        severity_str:   &str,
        description:    &str,
        malware_family: &str,
        ioc_hashes:     Vec<String>,
        src_ip:         &str,
        alert_id:       &str,
    ) -> Result<serde_json::Value> {
        // 1. Lookup
        let lookup = self.lookup_by_hostname(hostname).await?;

        if !lookup.found {
            tracing::warn!(
                "⚠️ [ARCAT] Dispositivo '{}' no encontrado en ArcatRegistry. Alerta no tokenizada.",
                hostname
            );
            return Ok(serde_json::json!({
                "status": "not_found",
                "message": format!("Dispositivo '{}' no registrado en ARCAT. Alerta solo guardada en SecurityAudit global.", hostname),
                "hostname": hostname,
                "token_id": null,
                "uo_contract": null,
                "tx_hash": null
            }));
        }

        let uo_contract = format!("{}", lookup.uo_contract);
        let token_id    = lookup.token_id;

        // 2. Construir payload SHA256 = descripción + hostname + alert_id
        let payload_str = format!("{}|{}|{}|{}", description, hostname, alert_id, event_type);

        // 3. Registrar auditoría on-chain
        match self.log_audit(
            &uo_contract,
            token_id,
            event_type,
            severity_str,
            description,
            payload_str.as_bytes(),
            malware_family,
            ioc_hashes,
            src_ip,
        ).await {
            Ok(tx_hash) => {
                Ok(serde_json::json!({
                    "status": "ok",
                    "message": "Alerta tokenizada y registrada on-chain en ARCAT",
                    "hostname": hostname,
                    "token_id": token_id.to_string(),
                    "uo_contract": uo_contract,
                    "tx_hash": tx_hash
                }))
            }
            Err(e) => {
                // Si falla por hash duplicado (alerta ya procesada), es OK
                if e.to_string().contains("ya registrado") || e.to_string().contains("already registered") {
                    tracing::info!("ℹ️ [ARCAT] Alerta '{}' ya registrada anteriormente (hash duplicado)", alert_id);
                    Ok(serde_json::json!({
                        "status": "duplicate",
                        "message": "Esta alerta ya fue registrada previamente en ARCAT",
                        "hostname": hostname,
                        "token_id": token_id.to_string(),
                        "uo_contract": uo_contract,
                        "tx_hash": null
                    }))
                } else {
                    Err(e)
                }
            }
        }
    }

    // ── Lectura de Datos ──────────────────────────────────────────────────────

    /// Obtiene información completa de un dispositivo por su contrato UO y tokenId
    pub async fn get_device_info(
        &self,
        uo_contract: &str,
        token_id:    U256,
    ) -> Result<DeviceInfo> {
        let provider = self.read_provider()?;
        let addr: Address = uo_contract.parse()
            .map_err(|e| anyhow!("UO address inválida: {}", e))?;
        let contract = UnidadOperativaSBT::new(addr.clone(), provider.clone());

        let dev    = contract.getDevice(token_id).call().await
            .map_err(|e| anyhow!("getDevice error: {}", e))?;
        let score  = contract.getThreatScore(token_id).call().await
            .unwrap_or(U256::ZERO);
        let count  = contract.getAuditsCount(token_id).call().await
            .unwrap_or(U256::ZERO);

        let device_type_str = match dev.deviceType {
            UnidadOperativaSBT::DeviceType::SERVER      => "SERVER",
            UnidadOperativaSBT::DeviceType::WORKSTATION => "WORKSTATION",
            UnidadOperativaSBT::DeviceType::FIREWALL    => "FIREWALL",
            UnidadOperativaSBT::DeviceType::SWITCH      => "SWITCH",
            UnidadOperativaSBT::DeviceType::PRINTER     => "PRINTER",
            UnidadOperativaSBT::DeviceType::ROUTER      => "ROUTER",
            _                                           => "OTHER",
        };

        Ok(DeviceInfo {
            token_id:      token_id.to_string(),
            device_name:   dev.deviceName,
            uuid:          dev.uuid,
            hostname:      dev.hostname,
            device_type:   device_type_str.to_string(),
            is_active:     dev.isActive,
            registered_at: chrono::DateTime::from_timestamp(dev.registeredAt.to::<i64>(), 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            uo_contract:   uo_contract.to_string(),
            threat_score:  score.to_string(),
            audits_count:  count.to_string(),
        })
    }

    /// Obtiene el número total de dispositivos registrados en una Unidad Operativa.
    pub async fn get_device_count(&self, uo_contract: &str) -> Result<u64> {
        let provider = self.read_provider()?;
        let addr: Address = uo_contract.parse()
            .map_err(|e| anyhow!("UO contract address inválida: {}", e))?;
        let contract = UnidadOperativaSBT::new(addr, provider);
        let count = contract.getDevicesCount().call().await
            .map_err(|e| anyhow!("getDevicesCount error: {}", e))?;
        Ok(count.to::<u64>())
    }

    /// Obtiene las últimas N auditorías de un dispositivo
    pub async fn get_latest_audits(
        &self,
        uo_contract: &str,
        token_id:    U256,
        count:       u64,
    ) -> Result<Vec<AuditInfo>> {
        let provider = self.read_provider()?;
        let addr: Address = uo_contract.parse()
            .map_err(|e| anyhow!("UO address inválida: {}", e))?;
        let contract = UnidadOperativaSBT::new(addr, provider);

        let entries = contract.getLatestAudits(token_id, U256::from(count)).call().await
            .map_err(|e| anyhow!("getLatestAudits error: {}", e))?;

        let audits = entries.into_iter().map(|e| {
            let severity_str = match e.severity {
                UnidadOperativaSBT::Severity::CRITICAL => "CRITICAL",
                UnidadOperativaSBT::Severity::HIGH     => "HIGH",
                UnidadOperativaSBT::Severity::MEDIUM   => "MEDIUM",
                UnidadOperativaSBT::Severity::LOW      => "LOW",
                _                                      => "INFO",
            };
            AuditInfo {
                timestamp:      chrono::DateTime::from_timestamp(e.timestamp.to::<i64>(), 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                event_type:     e.eventType,
                severity:       severity_str.to_string(),
                description:    e.description,
                data_hash:      format!("{}", e.dataHash),
                malware_family: e.malwareFamily,
                ioc_hashes:     e.iocHashes,
                src_ip:         e.srcIp,
                reporter:       format!("{}", e.reporter),
            }
        }).collect();

        Ok(audits)
    }

    /// Total de dispositivos en el índice global
    pub async fn get_total_devices(&self) -> Result<u64> {
        let provider = self.read_provider()?;
        let addr: Address = self.arcat_registry_addr.parse()
            .map_err(|e| anyhow!("ArcatRegistry address inválida: {}", e))?;
        let registry = ArcatRegistry::new(addr, provider);
        let total = registry.totalDevices().call().await
            .map_err(|e| anyhow!("totalDevices error: {}", e))?;
        Ok(total.to::<u64>())
    }
}
