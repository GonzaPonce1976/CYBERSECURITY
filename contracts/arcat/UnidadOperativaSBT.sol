// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title UnidadOperativaSBT
 * @notice Contrato ERC-721 Soulbound (SBT) que representa una Unidad Operativa de ARCAT.
 * @dev   Cada dispositivo físico (servidor, firewall, workstation, switch, etc.)
 *        se acuña como un token ERC-721 NO TRANSFERIBLE (Soulbound).
 *        Las auditorías de seguridad de Wazuh/Gateway se registran asociadas
 *        al tokenId del dispositivo, garantizando trazabilidad inmutable.
 *
 *        Implementa ERC-721 de forma minimal (sin dependencias de OpenZeppelin)
 *        para compatibilidad máxima y control total del comportamiento Soulbound.
 */
contract UnidadOperativaSBT {

    // ─── ERC-721 Mínimo ──────────────────────────────────────────────────────

    string public name;
    string public symbol;

    /// Código interno de la unidad (ej: "UO-REC", "UO-CAT")
    string public code;

    /// Nombre de la Dirección General padre
    string public dgName;

    uint256 private _tokenIdCounter;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;

    // ─── Tipos de Dispositivo ─────────────────────────────────────────────────

    enum DeviceType { SERVER, WORKSTATION, FIREWALL, SWITCH, PRINTER, ROUTER, OTHER }
    enum Severity   { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    // ─── Estructuras ──────────────────────────────────────────────────────────

    /**
     * @dev Información inmutable del dispositivo físico (inventario).
     */
    struct Device {
        string     deviceName;   // Ej: "Servidor DGR-BD-01"
        string     uuid;         // UUID de hardware (BIOS / MAC Address)
        string     hostname;     // Hostname Wazuh (agentName)
        DeviceType deviceType;
        bool       isActive;
        uint256    registeredAt;
        address    registeredBy; // Gateway o admin que lo registró
    }

    /**
     * @dev Registro de un evento de auditoría asociado a un dispositivo.
     */
    struct AuditEntry {
        uint256   timestamp;
        string    eventType;     // "MALWARE" | "INTRUSION" | "INTEGRITY" | "ANOMALY" | "COMPLIANCE"
        Severity  severity;
        string    description;
        bytes32   dataHash;      // SHA256 del payload Wazuh completo
        string    malwareFamily; // Familia de malware (ej: "Emotet") — vacío si no aplica
        string[]  iocHashes;     // Hashes SHA256 de IoCs
        string    srcIp;         // IP de origen del ataque
        address   reporter;      // Dirección del gateway que reportó
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// Admin (owner) de esta unidad — normalmente el deployer/DG admin
    address public immutable owner;

    /// Dirección del Rust Gateway autorizado a escribir auditorías
    address public gatewayAddress;

    /// Mapeo tokenId → Device
    mapping(uint256 => Device) private _devices;

    /// Mapeo tokenId → lista de AuditEntry
    mapping(uint256 => AuditEntry[]) private _audits;

    /// Mapeo hostname → tokenId (para lookup rápido desde el Gateway)
    mapping(string => uint256) private _hostnameToToken;
    mapping(string => bool)    private _hostnameExists;

    /// Mapeo uuid → tokenId
    mapping(string => uint256) private _uuidToToken;
    mapping(string => bool)    private _uuidExists;

    /// Mapeo dataHash → bool para evitar duplicados de auditoría
    mapping(bytes32 => bool) public registeredHashes;

    // ─── Eventos ERC-721 ──────────────────────────────────────────────────────

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    // ─── Eventos de Negocio ───────────────────────────────────────────────────

    event DeviceRegistered(
        uint256   indexed tokenId,
        string            deviceName,
        string            uuid,
        string            hostname,
        DeviceType        deviceType,
        uint256           timestamp
    );

    event DeviceDeactivated(
        uint256 indexed tokenId,
        uint256         timestamp
    );

    event AuditLogged(
        uint256  indexed tokenId,
        Severity indexed severity,
        string           eventType,
        bytes32          dataHash,
        uint256          timestamp
    );

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "UO-SBT: solo el owner");
        _;
    }

    modifier onlyGatewayOrOwner() {
        require(
            msg.sender == gatewayAddress || msg.sender == owner,
            "UO-SBT: solo gateway o owner"
        );
        _;
    }

    modifier tokenExists(uint256 tokenId) {
        require(_owners[tokenId] != address(0), "UO-SBT: token no existe");
        _;
    }

    modifier deviceActive(uint256 tokenId) {
        require(_devices[tokenId].isActive, "UO-SBT: dispositivo inactivo");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param _name    Nombre completo de la unidad (ej: "De Recaudación")
     * @param _code    Código único (ej: "UO-REC")
     * @param _dgName  Nombre de la Dirección General padre
     * @param _gateway Dirección del Rust Gateway
     */
    constructor(
        string  memory _name,
        string  memory _code,
        string  memory _dgName,
        address        _gateway
    ) {
        require(bytes(_name).length > 0,  "UO-SBT: nombre requerido");
        require(bytes(_code).length > 0,  "UO-SBT: codigo requerido");
        require(_gateway != address(0),   "UO-SBT: gateway invalido");

        name           = _name;
        symbol         = _code;
        code           = _code;
        dgName         = _dgName;
        gatewayAddress = _gateway;
        owner          = msg.sender;
    }

    // ─── Registro de Dispositivos ─────────────────────────────────────────────

    /**
     * @notice Acuña un nuevo token SBT para un dispositivo físico.
     * @param deviceOwner Dirección Ethereum del custodio del dispositivo
     * @param deviceName  Nombre descriptivo del equipo
     * @param uuid        UUID de hardware único (BIOS o MAC)
     * @param hostname    Hostname del agente Wazuh
     * @param dType       Tipo de dispositivo (enum DeviceType)
     * @return tokenId    El ID del token acuñado
     */
    function registerDevice(
        address       deviceOwner,
        string memory deviceName,
        string memory uuid,
        string memory hostname,
        DeviceType    dType
    ) external onlyGatewayOrOwner returns (uint256 tokenId) {
        require(deviceOwner != address(0),      "UO-SBT: owner invalido");
        require(bytes(deviceName).length > 0,   "UO-SBT: nombre requerido");
        require(bytes(uuid).length > 0,         "UO-SBT: uuid requerido");
        require(bytes(hostname).length > 0,     "UO-SBT: hostname requerido");

        if (_uuidExists[uuid]) {
            tokenId = _uuidToToken[uuid];
            
            string memory oldHostname = _devices[tokenId].hostname;
            if (keccak256(bytes(oldHostname)) != keccak256(bytes(hostname))) {
                require(!_hostnameExists[hostname], "UO-SBT: hostname ya registrado");
                _hostnameExists[oldHostname] = false;
                _hostnameToToken[oldHostname] = 0;
            }
            
            _devices[tokenId].deviceName = deviceName;
            _devices[tokenId].hostname = hostname;
            _devices[tokenId].deviceType = dType;
            _devices[tokenId].isActive = true;
            _devices[tokenId].registeredAt = block.timestamp;
            _devices[tokenId].registeredBy = msg.sender;
            
            _hostnameToToken[hostname] = tokenId;
            _hostnameExists[hostname] = true;
            
            if (_owners[tokenId] != deviceOwner) {
                address oldOwner = _owners[tokenId];
                if (_balances[oldOwner] > 0) {
                    _balances[oldOwner]--;
                }
                _owners[tokenId] = deviceOwner;
                _balances[deviceOwner]++;
                emit Transfer(oldOwner, deviceOwner, tokenId);
            }
            
            emit DeviceRegistered(tokenId, deviceName, uuid, hostname, dType, block.timestamp);
            return tokenId;
        }

        require(!_hostnameExists[hostname],     "UO-SBT: hostname ya registrado");

        tokenId = _tokenIdCounter++;

        _owners[tokenId]    = deviceOwner;
        _balances[deviceOwner]++;

        _devices[tokenId] = Device({
            deviceName:   deviceName,
            uuid:         uuid,
            hostname:     hostname,
            deviceType:   dType,
            isActive:     true,
            registeredAt: block.timestamp,
            registeredBy: msg.sender
        });

        _hostnameToToken[hostname] = tokenId;
        _hostnameExists[hostname]  = true;
        _uuidToToken[uuid]         = tokenId;
        _uuidExists[uuid]          = true;

        emit Transfer(address(0), deviceOwner, tokenId);
        emit DeviceRegistered(tokenId, deviceName, uuid, hostname, dType, block.timestamp);
    }

    /**
     * @notice Desactiva un dispositivo (ej: dado de baja, robado, reemplazado).
     * @dev El token sigue existiendo (trazabilidad histórica) pero se marca inactivo.
     */
    function deactivateDevice(uint256 tokenId)
        external
        onlyGatewayOrOwner
        tokenExists(tokenId)
    {
        _devices[tokenId].isActive = false;
        emit DeviceDeactivated(tokenId, block.timestamp);
    }

    // ─── Registro de Auditorías ───────────────────────────────────────────────

    /**
     * @notice Registra un evento de auditoría de seguridad para un dispositivo.
     * @param tokenId     Token del dispositivo afectado
     * @param eventType   Tipo de evento ("MALWARE", "INTRUSION", "INTEGRITY", etc.)
     * @param severity    Nivel de severidad
     * @param description Descripción legible del evento
     * @param dataHash    Hash SHA256 del payload completo de Wazuh (anti-duplicados)
     * @param malware     Familia de malware identificada (vacío si no aplica)
     * @param iocs        Lista de hashes SHA256 de IoCs
     * @param srcIp       IP de origen del ataque
     */
    function logAudit(
        uint256         tokenId,
        string calldata eventType,
        Severity        severity,
        string calldata description,
        bytes32         dataHash,
        string calldata malware,
        string[] calldata iocs,
        string calldata srcIp
    ) external onlyGatewayOrOwner tokenExists(tokenId) deviceActive(tokenId) {
        require(bytes(eventType).length > 0,   "UO-SBT: eventType requerido");
        require(bytes(description).length > 0, "UO-SBT: descripcion requerida");
        require(!registeredHashes[dataHash],   "UO-SBT: evento ya registrado");

        registeredHashes[dataHash] = true;

        _audits[tokenId].push(AuditEntry({
            timestamp:    block.timestamp,
            eventType:    eventType,
            severity:     severity,
            description:  description,
            dataHash:     dataHash,
            malwareFamily: malware,
            iocHashes:    iocs,
            srcIp:        srcIp,
            reporter:     msg.sender
        }));

        emit AuditLogged(tokenId, severity, eventType, dataHash, block.timestamp);
    }

    // ─── Consultas de Dispositivos ────────────────────────────────────────────

    /// Total de dispositivos/tokens registrados en esta unidad
    function getDevicesCount() external view returns (uint256) {
        return _tokenIdCounter;
    }

    /// Información completa del dispositivo por tokenId
    function getDevice(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (Device memory)
    {
        return _devices[tokenId];
    }

    /// Lookup por hostname → tokenId
    function getTokenByHostname(string calldata hostname)
        external
        view
        returns (uint256 tokenId, bool found)
    {
        found   = _hostnameExists[hostname];
        tokenId = found ? _hostnameToToken[hostname] : 0;
    }

    /// Lookup por UUID → tokenId
    function getTokenByUUID(string calldata uuid)
        external
        view
        returns (uint256 tokenId, bool found)
    {
        found   = _uuidExists[uuid];
        tokenId = found ? _uuidToToken[uuid] : 0;
    }

    /// Inventario completo de dispositivos (paginado para evitar límite de gas)
    function getDevices(uint256 from, uint256 count)
        external
        view
        returns (Device[] memory devices, uint256[] memory tokenIds)
    {
        uint256 total = _tokenIdCounter;
        if (from >= total) {
            return (new Device[](0), new uint256[](0));
        }
        uint256 end = from + count;
        if (end > total) end = total;
        uint256 len = end - from;

        devices  = new Device[](len);
        tokenIds = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            uint256 tid  = from + i;
            devices[i]   = _devices[tid];
            tokenIds[i]  = tid;
        }
    }

    // ─── Consultas de Auditorías ──────────────────────────────────────────────

    /// Total de auditorías de un dispositivo
    function getAuditsCount(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (uint256)
    {
        return _audits[tokenId].length;
    }

    /// Historial completo de auditorías de un dispositivo
    function getAudits(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (AuditEntry[] memory)
    {
        return _audits[tokenId];
    }

    /// Últimas N auditorías de un dispositivo
    function getLatestAudits(uint256 tokenId, uint256 count)
        external
        view
        tokenExists(tokenId)
        returns (AuditEntry[] memory)
    {
        AuditEntry[] storage all = _audits[tokenId];
        uint256 total = all.length;
        if (count > total) count = total;

        AuditEntry[] memory result = new AuditEntry[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = all[total - count + i];
        }
        return result;
    }

    /**
     * @notice Calcula el Threat Score dinámico de un dispositivo.
     * @dev   Pondera las auditorías de las últimas 24h según severidad.
     *        Score 0 = limpio, Score > 100 = crítico.
     * @param tokenId Token del dispositivo
     * @return score  Puntaje de amenaza (0–500+)
     */
    function getThreatScore(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (uint256 score)
    {
        AuditEntry[] storage all = _audits[tokenId];
        uint256 cutoff = block.timestamp - 24 hours;
        uint256[5] memory weights = [uint256(1), 5, 15, 40, 100]; // INFO→CRITICAL

        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].timestamp >= cutoff) {
                uint256 idx = uint256(all[i].severity);
                score += weights[idx];
            }
        }
    }

    // ─── ERC-721 Interfaz (Soulbound — NO transferible) ───────────────────────

    /// @notice Devuelve el owner de un token
    function ownerOf(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (address)
    {
        return _owners[tokenId];
    }

    /// @notice Devuelve el balance de tokens de una dirección
    function balanceOf(address account) external view returns (uint256) {
        require(account != address(0), "UO-SBT: cuenta invalida");
        return _balances[account];
    }

    /**
     * @dev SOULBOUND: transferencia completamente deshabilitada.
     *      Cualquier intento revierte con mensaje descriptivo.
     */
    function transferFrom(address, address, uint256) external pure {
        revert("UO-SBT: Token Soulbound - no transferible");
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert("UO-SBT: Token Soulbound - no transferible");
    }

    function safeTransferFrom(address, address, uint256, bytes calldata) external pure {
        revert("UO-SBT: Token Soulbound - no transferible");
    }

    function approve(address, uint256) external pure {
        revert("UO-SBT: Token Soulbound - no se permiten aprobaciones");
    }

    function setApprovalForAll(address, bool) external pure {
        revert("UO-SBT: Token Soulbound - no se permiten aprobaciones");
    }

    /// ERC-165 supportsInterface
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x80ac58cd || // ERC-721
            interfaceId == 0x01ffc9a7;  // ERC-165
    }
}
