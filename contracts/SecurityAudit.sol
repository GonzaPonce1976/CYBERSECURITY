// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title SecurityAudit
 * @notice Registro inmutable de eventos de seguridad en Ethereum
 * @dev Cada evento se almacena on-chain con su hash SHA256 del payload completo
 *      para garantizar integridad e inmutabilidad.
 */
contract SecurityAudit {
    // ─── Estructuras ─────────────────────────────────────────────────────────

    enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    struct AuditEvent {
        uint256 id;
        uint256 timestamp;
        Severity severity;
        string eventType;      // "INTRUSION", "MALWARE", "ANOMALY", "COMPLIANCE"
        string description;
        bytes32 dataHash;      // SHA256 del payload completo en Rust
        string malwareFamily;  // Familia de malware (Ej. "Emotet")
        string[] iocHashes;    // Hashes detectados (Ej. SHA256 de las muestras)
        address reporter;      // Dirección del Rust gateway
        string agentName;      // Nombre del agente Wazuh (opcional)
        string srcIp;          // IP de origen (opcional)
        bool verified;         // Si fue verificado por múltiples fuentes
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    AuditEvent[] private _events;

    /// Mapeo hash → id para evitar duplicados
    mapping(bytes32 => bool) public registeredHashes;

    /// Dirección del gateway autorizado a escribir
    address public immutable gateway;

    /// Dueño del contrato (admin)
    address public immutable owner;

    // ─── Eventos ─────────────────────────────────────────────────────────────

    event NewAuditEvent(
        uint256 indexed id,
        Severity indexed severity,
        string eventType,
        bytes32 dataHash,
        address reporter,
        uint256 timestamp
    );

    event GatewayUpdated(address oldGateway, address newGateway);

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyGateway() {
        require(msg.sender == gateway, "SecurityAudit: Solo el gateway puede escribir");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "SecurityAudit: Solo el owner");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _gateway) {
        require(_gateway != address(0), "SecurityAudit: Gateway invalido");
        gateway = _gateway;
        owner = msg.sender;
    }

    // ─── Escritura ────────────────────────────────────────────────────────────

    /**
     * @notice Registra un nuevo evento de seguridad
     * @param severity Nivel de severidad del evento
     * @param eventType Tipo de evento ("INTRUSION", "MALWARE", etc.)
     * @param description Descripción legible del evento
     * @param dataHash Hash SHA256 del payload completo del evento
     * @param malwareFamily Nombre de la familia de malware identificada
     * @param iocHashes Lista de hashes (SHA256) de indicadores de compromiso
     * @param agentName Nombre del agente que detectó el evento
     * @param srcIp IP de origen del ataque (vacío si no aplica)
     * @return id El ID del evento registrado
     */
    function logEvent(
        Severity severity,
        string calldata eventType,
        string calldata description,
        bytes32 dataHash,
        string calldata malwareFamily,
        string[] calldata iocHashes,
        string calldata agentName,
        string calldata srcIp
    ) external onlyGateway returns (uint256 id) {
        require(!registeredHashes[dataHash], "SecurityAudit: Evento ya registrado");
        require(bytes(eventType).length > 0, "SecurityAudit: eventType requerido");
        require(bytes(description).length > 0, "SecurityAudit: description requerida");

        id = _events.length;
        registeredHashes[dataHash] = true;

        _events.push(AuditEvent({
            id: id,
            timestamp: block.timestamp,
            severity: severity,
            eventType: eventType,
            description: description,
            dataHash: dataHash,
            malwareFamily: malwareFamily,
            iocHashes: iocHashes,
            reporter: msg.sender,
            agentName: agentName,
            srcIp: srcIp,
            verified: false
        }));

        emit NewAuditEvent(id, severity, eventType, dataHash, msg.sender, block.timestamp);
    }

    // ─── Lectura ──────────────────────────────────────────────────────────────

    /// Total de eventos registrados
    function getEventsCount() external view returns (uint256) {
        return _events.length;
    }

    /// Obtener evento por ID
    function getEvent(uint256 id) external view returns (AuditEvent memory) {
        require(id < _events.length, "SecurityAudit: ID no existe");
        return _events[id];
    }

    /// Obtener últimos N eventos
    function getLatestEvents(uint256 count) external view returns (AuditEvent[] memory) {
        uint256 total = _events.length;
        if (count > total) count = total;

        AuditEvent[] memory result = new AuditEvent[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = _events[total - count + i];
        }
        return result;
    }

    /// Verificar si un hash ya está registrado
    function isRegistered(bytes32 dataHash) external view returns (bool) {
        return registeredHashes[dataHash];
    }
}
