// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title AlertRegistry
 * @notice Registro de alertas críticas de seguridad
 * @dev Permite clasificar alertas por severidad y marcarlas como resueltas
 */
contract AlertRegistry {
    // ─── Estructuras ─────────────────────────────────────────────────────────

    enum Status { OPEN, IN_PROGRESS, RESOLVED, FALSE_POSITIVE }

    struct Alert {
        uint256 id;
        uint256 createdAt;
        uint256 resolvedAt;
        uint8 ruleLevel;           // Nivel Wazuh 1-15
        Status status;
        string wazuhAlertId;       // ID original en Wazuh
        string title;
        string srcIp;
        string agentName;
        string mitreTactic;
        string mitreId;
        address reporter;
        address resolver;          // Quien resolvió la alerta
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    Alert[] private _alerts;

    mapping(string => uint256) public wazuhIdToAlertId;
    mapping(string => bool) public wazuhIdRegistered;

    address public gateway;
    address public owner;

    // ─── Eventos ─────────────────────────────────────────────────────────────

    event AlertCreated(uint256 indexed id, uint8 ruleLevel, string wazuhAlertId);
    event AlertStatusChanged(uint256 indexed id, Status newStatus, address changedBy);

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyGateway() {
        require(msg.sender == gateway, "AlertRegistry: Solo el gateway");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "AlertRegistry: Solo el owner");
        _;
    }

    modifier alertExists(uint256 id) {
        require(id < _alerts.length, "AlertRegistry: Alerta no existe");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _gateway) {
        require(_gateway != address(0), "AlertRegistry: Gateway invalido");
        gateway = _gateway;
        owner = msg.sender;
    }

    // ─── Escritura ────────────────────────────────────────────────────────────

    /**
     * @notice Registra una nueva alerta crítica
     */
    function createAlert(
        string calldata wazuhAlertId,
        string calldata title,
        uint8 ruleLevel,
        string calldata srcIp,
        string calldata agentName,
        string calldata mitreTactic
    ) external onlyGateway returns (uint256 id) {
        require(!wazuhIdRegistered[wazuhAlertId], "AlertRegistry: Alerta ya registrada");
        require(ruleLevel >= 1 && ruleLevel <= 15, "AlertRegistry: Nivel invalido");

        id = _alerts.length;
        wazuhIdRegistered[wazuhAlertId] = true;
        wazuhIdToAlertId[wazuhAlertId] = id;

        Alert storage newAlert = _alerts.push();
        newAlert.id         = id;
        newAlert.createdAt  = block.timestamp;
        newAlert.ruleLevel  = ruleLevel;
        newAlert.status     = Status.OPEN;
        newAlert.wazuhAlertId = wazuhAlertId;
        newAlert.title      = title;
        newAlert.srcIp      = srcIp;
        newAlert.agentName  = agentName;
        newAlert.mitreTactic = mitreTactic;
        newAlert.reporter   = msg.sender;

        emit AlertCreated(id, ruleLevel, wazuhAlertId);
    }

    /**
     * @notice Actualiza el estado de una alerta
     */
    function updateStatus(uint256 id, Status newStatus)
        external
        alertExists(id)
    {
        require(
            msg.sender == gateway || msg.sender == owner,
            "AlertRegistry: No autorizado"
        );

        _alerts[id].status = newStatus;
        _alerts[id].resolver = msg.sender;

        if (newStatus == Status.RESOLVED || newStatus == Status.FALSE_POSITIVE) {
            _alerts[id].resolvedAt = block.timestamp;
        }

        emit AlertStatusChanged(id, newStatus, msg.sender);
    }

    // ─── Lectura ──────────────────────────────────────────────────────────────

    function getAlert(uint256 id) external view alertExists(id) returns (Alert memory) {
        return _alerts[id];
    }

    function getAlertsCount() external view returns (uint256) {
        return _alerts.length;
    }

    function getOpenAlertsCount() external view returns (uint256 count) {
        for (uint256 i = 0; i < _alerts.length; i++) {
            if (_alerts[i].status == Status.OPEN) count++;
        }
    }
}
