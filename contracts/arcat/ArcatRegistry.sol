// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title ArcatRegistry
 * @notice Índice global de dispositivos de toda la red ARCAT.
 * @dev   Permite al Rust Gateway y al Frontend descubrir rápidamente
 *        a qué contrato UnidadOperativaSBT pertenece un dispositivo
 *        (por hostname o UUID) sin necesidad de iterar toda la jerarquía.
 *
 *        Los contratos UnidadOperativaSBT autorizados deben registrar
 *        cada nuevo dispositivo aquí para mantener el índice actualizado.
 */
contract ArcatRegistry {

    // ─── Estructuras ──────────────────────────────────────────────────────────

    struct DeviceEntry {
        address uoContract;  // Dirección del contrato UnidadOperativaSBT
        uint256 tokenId;     // ID del token SBT del dispositivo
        string  dgCode;      // Código de la DG padre (ej: "DGR")
        string  uoCode;      // Código de la UO (ej: "UO-REC")
        bool    exists;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// Admin (deployer ARCAT)
    address public immutable admin;

    /// Dirección del contrato ArcatRoot (para validar contratos autorizados)
    address public immutable arcatRoot;

    /// Contratos UO autorizados a registrar dispositivos aquí
    mapping(address => bool) public authorizedUO;

    /// Índice hostname → DeviceEntry
    mapping(string => DeviceEntry) private _byHostname;

    /// Índice UUID → DeviceEntry
    mapping(string => DeviceEntry) private _byUUID;

    /// Lista global de hostnames registrados (para iterar)
    string[] private _hostnames;

    /// Total de entradas
    uint256 public totalDevices;

    // ─── Eventos ──────────────────────────────────────────────────────────────

    event DeviceIndexed(
        address indexed uoContract,
        uint256 indexed tokenId,
        string          hostname,
        string          uuid,
        string          dgCode,
        string          uoCode,
        uint256         timestamp
    );

    event UOAuthorized(address indexed uo);
    event UORevoked(address indexed uo);

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "ArcatRegistry: solo el admin");
        _;
    }

    modifier onlyAuthorizedUO() {
        require(authorizedUO[msg.sender], "ArcatRegistry: UO no autorizada");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _arcatRoot) {
        require(_arcatRoot != address(0), "ArcatRegistry: arcatRoot invalido");
        admin     = msg.sender;
        arcatRoot = _arcatRoot;
    }

    // ─── Administración ───────────────────────────────────────────────────────

    /// Autoriza un contrato UnidadOperativaSBT a registrar dispositivos
    function authorizeUO(address uo) external onlyAdmin {
        require(uo != address(0), "ArcatRegistry: UO invalida");
        authorizedUO[uo] = true;
        emit UOAuthorized(uo);
    }

    /// Revoca la autorización de una UO
    function revokeUO(address uo) external onlyAdmin {
        authorizedUO[uo] = false;
        emit UORevoked(uo);
    }

    /**
     * @notice Autoriza múltiples UOs en una sola transacción (para el deploy inicial).
     * @param uos Array de direcciones de contratos UO
     */
    function batchAuthorizeUOs(address[] calldata uos) external onlyAdmin {
        for (uint256 i = 0; i < uos.length; i++) {
            if (uos[i] != address(0)) {
                authorizedUO[uos[i]] = true;
                emit UOAuthorized(uos[i]);
            }
        }
    }

    // ─── Indexación ───────────────────────────────────────────────────────────

    /**
     * @notice Registra un dispositivo en el índice global.
     * @dev   Solo puede ser llamado por contratos UO autorizados O por el admin
     *        (para el deploy inicial de dispositivos existentes).
     * @param tokenId    ID del token SBT
     * @param hostname   Hostname del dispositivo (agentName de Wazuh)
     * @param uuid       UUID de hardware
     * @param dgCode     Código de la Dirección General (ej: "DGR")
     * @param uoCode     Código de la Unidad Operativa (ej: "UO-REC")
     */
    function indexDevice(
        uint256       tokenId,
        string memory hostname,
        string memory uuid,
        string memory dgCode,
        string memory uoCode
    ) external {
        require(
            authorizedUO[msg.sender] || msg.sender == admin,
            "ArcatRegistry: no autorizado"
        );
        require(bytes(hostname).length > 0, "ArcatRegistry: hostname requerido");
        require(bytes(uuid).length > 0,     "ArcatRegistry: uuid requerido");

        address uoContract = msg.sender;

        if (_byUUID[uuid].exists) {
            DeviceEntry storage existingEntry = _byUUID[uuid];
            
            string memory oldHostname = "";
            for (uint256 i = 0; i < _hostnames.length; i++) {
                if (_byHostname[_hostnames[i]].uoContract == existingEntry.uoContract && 
                    _byHostname[_hostnames[i]].tokenId == existingEntry.tokenId) {
                    oldHostname = _hostnames[i];
                    break;
                }
            }
            if (bytes(oldHostname).length > 0 && keccak256(bytes(oldHostname)) != keccak256(bytes(hostname))) {
                _byHostname[oldHostname].exists = false;
            }

            existingEntry.uoContract = uoContract;
            existingEntry.tokenId = tokenId;
            existingEntry.dgCode = dgCode;
            existingEntry.uoCode = uoCode;
            existingEntry.exists = true;

            _byHostname[hostname] = existingEntry;
            _byUUID[uuid] = existingEntry;

            bool hostnameFound = false;
            for (uint256 i = 0; i < _hostnames.length; i++) {
                if (keccak256(bytes(_hostnames[i])) == keccak256(bytes(hostname))) {
                    hostnameFound = true;
                    break;
                }
            }
            if (!hostnameFound) {
                _hostnames.push(hostname);
            }

            emit DeviceIndexed(uoContract, tokenId, hostname, uuid, dgCode, uoCode, block.timestamp);
            return;
        }

        require(
            !_byHostname[hostname].exists,
            "ArcatRegistry: hostname ya indexado"
        );

        DeviceEntry memory entry = DeviceEntry({
            uoContract: uoContract,
            tokenId:    tokenId,
            dgCode:     dgCode,
            uoCode:     uoCode,
            exists:     true
        });

        _byHostname[hostname] = entry;
        _byUUID[uuid]         = entry;
        _hostnames.push(hostname);
        totalDevices++;

        emit DeviceIndexed(uoContract, tokenId, hostname, uuid, dgCode, uoCode, block.timestamp);
    }

    /**
     * @notice Versión del admin para indexar con dirección de UO explícita.
     *         Usada en el script de deploy para registrar desde el deployer.
     */
    function adminIndexDevice(
        address       uoContract,
        uint256       tokenId,
        string memory hostname,
        string memory uuid,
        string memory dgCode,
        string memory uoCode
    ) external onlyAdmin {
        require(uoContract != address(0),   "ArcatRegistry: UO invalida");
        require(bytes(hostname).length > 0, "ArcatRegistry: hostname requerido");
        require(bytes(uuid).length > 0,     "ArcatRegistry: uuid requerido");

        if (_byUUID[uuid].exists) {
            DeviceEntry storage existingEntry = _byUUID[uuid];
            
            string memory oldHostname = "";
            for (uint256 i = 0; i < _hostnames.length; i++) {
                if (_byHostname[_hostnames[i]].uoContract == existingEntry.uoContract && 
                    _byHostname[_hostnames[i]].tokenId == existingEntry.tokenId) {
                    oldHostname = _hostnames[i];
                    break;
                }
            }
            if (bytes(oldHostname).length > 0 && keccak256(bytes(oldHostname)) != keccak256(bytes(hostname))) {
                _byHostname[oldHostname].exists = false;
            }

            existingEntry.uoContract = uoContract;
            existingEntry.tokenId = tokenId;
            existingEntry.dgCode = dgCode;
            existingEntry.uoCode = uoCode;
            existingEntry.exists = true;

            _byHostname[hostname] = existingEntry;
            _byUUID[uuid] = existingEntry;

            bool hostnameFound = false;
            for (uint256 i = 0; i < _hostnames.length; i++) {
                if (keccak256(bytes(_hostnames[i])) == keccak256(bytes(hostname))) {
                    hostnameFound = true;
                    break;
                }
            }
            if (!hostnameFound) {
                _hostnames.push(hostname);
            }

            emit DeviceIndexed(uoContract, tokenId, hostname, uuid, dgCode, uoCode, block.timestamp);
            return;
        }

        require(
            !_byHostname[hostname].exists,
            "ArcatRegistry: hostname ya indexado"
        );

        DeviceEntry memory entry = DeviceEntry({
            uoContract: uoContract,
            tokenId:    tokenId,
            dgCode:     dgCode,
            uoCode:     uoCode,
            exists:     true
        });

        _byHostname[hostname] = entry;
        _byUUID[uuid]         = entry;
        _hostnames.push(hostname);
        totalDevices++;

        emit DeviceIndexed(uoContract, tokenId, hostname, uuid, dgCode, uoCode, block.timestamp);
    }

    // ─── Consultas ────────────────────────────────────────────────────────────

    /**
     * @notice Lookup por hostname → contrato UO + tokenId.
     * @return uoContract Dirección del contrato UnidadOperativaSBT
     * @return tokenId    ID del token SBT
     * @return found      true si existe el dispositivo
     */
    function lookupByHostname(string calldata hostname)
        external
        view
        returns (address uoContract, uint256 tokenId, bool found)
    {
        DeviceEntry storage e = _byHostname[hostname];
        return (e.uoContract, e.tokenId, e.exists);
    }

    /**
     * @notice Lookup por UUID → contrato UO + tokenId.
     */
    function lookupByUUID(string calldata uuid)
        external
        view
        returns (address uoContract, uint256 tokenId, bool found)
    {
        DeviceEntry storage e = _byUUID[uuid];
        return (e.uoContract, e.tokenId, e.exists);
    }

    /**
     * @notice Devuelve la entrada completa de un dispositivo por hostname.
     */
    function getDeviceEntry(string calldata hostname)
        external
        view
        returns (DeviceEntry memory)
    {
        return _byHostname[hostname];
    }

    /**
     * @notice Lista de todos los hostnames indexados (paginado).
     */
    function getHostnames(uint256 from, uint256 count)
        external
        view
        returns (string[] memory)
    {
        uint256 total = _hostnames.length;
        if (from >= total) return new string[](0);
        uint256 end = from + count;
        if (end > total) end = total;
        uint256 len = end - from;

        string[] memory result = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            result[i] = _hostnames[from + i];
        }
        return result;
    }
}
