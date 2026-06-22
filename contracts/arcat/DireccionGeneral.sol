// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title DireccionGeneral
 * @notice Contrato Fábrica que representa una Dirección General de ARCAT.
 * @dev   Cada instancia de este contrato corresponde a una de las Direcciones
 *        Generales (DG) del organismo (Rentas, Catastro, DGRPI, Staff).
 *        Despliega y administra contratos `UnidadOperativaSBT`.
 *
 *        Límite: hasta MAX_UNIDADES por Dirección General.
 */
interface IUnidadOperativaSBT {
    function name() external view returns (string memory);
    function code() external view returns (string memory);
    function getDevicesCount() external view returns (uint256);
}

contract DireccionGeneral {
    // ─── Constantes ───────────────────────────────────────────────────────────

    uint256 public constant MAX_UNIDADES = 20;

    // ─── Estructuras ──────────────────────────────────────────────────────────

    struct UnidadInfo {
        string  name;
        string  code;
        address contractAddr;
        bool    isActive;
        uint256 deployedAt;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// Nombre completo de la Dirección General
    string public dgName;

    /// Código corto de la DG (ej: "DGR", "DGC")
    string public dgCode;

    /// Admin de la DG (puede ser el admin de ARCAT u otro delegado)
    address public immutable owner;

    /// Dirección del contrato ArcatRoot (para validaciones de autorización)
    address public immutable arcatRoot;

    /// Dirección del Rust Gateway autorizado
    address public gatewayAddress;

    /// Lista de contratos UnidadOperativaSBT
    address[] private _unidades;

    /// Mapeo dirección → info
    mapping(address => UnidadInfo) private _uoInfo;

    /// Mapeo código → dirección del contrato
    mapping(string => address) private _uoByCode;

    // ─── Eventos ──────────────────────────────────────────────────────────────

    event UnidadOperativaDeployed(
        address indexed uo,
        string          name,
        string          code,
        uint256         timestamp
    );

    event UnidadOperativaRevoked(
        address indexed uo,
        string          code,
        uint256         timestamp
    );

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "DireccionGeneral: solo el owner");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param _name       Nombre completo de la Dirección General
     * @param _code       Código corto único (ej: "DGR")
     * @param _arcatRoot  Dirección del contrato ArcatRoot
     * @param _gateway    Dirección del Rust Gateway
     */
    constructor(
        string  memory _name,
        string  memory _code,
        address        _arcatRoot,
        address        _gateway
    ) {
        require(bytes(_name).length > 0,    "DireccionGeneral: nombre requerido");
        require(bytes(_code).length > 0,    "DireccionGeneral: codigo requerido");
        require(_arcatRoot != address(0),   "DireccionGeneral: arcatRoot invalido");
        require(_gateway   != address(0),   "DireccionGeneral: gateway invalido");

        dgName         = _name;
        dgCode         = _code;
        arcatRoot      = _arcatRoot;
        gatewayAddress = _gateway;
        owner          = msg.sender;
    }

    // ─── Registro de Unidades Operativas ──────────────────────────────────────

    /**
     * @notice Registra una Unidad Operativa ya desplegada en esta Dirección General.
     * @dev   El contrato UnidadOperativaSBT debe estar desplegado previamente por
     *        el script de deploy. Este método solo lo registra en el índice.
     * @param uoAddr Dirección del contrato UnidadOperativaSBT
     * @param name   Nombre de la unidad (ej: "De Recaudación")
     * @param code   Código único (ej: "UO-REC")
     */
    function registerUnidadOperativa(
        address       uoAddr,
        string memory name,
        string memory code
    ) external onlyOwner {
        require(uoAddr != address(0),                         "DireccionGeneral: dir invalida");
        require(bytes(name).length > 0,                       "DireccionGeneral: nombre requerido");
        require(bytes(code).length > 0,                       "DireccionGeneral: codigo requerido");
        require(_unidades.length < MAX_UNIDADES,              "DireccionGeneral: limite de unidades alcanzado");
        require(_uoInfo[uoAddr].contractAddr == address(0),   "DireccionGeneral: UO ya registrada");
        require(_uoByCode[code] == address(0),                "DireccionGeneral: codigo ya existe");

        _uoInfo[uoAddr] = UnidadInfo({
            name:         name,
            code:         code,
            contractAddr: uoAddr,
            isActive:     true,
            deployedAt:   block.timestamp
        });
        _uoByCode[code] = uoAddr;
        _unidades.push(uoAddr);

        emit UnidadOperativaDeployed(uoAddr, name, code, block.timestamp);
    }

    /**
     * @notice Revoca (desactiva) una Unidad Operativa.
     */
    function revokeUnidadOperativa(address uoAddr) external onlyOwner {
        require(_uoInfo[uoAddr].contractAddr != address(0), "DireccionGeneral: UO no existe");
        _uoInfo[uoAddr].isActive = false;
        emit UnidadOperativaRevoked(uoAddr, _uoInfo[uoAddr].code, block.timestamp);
    }

    // ─── Consultas ────────────────────────────────────────────────────────────

    /// Total de Unidades Operativas registradas
    function getUnidadesCount() external view returns (uint256) {
        return _unidades.length;
    }

    /// Lista completa de direcciones de contratos UO
    function getAllUnidades() external view returns (address[] memory) {
        return _unidades;
    }

    /// Información de una UO por su dirección de contrato
    function getUnidadInfo(address uoAddr)
        external
        view
        returns (UnidadInfo memory)
    {
        require(_uoInfo[uoAddr].contractAddr != address(0), "DireccionGeneral: UO no existe");
        return _uoInfo[uoAddr];
    }

    /// Dirección de contrato de una UO por su código
    function getUnidadByCode(string memory code)
        external
        view
        returns (address)
    {
        return _uoByCode[code];
    }

    /**
     * @notice Resumen completo de la DG: info de cada UO con cantidad de dispositivos.
     * @return names       Nombres de las UO
     * @return codes       Códigos de las UO
     * @return addrs       Direcciones de los contratos
     * @return actives     Si están activas
     * @return deviceCounts Cantidad de tokens/dispositivos en cada UO
     */
    function getSummary()
        external
        view
        returns (
            string[]  memory names,
            string[]  memory codes,
            address[] memory addrs,
            bool[]    memory actives,
            uint256[] memory deviceCounts
        )
    {
        uint256 len = _unidades.length;
        names        = new string[](len);
        codes        = new string[](len);
        addrs        = new address[](len);
        actives      = new bool[](len);
        deviceCounts = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            address ua      = _unidades[i];
            UnidadInfo memory ui = _uoInfo[ua];
            names[i]        = ui.name;
            codes[i]        = ui.code;
            addrs[i]        = ua;
            actives[i]      = ui.isActive;
            // Intenta obtener el conteo de dispositivos (puede fallar con contratos externos)
            try IUnidadOperativaSBT(ua).getDevicesCount() returns (uint256 c) {
                deviceCounts[i] = c;
            } catch {
                deviceCounts[i] = 0;
            }
        }
    }
}
