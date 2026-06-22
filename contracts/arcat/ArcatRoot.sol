// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title ArcatRoot
 * @notice Contrato de gobernanza raíz de ARCAT.
 * @dev   Administra y autoriza las Direcciones Generales (DG) que forman
 *        la primera capa de la jerarquía de contratos de trazabilidad de
 *        equipos informáticos del organismo.
 *
 * Jerarquía:
 *   ArcatRoot
 *     └── DireccionGeneral (×N)
 *           └── UnidadOperativaSBT (×M por DG)
 *                 └── SBT Token (1 por dispositivo físico)
 */
contract ArcatRoot {
    // ─── Estructura ───────────────────────────────────────────────────────────

    struct DireccionGeneralInfo {
        string  name;         // Ej: "Dirección General de Rentas"
        string  code;         // Ej: "DGR"
        address contractAddr; // Dirección del contrato DireccionGeneral
        bool    isActive;
        uint256 deployedAt;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// Administrador de ARCAT (único que puede autorizar DG)
    address public immutable admin;

    /// Dirección del Rust Gateway autorizado globalmente
    address public gatewayAddress;

    /// Listado de direcciones de contratos DireccionGeneral autorizados
    address[] private _dgList;

    /// Mapeo dirección → información de la DG
    mapping(address => DireccionGeneralInfo) private _dgInfo;

    /// Mapeo código corto → dirección del contrato DG
    mapping(string => address) private _dgByCode;

    // ─── Eventos ──────────────────────────────────────────────────────────────

    event DireccionGeneralAdded(
        address indexed dg,
        string          name,
        string          code,
        uint256         timestamp
    );

    event DireccionGeneralRevoked(
        address indexed dg,
        string          code,
        uint256         timestamp
    );

    event GatewayUpdated(
        address indexed oldGateway,
        address indexed newGateway
    );

    // ─── Modificadores ────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "ArcatRoot: solo el admin");
        _;
    }

    modifier dgExists(address dg) {
        require(_dgInfo[dg].contractAddr != address(0), "ArcatRoot: DG no existe");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param _gateway Dirección del Rust Gateway autorizado para escritura
     */
    constructor(address _gateway) {
        require(_gateway != address(0), "ArcatRoot: gateway invalido");
        admin          = msg.sender;
        gatewayAddress = _gateway;
    }

    // ─── Administración ───────────────────────────────────────────────────────

    /**
     * @notice Registra y autoriza una nueva Dirección General.
     * @param dg    Dirección del contrato DireccionGeneral ya desplegado
     * @param name  Nombre completo de la Dirección General
     * @param code  Código corto único (ej: "DGR", "DGC", "DGRPI")
     */
    function addDireccionGeneral(
        address       dg,
        string memory name,
        string memory code
    ) external onlyAdmin {
        require(dg != address(0),                           "ArcatRoot: direccion invalida");
        require(bytes(name).length > 0,                     "ArcatRoot: nombre requerido");
        require(bytes(code).length > 0,                     "ArcatRoot: codigo requerido");
        require(_dgInfo[dg].contractAddr == address(0),     "ArcatRoot: DG ya registrada");
        require(_dgByCode[code] == address(0),              "ArcatRoot: codigo ya existe");

        _dgInfo[dg] = DireccionGeneralInfo({
            name:         name,
            code:         code,
            contractAddr: dg,
            isActive:     true,
            deployedAt:   block.timestamp
        });
        _dgByCode[code] = dg;
        _dgList.push(dg);

        emit DireccionGeneralAdded(dg, name, code, block.timestamp);
    }

    /**
     * @notice Revoca la autorización de una Dirección General.
     * @param dg Dirección del contrato DireccionGeneral
     */
    function revokeDireccionGeneral(address dg)
        external
        onlyAdmin
        dgExists(dg)
    {
        _dgInfo[dg].isActive = false;
        emit DireccionGeneralRevoked(dg, _dgInfo[dg].code, block.timestamp);
    }

    /**
     * @notice Actualiza la dirección del Rust Gateway global.
     * @param newGateway Nueva dirección del gateway
     */
    function updateGateway(address newGateway) external onlyAdmin {
        require(newGateway != address(0), "ArcatRoot: gateway invalido");
        emit GatewayUpdated(gatewayAddress, newGateway);
        gatewayAddress = newGateway;
    }

    // ─── Consultas ────────────────────────────────────────────────────────────

    /**
     * @notice Devuelve si una dirección de contrato está autorizada como DG.
     */
    function isAuthorized(address dg) external view returns (bool) {
        return _dgInfo[dg].isActive;
    }

    /**
     * @notice Devuelve la información completa de una DG por su dirección.
     */
    function getDireccionGeneral(address dg)
        external
        view
        dgExists(dg)
        returns (DireccionGeneralInfo memory)
    {
        return _dgInfo[dg];
    }

    /**
     * @notice Busca una DG por su código corto.
     */
    function getDireccionByCode(string memory code)
        external
        view
        returns (address)
    {
        return _dgByCode[code];
    }

    /**
     * @notice Devuelve el listado completo de direcciones de contratos DG.
     */
    function getAllDirecciones() external view returns (address[] memory) {
        return _dgList;
    }

    /**
     * @notice Devuelve el total de Direcciones Generales registradas.
     */
    function getDireccionesCount() external view returns (uint256) {
        return _dgList.length;
    }
}
