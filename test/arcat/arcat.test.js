import { expect }      from "chai";
import hre             from "hardhat";
import { getContract } from "viem";

/**
 * test/arcat/arcat.test.js
 *
 * Tests de integración para la arquitectura ARCAT Multicontratos SBT.
 *
 * Patrón de Hardhat-Viem v1.0.x:
 *   - hre.viem.deployContract() → { address, abi }  (solo descriptores)
 *   - getContract({ address, abi, client: { wallet, public } }) → instancia con .read / .write
 */

/** Helper: crea una instancia de contrato interactuable */
async function contract(name, address, wallet) {
  const pc   = await hre.viem.getPublicClient();
  const info = await hre.viem.deployContract(name, []); // solo para obtener el ABI
  // Buscamos el ABI en los artefactos compilados
  const artifact = await hre.artifacts.readArtifact(name);
  return getContract({
    address,
    abi:    artifact.abi,
    client: { wallet, public: pc },
  });
}

/** Helper: despliega y retorna instancia interactuable de inmediato */
async function deploy(name, args, wallet) {
  const pc       = await hre.viem.getPublicClient();
  const deployed = await hre.viem.deployContract(name, args);
  const artifact = await hre.artifacts.readArtifact(name);
  return getContract({
    address: deployed.address,
    abi:     artifact.abi,
    client:  { wallet, public: pc },
  });
}

// ── Fixture global ─────────────────────────────────────────────────────────

async function deployARCAT() {
  const wallets      = await hre.viem.getWalletClients();
  const deployer     = wallets[0];
  const user1        = wallets[1];
  const deployerAddr = deployer.account.address;

  const arcatRoot     = await deploy("ArcatRoot",    [deployerAddr],                                              deployer);
  const arcatRegistry = await deploy("ArcatRegistry",[arcatRoot.address],                                        deployer);
  const dgRentas      = await deploy("DireccionGeneral", ["Direccion General de Rentas","DGR",arcatRoot.address,deployerAddr], deployer);

  await arcatRoot.write.addDireccionGeneral([dgRentas.address, "Direccion General de Rentas", "DGR"]);

  const uoRecaudacion = await deploy("UnidadOperativaSBT", [
    "De Recaudacion", "UO-REC", "Direccion General de Rentas", deployerAddr,
  ], deployer);

  await dgRentas.write.registerUnidadOperativa([uoRecaudacion.address, "De Recaudacion", "UO-REC"]);
  await arcatRegistry.write.authorizeUO([uoRecaudacion.address]);

  return { deployer, user1, arcatRoot, arcatRegistry, dgRentas, uoRecaudacion };
}

// ═══════════════════════════════════════════════════════════════════════════

describe("ARCAT — Multicontratos SBT", function () {

  // ── ArcatRoot ────────────────────────────────────────────────────────────

  describe("ArcatRoot — Gobernanza", () => {
    it("debe tener admin correcto", async () => {
      const { deployer, arcatRoot } = await deployARCAT();
      const admin = await arcatRoot.read.admin();
      expect(admin.toLowerCase()).to.equal(deployer.account.address.toLowerCase());
    });

    it("debe reconocer DGR como autorizada", async () => {
      const { dgRentas, arcatRoot } = await deployARCAT();
      expect(await arcatRoot.read.isAuthorized([dgRentas.address])).to.be.true;
    });

    it("debe recuperar DGR por codigo", async () => {
      const { dgRentas, arcatRoot } = await deployARCAT();
      const addr = await arcatRoot.read.getDireccionByCode(["DGR"]);
      expect(addr.toLowerCase()).to.equal(dgRentas.address.toLowerCase());
    });

    it("debe contar 1 DG registrada", async () => {
      const { arcatRoot } = await deployARCAT();
      expect(Number(await arcatRoot.read.getDireccionesCount())).to.equal(1);
    });

    it("debe revocar DG y marcarla inactiva", async () => {
      const { dgRentas, arcatRoot } = await deployARCAT();
      await arcatRoot.write.revokeDireccionGeneral([dgRentas.address]);
      expect(await arcatRoot.read.isAuthorized([dgRentas.address])).to.be.false;
    });

    it("debe rechazar DG duplicada", async () => {
      const { dgRentas, arcatRoot } = await deployARCAT();
      await expect(
        arcatRoot.write.addDireccionGeneral([dgRentas.address, "Duplicada", "DGR"])
      ).to.be.rejectedWith("DG ya registrada");
    });
  });

  // ── DireccionGeneral ──────────────────────────────────────────────────────

  describe("DireccionGeneral — Fabrica de UO", () => {
    it("nombre y codigo correctos", async () => {
      const { dgRentas } = await deployARCAT();
      expect(await dgRentas.read.dgName()).to.equal("Direccion General de Rentas");
      expect(await dgRentas.read.dgCode()).to.equal("DGR");
    });

    it("cuenta 1 unidad operativa", async () => {
      const { dgRentas } = await deployARCAT();
      expect(Number(await dgRentas.read.getUnidadesCount())).to.equal(1);
    });

    it("recupera UO por codigo", async () => {
      const { dgRentas, uoRecaudacion } = await deployARCAT();
      const addr = await dgRentas.read.getUnidadByCode(["UO-REC"]);
      expect(addr.toLowerCase()).to.equal(uoRecaudacion.address.toLowerCase());
    });

    it("genera resumen con 1 UO activa", async () => {
      const { dgRentas } = await deployARCAT();
      const [names, codes, , actives] = await dgRentas.read.getSummary();
      expect(names[0]).to.equal("De Recaudacion");
      expect(codes[0]).to.equal("UO-REC");
      expect(actives[0]).to.be.true;
    });

    it("rechaza UO duplicada (misma address)", async () => {
      const { dgRentas, uoRecaudacion } = await deployARCAT();
      await expect(
        dgRentas.write.registerUnidadOperativa([uoRecaudacion.address, "Dup", "UO-DUP"])
      ).to.be.rejectedWith("UO ya registrada");
    });

    it("revoca una UO y la marca inactiva", async () => {
      const { dgRentas, uoRecaudacion } = await deployARCAT();
      await dgRentas.write.revokeUnidadOperativa([uoRecaudacion.address]);
      const info = await dgRentas.read.getUnidadInfo([uoRecaudacion.address]);
      expect(info.isActive).to.be.false;
    });
  });

  // ── UnidadOperativaSBT — Dispositivos ──────────────────────────────────────

  describe("UnidadOperativaSBT — Inventario", () => {
    it("acuna un token SBT correctamente", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Servidor DGR-BD-01", "uuid-bd-001", "dgr-bd-01", 0,
      ]);
      expect(Number(await uoRecaudacion.read.getDevicesCount())).to.equal(1);
    });

    it("recupera device info por tokenId", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Firewall DGR-FW-01", "uuid-fw-001", "dgr-fw-01", 2,
      ]);
      const dev = await uoRecaudacion.read.getDevice([0n]);
      expect(dev.deviceName).to.equal("Firewall DGR-FW-01");
      expect(dev.isActive).to.be.true;
    });

    it("lookup por hostname", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Switch SW-01", "uuid-sw-001", "dgr-sw-01", 3,
      ]);
      const [tokenId, found] = await uoRecaudacion.read.getTokenByHostname(["dgr-sw-01"]);
      expect(found).to.be.true;
      expect(Number(tokenId)).to.equal(0);
    });

    it("lookup por UUID", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "PC WS-01", "uuid-ws-001", "dgr-ws-01", 1,
      ]);
      const [, found] = await uoRecaudacion.read.getTokenByUUID(["uuid-ws-001"]);
      expect(found).to.be.true;
    });

    it("rechaza UUID duplicado", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Srv 1", "uuid-dup-001", "host-1", 0,
      ]);
      await expect(
        uoRecaudacion.write.registerDevice([
          deployer.account.address, "Srv 2", "uuid-dup-001", "host-2", 0,
        ])
      ).to.be.rejectedWith("UUID ya registrado");
    });

    it("rechaza hostname duplicado", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Srv 1", "uuid-h-001", "host-dup-01", 0,
      ]);
      await expect(
        uoRecaudacion.write.registerDevice([
          deployer.account.address, "Srv 2", "uuid-h-002", "host-dup-01", 0,
        ])
      ).to.be.rejectedWith("hostname ya registrado");
    });

    it("desactiva un dispositivo", async () => {
      const { deployer, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Srv Old", "uuid-old-001", "host-old-01", 0,
      ]);
      await uoRecaudacion.write.deactivateDevice([0n]);
      const dev = await uoRecaudacion.read.getDevice([0n]);
      expect(dev.isActive).to.be.false;
    });
  });

  // ── Soulbound ──────────────────────────────────────────────────────────────

  describe("UnidadOperativaSBT — Soulbound", () => {
    it("rechaza transferFrom", async () => {
      const { deployer, user1, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Printer PR-01", "uuid-pr-001", "dgr-pr-01", 4,
      ]);
      await expect(
        uoRecaudacion.write.transferFrom([deployer.account.address, user1.account.address, 0n])
      ).to.be.rejectedWith("Soulbound");
    });

    it("rechaza safeTransferFrom", async () => {
      const { deployer, user1, uoRecaudacion } = await deployARCAT();
      await uoRecaudacion.write.registerDevice([
        deployer.account.address, "Router RT-01", "uuid-rt-001", "dgr-rt-01", 5,
      ]);
      await expect(
        uoRecaudacion.write.safeTransferFrom([deployer.account.address, user1.account.address, 0n])
      ).to.be.rejectedWith("Soulbound");
    });

    it("rechaza approve", async () => {
      const { user1, uoRecaudacion } = await deployARCAT();
      await expect(
        uoRecaudacion.write.approve([user1.account.address, 0n])
      ).to.be.rejectedWith("Soulbound");
    });

    it("rechaza setApprovalForAll", async () => {
      const { user1, uoRecaudacion } = await deployARCAT();
      await expect(
        uoRecaudacion.write.setApprovalForAll([user1.account.address, true])
      ).to.be.rejectedWith("Soulbound");
    });
  });

  // ── Auditorias ────────────────────────────────────────────────────────────

  describe("UnidadOperativaSBT — Auditorias", () => {
    const H1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const H2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const H3 = "0x3333333333333333333333333333333333333333333333333333333333333333";

    async function withDevice() {
      const ctx = await deployARCAT();
      await ctx.uoRecaudacion.write.registerDevice([
        ctx.deployer.account.address, "Servidor BD", "uuid-aud-001", "dgr-aud-01", 0,
      ]);
      return ctx;
    }

    it("registra auditoria MALWARE CRITICAL", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.logAudit([
        0n, "MALWARE", 4, "Emotet detectado", H1, "Emotet", ["sha256:abc"], "192.168.1.100",
      ]);
      expect(Number(await uoRecaudacion.read.getAuditsCount([0n]))).to.equal(1);
    });

    it("recupera datos correctos de la auditoria", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.logAudit([
        0n, "INTRUSION", 3, "Fuerza bruta SSH", H1, "", [], "10.0.0.50",
      ]);
      const audits = await uoRecaudacion.read.getAudits([0n]);
      expect(audits[0].eventType).to.equal("INTRUSION");
      expect(audits[0].srcIp).to.equal("10.0.0.50");
      expect(Number(audits[0].severity)).to.equal(3);
    });

    it("rechaza hash duplicado de auditoria", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "Deteccion 1", H1, "", [], ""]);
      await expect(
        uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "Duplicado", H1, "", [], ""])
      ).to.be.rejectedWith("ya registrado");
    });

    it("rechaza auditoria en dispositivo inactivo", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.deactivateDevice([0n]);
      await expect(
        uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "Intento", H1, "", [], ""])
      ).to.be.rejectedWith("inactivo");
    });

    it("ThreatScore = 300 con 3 alertas CRITICAL", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "A1", H1, "", [], ""]);
      await uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "A2", H2, "", [], ""]);
      await uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "A3", H3, "", [], ""]);
      expect(Number(await uoRecaudacion.read.getThreatScore([0n]))).to.equal(300);
    });

    it("ThreatScore = 0 sin alertas", async () => {
      const { uoRecaudacion } = await withDevice();
      expect(Number(await uoRecaudacion.read.getThreatScore([0n]))).to.equal(0);
    });

    it("getLatestAudits devuelve las 2 mas recientes", async () => {
      const { uoRecaudacion } = await withDevice();
      await uoRecaudacion.write.logAudit([0n, "INFO", 0, "Info 1", H1, "", [], ""]);
      await uoRecaudacion.write.logAudit([0n, "MALWARE", 4, "Critical 1", H2, "", [], ""]);
      await uoRecaudacion.write.logAudit([0n, "ANOMALY", 2, "Medium 1", H3, "", [], ""]);
      const last2 = await uoRecaudacion.read.getLatestAudits([0n, 2n]);
      expect(last2.length).to.equal(2);
      expect(last2[0].eventType).to.equal("MALWARE");
      expect(last2[1].eventType).to.equal("ANOMALY");
    });
  });

  // ── ArcatRegistry ─────────────────────────────────────────────────────────

  describe("ArcatRegistry — Indice Global", () => {
    it("indexa dispositivo y lookup por hostname", async () => {
      const { arcatRegistry, uoRecaudacion } = await deployARCAT();
      await arcatRegistry.write.adminIndexDevice([
        uoRecaudacion.address, 0n, "dgr-srv-01", "uuid-srv-001", "DGR", "UO-REC",
      ]);
      const [uoAddr, tokenId, found] = await arcatRegistry.read.lookupByHostname(["dgr-srv-01"]);
      expect(found).to.be.true;
      expect(uoAddr.toLowerCase()).to.equal(uoRecaudacion.address.toLowerCase());
      expect(Number(tokenId)).to.equal(0);
    });

    it("lookup por UUID", async () => {
      const { arcatRegistry, uoRecaudacion } = await deployARCAT();
      await arcatRegistry.write.adminIndexDevice([
        uoRecaudacion.address, 0n, "dgr-u01", "uuid-u001", "DGR", "UO-REC",
      ]);
      const [, , found] = await arcatRegistry.read.lookupByUUID(["uuid-u001"]);
      expect(found).to.be.true;
    });

    it("incrementa totalDevices correctamente", async () => {
      const { arcatRegistry, uoRecaudacion } = await deployARCAT();
      await arcatRegistry.write.adminIndexDevice([
        uoRecaudacion.address, 0n, "host-1", "uuid-1", "DGR", "UO-REC",
      ]);
      await arcatRegistry.write.adminIndexDevice([
        uoRecaudacion.address, 1n, "host-2", "uuid-2", "DGR", "UO-REC",
      ]);
      expect(Number(await arcatRegistry.read.totalDevices())).to.equal(2);
    });

    it("rechaza hostname duplicado en el indice", async () => {
      const { arcatRegistry, uoRecaudacion } = await deployARCAT();
      await arcatRegistry.write.adminIndexDevice([
        uoRecaudacion.address, 0n, "host-dup", "uuid-dup-1", "DGR", "UO-REC",
      ]);
      await expect(
        arcatRegistry.write.adminIndexDevice([
          uoRecaudacion.address, 1n, "host-dup", "uuid-dup-2", "DGR", "UO-REC",
        ])
      ).to.be.rejectedWith("ya indexado");
    });

    it("devuelve found=false para hostname no registrado", async () => {
      const { arcatRegistry } = await deployARCAT();
      const [, , found] = await arcatRegistry.read.lookupByHostname(["no-existe"]);
      expect(found).to.be.false;
    });

    it("autoriza y revoca UO correctamente", async () => {
      const { arcatRegistry, uoRecaudacion } = await deployARCAT();
      expect(await arcatRegistry.read.authorizedUO([uoRecaudacion.address])).to.be.true;
      await arcatRegistry.write.revokeUO([uoRecaudacion.address]);
      expect(await arcatRegistry.read.authorizedUO([uoRecaudacion.address])).to.be.false;
    });
  });
});
