import { expect } from "chai";
import hre from "hardhat";
import { getContract } from "viem";

async function getContractInstance(name, address, wallet) {
  const pc = await hre.viem.getPublicClient();
  const artifact = await hre.artifacts.readArtifact(name);
  return getContract({
    address,
    abi: artifact.abi,
    client: { wallet, public: pc },
  });
}

/**
 * Tests del contrato SecurityAudit
 * Ejecutar con: npx hardhat test
 */
describe("SecurityAudit", function () {
  // Helpers
  async function deployFixture() {
    const [owner, gateway, attacker] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployed = await hre.viem.deployContract("SecurityAudit", [
      gateway.account.address,
    ]);

    const contract = await getContractInstance("SecurityAudit", deployed.address, owner);

    return { contract, owner, gateway, attacker, publicClient };
  }

  // ─── Constructor ──────────────────────────────────────────────────────────
  describe("Constructor", function () {
    it("asigna el gateway y owner correctamente", async function () {
      const { contract, owner, gateway } = await deployFixture();

      expect((await contract.read.gateway()).toLowerCase()).to.equal(
        gateway.account.address.toLowerCase()
      );
      expect((await contract.read.owner()).toLowerCase()).to.equal(
        owner.account.address.toLowerCase()
      );
    });

    it("rechaza gateway address(0)", async function () {
      await expect(
        hre.viem.deployContract("SecurityAudit", [
          "0x0000000000000000000000000000000000000000",
        ])
      ).to.be.rejectedWith("SecurityAudit: Gateway invalido");
    });
  });

  // ─── logEvent ─────────────────────────────────────────────────────────────
  describe("logEvent", function () {
    it("registra un evento correctamente desde el gateway", async function () {
      const { contract, gateway } = await deployFixture();

      const dataHash =
        "0x" + "ab".repeat(32); // bytes32 de prueba

      const gatewayContract = await getContractInstance(
        "SecurityAudit",
        contract.address,
        gateway
      );

      await gatewayContract.write.logEvent([
        2, // Severity.MEDIUM
        "INTRUSION",
        "Intento de login por fuerza bruta",
        dataHash,
        "", // malwareFamily
        [], // iocHashes
        "agent-web-01",
        "192.168.1.100",
      ]);

      expect(await contract.read.getEventsCount()).to.equal(1n);
    });

    it("evita registrar el mismo hash dos veces (duplicado)", async function () {
      const { contract, gateway } = await deployFixture();

      const dataHash = "0x" + "cd".repeat(32);

      const gatewayContract = await getContractInstance(
        "SecurityAudit",
        contract.address,
        gateway
      );

      await gatewayContract.write.logEvent([
        3, // Severity.HIGH
        "MALWARE",
        "Hash malicioso detectado",
        dataHash,
        "", // malwareFamily
        [], // iocHashes
        "agent-db-02",
        "",
      ]);

      await expect(
        gatewayContract.write.logEvent([
          3,
          "MALWARE",
          "Segundo intento con el mismo hash",
          dataHash,
          "", // malwareFamily
          [], // iocHashes
          "agent-db-02",
          "",
        ])
      ).to.be.rejectedWith("SecurityAudit: Evento ya registrado");
    });

    it("rechaza escrituras desde una cuenta no autorizada", async function () {
      const { contract, attacker } = await deployFixture();

      const attackerContract = await getContractInstance(
        "SecurityAudit",
        contract.address,
        attacker
      );

      await expect(
        attackerContract.write.logEvent([
          4, // Severity.CRITICAL
          "INTRUSION",
          "Intento de escritura no autorizado",
          "0x" + "ff".repeat(32),
          "", // malwareFamily
          [], // iocHashes
          "agent-attacker",
          "10.0.0.1",
        ])
      ).to.be.rejectedWith("SecurityAudit: Solo el gateway puede escribir");
    });

    it("verifica que isRegistered() devuelve true después del registro", async function () {
      const { contract, gateway } = await deployFixture();
      const dataHash = "0x" + "aa".repeat(32);

      const gatewayContract = await getContractInstance(
        "SecurityAudit",
        contract.address,
        gateway
      );

      expect(await contract.read.isRegistered([dataHash])).to.equal(false);

      await gatewayContract.write.logEvent([
        1, // Severity.LOW
        "COMPLIANCE",
        "Evento de compliance",
        dataHash,
        "", // malwareFamily
        [], // iocHashes
        "agent-01",
        "",
      ]);

      expect(await contract.read.isRegistered([dataHash])).to.equal(true);
    });
  });

  // ─── getLatestEvents ──────────────────────────────────────────────────────
  describe("getLatestEvents", function () {
    it("retorna los últimos N eventos en orden correcto", async function () {
      const { contract, gateway } = await deployFixture();

      const gatewayContract = await getContractInstance(
        "SecurityAudit",
        contract.address,
        gateway
      );

      // Registrar 3 eventos
      for (let i = 0; i < 3; i++) {
        await gatewayContract.write.logEvent([
          0, // Severity.INFO
          "ANOMALY",
          `Evento número ${i}`,
          "0x" + i.toString().padStart(2, "0").repeat(32).slice(0, 64),
          "", // malwareFamily
          [], // iocHashes
          `agent-${i}`,
          "",
        ]);
      }

      expect(await contract.read.getEventsCount()).to.equal(3n);

      const latest = await contract.read.getLatestEvents([2n]);
      expect(latest.length).to.equal(2);
      // El último evento registrado debe ser el evento 2
      expect(latest[1].description).to.equal("Evento número 2");
    });
  });
});
