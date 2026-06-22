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
 * Tests del contrato AlertRegistry
 * Ejecutar con: npx hardhat test
 */
describe("AlertRegistry", function () {
  async function deployFixture() {
    const [owner, gateway, analyst, attacker] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();

    const deployed = await hre.viem.deployContract("AlertRegistry", [
      gateway.account.address,
    ]);

    const contract = await getContractInstance("AlertRegistry", deployed.address, owner);
    const asGateway = await getContractInstance("AlertRegistry", deployed.address, gateway);
    const asOwner = await getContractInstance("AlertRegistry", deployed.address, owner);

    return { contract, owner, gateway, analyst, attacker, asGateway, asOwner, publicClient };
  }

  // ─── Constructor ──────────────────────────────────────────────────────────
  describe("Constructor", function () {
    it("asigna gateway y owner correctamente", async function () {
      const { contract, owner, gateway } = await deployFixture();

      expect((await contract.read.gateway()).toLowerCase()).to.equal(
        gateway.account.address.toLowerCase()
      );
      expect((await contract.read.owner()).toLowerCase()).to.equal(
        owner.account.address.toLowerCase()
      );
    });

    it("rechaza address(0) como gateway", async function () {
      await expect(
        hre.viem.deployContract("AlertRegistry", [
          "0x0000000000000000000000000000000000000000",
        ])
      ).to.be.rejectedWith("AlertRegistry: Gateway invalido");
    });
  });

  // ─── createAlert ──────────────────────────────────────────────────────────
  describe("createAlert", function () {
    it("crea una alerta correctamente desde el gateway", async function () {
      const { contract, asGateway } = await deployFixture();

      await asGateway.write.createAlert([
        "WAZUH-001",
        "Brute Force SSH",
        10, // ruleLevel HIGH
        "192.168.1.50",
        "agent-ssh-01",
        "Credential Access",
      ]);

      expect(await contract.read.getAlertsCount()).to.equal(1n);

      const alert = await contract.read.getAlert([0n]);
      expect(alert.title).to.equal("Brute Force SSH");
      expect(alert.ruleLevel).to.equal(10);
      expect(alert.status).to.equal(0); // Status.OPEN
    });

    it("evita duplicados por wazuhAlertId", async function () {
      const { asGateway } = await deployFixture();

      await asGateway.write.createAlert([
        "WAZUH-DUPLICATE",
        "Primera alerta",
        5,
        "",
        "agent-01",
        "",
      ]);

      await expect(
        asGateway.write.createAlert([
          "WAZUH-DUPLICATE",
          "Segunda alerta igual ID",
          5,
          "",
          "agent-01",
          "",
        ])
      ).to.be.rejectedWith("AlertRegistry: Alerta ya registrada");
    });

    it("rechaza ruleLevel fuera del rango 1-15", async function () {
      const { asGateway } = await deployFixture();

      await expect(
        asGateway.write.createAlert([
          "WAZUH-BADRULE",
          "Nivel inválido",
          0, // 0 es inválido
          "",
          "agent-01",
          "",
        ])
      ).to.be.rejectedWith("AlertRegistry: Nivel invalido");

      await expect(
        asGateway.write.createAlert([
          "WAZUH-BADRULE2",
          "Nivel inválido alto",
          16, // 16 es inválido
          "",
          "agent-01",
          "",
        ])
      ).to.be.rejectedWith("AlertRegistry: Nivel invalido");
    });

    it("rechaza createAlert desde cuenta no autorizada", async function () {
      const { contract, attacker } = await deployFixture();

      const asAttacker = await getContractInstance(
        "AlertRegistry",
        contract.address,
        attacker
      );

      await expect(
        asAttacker.write.createAlert([
          "WAZUH-HACK",
          "Intento no autorizado",
          10,
          "1.2.3.4",
          "agent-evil",
          "",
        ])
      ).to.be.rejectedWith("AlertRegistry: Solo el gateway");
    });
  });

  // ─── updateStatus ─────────────────────────────────────────────────────────
  describe("updateStatus", function () {
    it("el gateway puede cambiar el estado de OPEN a RESOLVED", async function () {
      const { contract, asGateway } = await deployFixture();

      await asGateway.write.createAlert([
        "WAZUH-RESOLVE",
        "Alerta a resolver",
        8,
        "10.0.0.1",
        "agent-02",
        "Execution",
      ]);

      // Status.RESOLVED = 2
      await asGateway.write.updateStatus([0n, 2]);

      const alert = await contract.read.getAlert([0n]);
      expect(alert.status).to.equal(2); // RESOLVED
      expect(alert.resolvedAt).to.be.greaterThan(0n);
    });

    it("el owner puede cambiar estado", async function () {
      const { contract, asGateway, asOwner } = await deployFixture();

      await asGateway.write.createAlert([
        "WAZUH-OWNER",
        "Falso positivo",
        4,
        "",
        "agent-03",
        "",
      ]);

      // Status.FALSE_POSITIVE = 3
      await asOwner.write.updateStatus([0n, 3]);

      const alert = await contract.read.getAlert([0n]);
      expect(alert.status).to.equal(3); // FALSE_POSITIVE
    });

    it("terceros no pueden cambiar el estado", async function () {
      const { contract, asGateway, attacker } = await deployFixture();

      await asGateway.write.createAlert([
        "WAZUH-PROTECT",
        "Alerta protegida",
        12,
        "5.5.5.5",
        "agent-04",
        "Impact",
      ]);

      const asAttacker = await getContractInstance(
        "AlertRegistry",
        contract.address,
        attacker
      );

      await expect(
        asAttacker.write.updateStatus([0n, 2])
      ).to.be.rejectedWith("AlertRegistry: No autorizado");
    });
  });

  // ─── getOpenAlertsCount ───────────────────────────────────────────────────
  describe("getOpenAlertsCount", function () {
    it("cuenta correctamente las alertas abiertas", async function () {
      const { contract, asGateway } = await deployFixture();

      await asGateway.write.createAlert(["W-01", "Alerta 1", 10, "", "a", ""]);
      await asGateway.write.createAlert(["W-02", "Alerta 2", 11, "", "b", ""]);
      await asGateway.write.createAlert(["W-03", "Alerta 3", 12, "", "c", ""]);

      // Resolver una
      await asGateway.write.updateStatus([1n, 2]); // RESOLVED

      expect(await contract.read.getOpenAlertsCount()).to.equal(2n);
    });
  });
});
