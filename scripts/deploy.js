import hre from "hardhat";
import fs from "fs";
import path from "path";

/**
 * deploy.js — Script de deploy completo con verificación post-deploy
 *
 * Uso:
 *   npx hardhat run scripts/deploy.js --network localhost   # local
 *   npx hardhat run scripts/deploy.js --network sepolia     # testnet
 */

async function main() {
  const network = hre.network.name;
  const [deployer] = await hre.viem.getWalletClients();
  const publicClient = await hre.viem.getPublicClient();
  const deployerAddr = deployer.account.address;

  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║   CyberSecurity DApp — Smart Contract Deploy     ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log(`\n📡 Red:      ${network}`);
  console.log(`👤 Deployer: ${deployerAddr}`);

  const balance = await publicClient.getBalance({ address: deployerAddr });
  const balanceEth = Number(balance) / 1e18;
  console.log(`💰 Balance:  ${balanceEth.toFixed(4)} ETH`);

  if (network === "sepolia" && balanceEth < 0.01) {
    throw new Error("Balance insuficiente para deploy en Sepolia (mínimo 0.01 ETH)");
  }

  // ── 1. SecurityAudit ──────────────────────────────────────────
  console.log("\n⏳ Desplegando SecurityAudit...");
  const securityAudit = await hre.viem.deployContract("SecurityAudit", [deployerAddr]);
  const securityAuditAddr = securityAudit.address;
  console.log(`✅ SecurityAudit: ${securityAuditAddr}`);

  if (securityAudit.read) {
    try {
      const saGateway = await securityAudit.read.gateway();
      const saOwner = await securityAudit.read.owner();
      console.log(`   gateway = ${saGateway}`);
      console.log(`   owner   = ${saOwner}`);
    } catch (err) {
      console.warn(`   ⚠️  No se pudo verificar contrato: ${err.message}`);
    }
  } else {
    console.warn("   ⚠️  No hay interfaz read disponible para SecurityAudit en este entorno");
  }

  // ── 2. AlertRegistry ──────────────────────────────────────────
  console.log("\n⏳ Desplegando AlertRegistry...");
  const alertRegistry = await hre.viem.deployContract("AlertRegistry", [deployerAddr]);
  const alertRegistryAddr = alertRegistry.address;
  console.log(`✅ AlertRegistry: ${alertRegistryAddr}`);

  if (alertRegistry.read) {
    try {
      const arGateway = await alertRegistry.read.gateway();
      const arOwner = await alertRegistry.read.owner();
      console.log(`   gateway = ${arGateway}`);
      console.log(`   owner   = ${arOwner}`);
    } catch (err) {
      console.warn(`   ⚠️  No se pudo verificar contrato: ${err.message}`);
    }
  } else {
    console.warn("   ⚠️  No hay interfaz read disponible para AlertRegistry en este entorno");
  }

  // ── 3. Guardar addresses en archivo de deploy ─────────────────
  const deployOutput = {
    network,
    deployedAt: new Date().toISOString(),
    deployer: deployerAddr,
    contracts: {
      SecurityAudit: securityAuditAddr,
      AlertRegistry: alertRegistryAddr,
    },
  };

  const outDir = path.resolve("deployments");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `${network}.json`);
  fs.writeFileSync(outFile, JSON.stringify(deployOutput, null, 2));
  console.log(`\n📄 Deploy guardado en: deployments/${network}.json`);

  // ── 4. Actualizar .env con las direcciones ─────────────────────
  updateEnvFile({
    CONTRACT_SECURITY_AUDIT: securityAuditAddr,
    CONTRACT_ALERT_REGISTRY: alertRegistryAddr,
    VITE_CONTRACT_SECURITY_AUDIT: securityAuditAddr,
    VITE_CONTRACT_ALERT_REGISTRY: alertRegistryAddr,
  });

  // ── 5. Resumen final ───────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════╗");
  console.log("║              Deploy exitoso ✅                    ║");
  console.log("╠══════════════════════════════════════════════════╣");
  console.log(`║ SecurityAudit  : ${securityAuditAddr.slice(0, 20)}… ║`);
  console.log(`║ AlertRegistry  : ${alertRegistryAddr.slice(0, 20)}… ║`);
  console.log("╚══════════════════════════════════════════════════╝");

  if (network === "sepolia") {
    console.log(`\n🔍 Verificar en Etherscan:`);
    console.log(`   https://sepolia.etherscan.io/address/${securityAuditAddr}`);
    console.log(`   https://sepolia.etherscan.io/address/${alertRegistryAddr}`);
    console.log("\n⏳ Esperando confirmaciones para verificación de código...");
    await sleep(30000);
    await verifyContracts(securityAuditAddr, alertRegistryAddr, deployerAddr);
  }
}

/**
 * Actualiza variables en el .env local
 */
function updateEnvFile(vars) {
  const envPath = path.resolve(".env");
  if (!fs.existsSync(envPath)) {
    console.warn("⚠️  No se encontró .env — crea el archivo desde .env.example");
    return;
  }

  let content = fs.readFileSync(envPath, "utf-8");
  for (const [key, value] of Object.entries(vars)) {
    const regex = new RegExp(`^${key}=.*$`, "m");
    const line = `${key}=${value}`;
    if (regex.test(content)) {
      content = content.replace(regex, line);
    } else {
      content += `\n${line}`;
    }
  }
  fs.writeFileSync(envPath, content);
  console.log("✅ .env actualizado con las direcciones de contratos");
}

/**
 * Verifica los contratos en Etherscan (solo Sepolia)
 */
async function verifyContracts(securityAuditAddr, alertRegistryAddr, deployerAddr) {
  try {
    console.log("🔍 Verificando SecurityAudit en Etherscan...");
    await hre.run("verify:verify", {
      address: securityAuditAddr,
      constructorArguments: [deployerAddr],
    });
    console.log("✅ SecurityAudit verificado");
  } catch (e) {
    console.warn("⚠️  Verificación SecurityAudit:", e.message?.slice(0, 80));
  }

  try {
    console.log("🔍 Verificando AlertRegistry en Etherscan...");
    await hre.run("verify:verify", {
      address: alertRegistryAddr,
      constructorArguments: [deployerAddr],
    });
    console.log("✅ AlertRegistry verificado");
  } catch (e) {
    console.warn("⚠️  Verificación AlertRegistry:", e.message?.slice(0, 80));
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((error) => {
  console.error("\n❌ Deploy fallido:", error.message);
  process.exit(1);
});
