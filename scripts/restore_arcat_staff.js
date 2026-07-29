import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import hre from "hardhat";
import { getContract } from "viem";

const ARCAT_DEPLOYMENTS_PATH = path.resolve("deployments/localhost_arcat.json");

const STAFF_DEVICES = [
  {
    ip: "192.168.125.250",
    hostname: "srv-tec-gw-01",
    uuid: "BIOS-TEC-2026-GW01-UUID",
    tipo: 0,
    deviceName: "Gateway Staff TEC 01",
    uoCode: "UO-TEC",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.142",
    hostname: "dell-aio-fg",
    uuid: "4C4C4544-0033-5A10-8043-C2C04F4E4432",
    tipo: 1,
    deviceName: "Estacion de Trabajo TEC 01",
    uoCode: "UO-TEC",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.148",
    hostname: "laptop-tec-dev01",
    uuid: "BIOS-TEC-2026-LP01-UUID",
    tipo: 1,
    deviceName: "Laptop TEC DEV01",
    uoCode: "UO-TEC",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.151",
    hostname: "srv-tec-backup",
    uuid: "BIOS-TEC-2026-BAK1-UUID",
    tipo: 0,
    deviceName: "Servidor Staff TEC Backup",
    uoCode: "UO-TEC",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.160",
    hostname: "pc-adm-01",
    uuid: "BIOS-ADM-2026-PC01-UUID",
    tipo: 1,
    deviceName: "PC Administracion 01",
    uoCode: "UO-ADM",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.161",
    hostname: "pc-adm-02",
    uuid: "BIOS-ADM-2026-PC02-UUID",
    tipo: 1,
    deviceName: "PC Administracion 02",
    uoCode: "UO-ADM",
    dgCode: "STAFF",
  },
  {
    ip: "192.168.125.170",
    hostname: "pc-rhh-01",
    uuid: "BIOS-RHH-2026-PC01-UUID",
    tipo: 1,
    deviceName: "PC Recursos Humanos 01",
    uoCode: "UO-RHH",
    dgCode: "STAFF",
  },
];

async function getContractInstance(name, address, wallet, publicClient) {
  const artifact = await hre.artifacts.readArtifact(name);
  return getContract({
    address,
    abi: artifact.abi,
    client: { wallet, public: publicClient },
  });
}

function getUOAddress(deployments, uoCode) {
  const staffGroup = deployments.contracts?.UnidadesOperativas?.STAFF;
  if (!staffGroup || !staffGroup[uoCode]) {
    throw new Error(`No se encontró la dirección de la UO '${uoCode}' en deployments/localhost_arcat.json`);
  }
  return staffGroup[uoCode].address;
}

async function addressHasCode(publicClient, address) {
  if (!address) return false;
  try {
    const code = await publicClient.getCode({ address });
    return code && code !== "0x" && code !== "0x0";
  } catch {
    return false;
  }
}

async function ensureArcatDeployment(deployments, publicClient) {
  const rootAddr = deployments.contracts?.ArcatRoot;
  const registryAddr = deployments.contracts?.ArcatRegistry;
  if (!rootAddr || !registryAddr) {
    return false;
  }

  if (!await addressHasCode(publicClient, rootAddr)) {
    return false;
  }

  if (!await addressHasCode(publicClient, registryAddr)) {
    return false;
  }

  const staffUOs = ["UO-ADM", "UO-RHH", "UO-TEC"];
  for (const code of staffUOs) {
    const uoAddr = deployments.contracts?.UnidadesOperativas?.STAFF?.[code]?.address;
    if (!uoAddr || !await addressHasCode(publicClient, uoAddr)) {
      return false;
    }
  }

  return true;
}

function updateEnvFile(pathToFile, variables) {
  let content = fs.existsSync(pathToFile) ? fs.readFileSync(pathToFile, "utf-8") : "";
  for (const [key, value] of Object.entries(variables)) {
    const regex = new RegExp(`^${key}=.*$`, "m");
    const line = `${key}=${value}`;
    if (regex.test(content)) {
      content = content.replace(regex, line);
    } else {
      if (content.length > 0 && !content.endsWith("\n")) {
        content += "\n";
      }
      content += `${line}\n`;
    }
  }
  fs.writeFileSync(pathToFile, content, "utf-8");
}

function syncArcatEnv(deployments) {
  const vars = {};
  vars["CONTRACT_ARCAT_ROOT"] = deployments.contracts.ArcatRoot;
  vars["CONTRACT_ARCAT_REGISTRY"] = deployments.contracts.ArcatRegistry;
  vars["VITE_ARCAT_ROOT"] = deployments.contracts.ArcatRoot;
  vars["VITE_ARCAT_REGISTRY"] = deployments.contracts.ArcatRegistry;

  for (const [dgCode, info] of Object.entries(deployments.contracts.DireccionesGenerales || {})) {
    const key = `CONTRACT_DG_${dgCode.replace(/-/g, "_")}`;
    vars[key] = info.address;
    vars[`VITE_${key}`] = info.address;
  }

  for (const [dgCode, uos] of Object.entries(deployments.contracts.UnidadesOperativas || {})) {
    for (const [uoCode, info] of Object.entries(uos)) {
      const key = `CONTRACT_${uoCode.replace(/-/g, "_")}`;
      vars[key] = info.address;
      vars[`VITE_${key}`] = info.address;
    }
  }

  const envPath = path.resolve(".env");
  const gatewayEnvPath = path.resolve("rust-gateway/.env");

  updateEnvFile(envPath, vars);
  console.log(`   ✅ Actualizado ${envPath} con direcciones ARCAT`);

  if (fs.existsSync(gatewayEnvPath)) {
    updateEnvFile(gatewayEnvPath, vars);
    console.log(`   ✅ Actualizado ${gatewayEnvPath} con direcciones ARCAT`);
  }
}

function redeployArcat() {
  console.log("⚠️  No se encontró la red ARCAT local desplegada o su estado está perdido.");
  console.log("   Iniciando redeploy de ARCAT en localhost...");
  execSync("npx hardhat run scripts/deploy_arcat.js --network localhost --config hardhat.config.cjs", {
    stdio: "inherit",
  });
  const deployments = JSON.parse(fs.readFileSync(ARCAT_DEPLOYMENTS_PATH, "utf-8"));
  syncArcatEnv(deployments);
  return deployments;
}

async function main() {
  console.log("╔════════════════════════════════════════════════════════════════╗");
  console.log("║   RESTORE_ARCAT_STAFF.js — Restauración on-chain de SBT STAFF  ║");
  console.log("╚════════════════════════════════════════════════════════════════╝");

  if (!fs.existsSync(ARCAT_DEPLOYMENTS_PATH)) {
    throw new Error(`No se encontró ${ARCAT_DEPLOYMENTS_PATH}. Ejecuta primero npm run deploy:arcat:local`);
  }

  let deployments = JSON.parse(fs.readFileSync(ARCAT_DEPLOYMENTS_PATH, "utf-8"));
  const publicClient = await hre.viem.getPublicClient();

  if (!await ensureArcatDeployment(deployments, publicClient)) {
    deployments = redeployArcat();
  }

  const registryAddress = deployments.contracts?.ArcatRegistry;
  if (!registryAddress) {
    throw new Error("El archivo de deploy no contiene ArcatRegistry. Verifica deployments/localhost_arcat.json");
  }

  const [deployer] = await hre.viem.getWalletClients();
  const deployerAddress = deployer.account.address;

  console.log(`\n📡 Red: ${hre.network.name}`);
  console.log(`👤 Deployer: ${deployerAddress}`);
  console.log(`🏛️  ArcatRegistry: ${registryAddress}\n`);

  const registryContract = await getContractInstance("ArcatRegistry", registryAddress, deployer, publicClient);

  let succeeded = 0;
  let failed = 0;

  for (const device of STAFF_DEVICES) {
    try {
      const uoAddress = getUOAddress(deployments, device.uoCode);
      const uoContract = await getContractInstance("UnidadOperativaSBT", uoAddress, deployer, publicClient);

      console.log(`➡️  Restaurando dispositivo ${device.hostname} en ${device.uoCode}...`);

      const tx = await uoContract.write.registerDevice([
        deployerAddress,
        device.deviceName,
        device.uuid,
        device.hostname,
        device.tipo,
      ]);
      await tx.wait();

      const lookup = await uoContract.read.getTokenByHostname([device.hostname]);
      const tokenId = lookup[0];
      const found = lookup[1];
      if (!found) {
        throw new Error(`No se encontró tokenId tras registerDevice para ${device.hostname}`);
      }

      console.log(`   ✅ Dispositivo acuñado en UO ${device.uoCode} tokenId=${tokenId}`);

      const tx2 = await registryContract.write.adminIndexDevice([
        uoAddress,
        tokenId,
        device.hostname,
        device.uuid,
        device.dgCode,
        device.uoCode,
      ]);
      await tx2.wait();

      console.log(`   ✅ Indexado en ArcatRegistry (${registryAddress})\n`);
      succeeded += 1;
    } catch (error) {
      console.error(`   ❌ Falló al restaurar ${device.hostname}: ${error.message}`);
      failed += 1;
    }
  }

  console.log("╔════════════════════════════════════════════════════════════════╗");
  console.log(`║   Restauración ARCAT finalizada: ${succeeded} ok, ${failed} fallidas   ║`);
  console.log("╚════════════════════════════════════════════════════════════════╝");

  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("\n❌ Error en restore_arcat_staff:", error.message);
  process.exit(1);
});
