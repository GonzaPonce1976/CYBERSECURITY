import hre from "hardhat";
import fs from "fs";
import path from "path";
import { getContract } from "viem";

/**
 * deploy_arcat.js — Deploy completo de la arquitectura ARCAT Multicontratos SBT
 *
 * Jerarquía desplegada:
 *   1. ArcatRoot        (gobernanza raíz)
 *   2. ArcatRegistry    (índice global de dispositivos)
 *   3. DireccionGeneral × 4 (DGR, DGC, DGRPI, STAFF)
 *   4. UnidadOperativaSBT × 12 (todas las UO del organigrama)
 *
 * Uso:
 *   npx hardhat run scripts/deploy_arcat.js --network localhost
 *   npx hardhat run scripts/deploy_arcat.js --network sepolia
 */

// ─── Definición del Organigrama ARCAT ──────────────────────────────────────────
const ARCAT_HIERARCHY = [
  {
    name: "Direccion General de Rentas",
    code: "DGR",
    unidades: [
      { name: "De Recaudacion",  code: "UO-REC" },
      { name: "De Fiscalizacion", code: "UO-FIS" },
    ],
  },
  {
    name: "Direccion General de Catastro",
    code: "DGC",
    unidades: [
      { name: "De Saneamiento de Titulo",  code: "UO-SAN" },
      { name: "De Cartografia",             code: "UO-CAR" },
      { name: "De Registro Territorial",    code: "UO-REG" },
    ],
  },
  {
    name: "Direccion General de Registro de la Propiedad Inmobiliaria y de Mandatos",
    code: "DGRPI",
    unidades: [
      { name: "De Registracion Inmobiliaria",                      code: "UO-RIN" },
      { name: "De Publicidad Inmobiliaria y Medidas Cautelares",    code: "UO-PUB" },
    ],
  },
  {
    name: "Dependencias Staff ARCAT",
    code: "STAFF",
    unidades: [
      { name: "De Administracion",                                  code: "UO-ADM" },
      { name: "De Capital Humano",                                   code: "UO-RHH" },
      { name: "De Tecnologias y Sistemas",                           code: "UO-TEC" },
      { name: "De Asuntos Juridicos",                                code: "UO-JUR" },
      { name: "De Gestion y Recaudacion de Recursos Especificos",   code: "UO-GRE" },
      { name: "Auditoria Interna",                                   code: "UO-AUD" },
      { name: "Secretaria General",                                  code: "UO-SEC" },
    ],
  },
];

// ─── Main ────────────────────────────────────────────────────────────────────

async function getContractInstance(name, address, wallet, publicClient) {
  const artifact = await hre.artifacts.readArtifact(name);
  return getContract({
    address,
    abi: artifact.abi,
    client: { wallet, public: publicClient },
  });
}

async function main() {
  const network = hre.network.name;
  const [deployer] = await hre.viem.getWalletClients();
  const publicClient = await hre.viem.getPublicClient();
  const deployerAddr = deployer.account.address;

  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║   ARCAT — Deploy Multicontratos SBT (Soulbound Tokens)      ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`\n📡 Red:      ${network}`);
  console.log(`👤 Deployer: ${deployerAddr}`);

  const balance = await publicClient.getBalance({ address: deployerAddr });
  const balEth = Number(balance) / 1e18;
  console.log(`💰 Balance:  ${balEth.toFixed(4)} ETH\n`);

  if (network === "sepolia" && balEth < 0.05) {
    throw new Error("Balance insuficiente para deploy en Sepolia (minimo 0.05 ETH para ~17 contratos)");
  }

  const output = {
    network,
    deployedAt: new Date().toISOString(),
    deployer: deployerAddr,
    contracts: {},
  };

  // ── 1. ArcatRoot ────────────────────────────────────────────────────────────
  console.log("⏳ [1/4] Desplegando ArcatRoot (Gobernanza)...");
  const arcatRootDeployed = await hre.viem.deployContract("ArcatRoot", [deployerAddr]);
  const arcatRootAddr = arcatRootDeployed.address;
  const arcatRoot = await getContractInstance("ArcatRoot", arcatRootAddr, deployer, publicClient);
  output.contracts.ArcatRoot = arcatRootAddr;
  console.log(`   ✅ ArcatRoot: ${arcatRootAddr}`);

  // ── 2. ArcatRegistry ────────────────────────────────────────────────────────
  console.log("\n⏳ [2/4] Desplegando ArcatRegistry (Indice Global)...");
  const arcatRegistryDeployed = await hre.viem.deployContract("ArcatRegistry", [arcatRootAddr]);
  const arcatRegistryAddr = arcatRegistryDeployed.address;
  const arcatRegistry = await getContractInstance("ArcatRegistry", arcatRegistryAddr, deployer, publicClient);
  output.contracts.ArcatRegistry = arcatRegistryAddr;
  console.log(`   ✅ ArcatRegistry: ${arcatRegistryAddr}`);

  // ── 3. Direcciones Generales + Unidades Operativas ─────────────────────────
  console.log("\n⏳ [3/4] Desplegando Direcciones Generales y Unidades Operativas...");
  const allUOAddrs = [];

  output.contracts.DireccionesGenerales = {};
  output.contracts.UnidadesOperativas   = {};

  for (const dg of ARCAT_HIERARCHY) {
    console.log(`\n   📁 Desplegando DireccionGeneral: ${dg.name} (${dg.code})`);

    const dgContractDeployed = await hre.viem.deployContract("DireccionGeneral", [
      dg.name,
      dg.code,
      arcatRootAddr,
      deployerAddr, // gateway = deployer en local; en producción = rust-gateway address
    ]);
    const dgAddr = dgContractDeployed.address;
    const dgContract = await getContractInstance("DireccionGeneral", dgAddr, deployer, publicClient);

    output.contracts.DireccionesGenerales[dg.code] = {
      name: dg.name,
      address: dgAddr,
    };
    console.log(`      ✅ ${dg.code}: ${dgAddr}`);

    // Autorizar la DG en ArcatRoot
    await arcatRoot.write.addDireccionGeneral([dgAddr, dg.name, dg.code]);
    console.log(`      🔑 Autorizada en ArcatRoot`);

    // Deploy de Unidades Operativas para esta DG
    output.contracts.UnidadesOperativas[dg.code] = {};

    for (const uo of dg.unidades) {
      const uoContract = await hre.viem.deployContract("UnidadOperativaSBT", [
        uo.name,
        uo.code,
        dg.name,
        deployerAddr, // gateway = deployer en local
      ]);
      const uoAddr = uoContract.address;

      output.contracts.UnidadesOperativas[dg.code][uo.code] = {
        name: uo.name,
        address: uoAddr,
      };

      // Registrar la UO en su DG
      await dgContract.write.registerUnidadOperativa([uoAddr, uo.name, uo.code]);

      // Autorizar la UO en el ArcatRegistry
      await arcatRegistry.write.authorizeUO([uoAddr]);

      allUOAddrs.push(uoAddr);
      console.log(`      🏛️  UO ${uo.code} (${uo.name}): ${uoAddr}`);
    }
  }

  // ── 4. Resumen y guardado ────────────────────────────────────────────────────
  console.log("\n⏳ [4/4] Guardando configuracion...");

  const outDir  = path.resolve("deployments");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `${network}_arcat.json`);
  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
  console.log(`   📄 Deploy guardado en: deployments/${network}_arcat.json`);

  // Actualizar .env con todas las variables ARCAT
  updateEnvArcat(output, network);

  // ── Resumen Final ────────────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║              Deploy ARCAT SBT exitoso ✅                    ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║ ArcatRoot     : ${arcatRootAddr.slice(0, 22)}...  ║`);
  console.log(`║ ArcatRegistry : ${arcatRegistryAddr.slice(0, 22)}...  ║`);
  console.log(`║ DG desplegadas: 4                                           ║`);
  console.log(`║ UO desplegadas: ${String(allUOAddrs.length).padEnd(43)}║`);
  console.log("╚══════════════════════════════════════════════════════════════╝");
}

// ─── Actualización de .env ────────────────────────────────────────────────────

function updateEnvArcat(output, network) {
  const envPath = path.resolve(".env");
  if (!fs.existsSync(envPath)) {
    console.warn("   ⚠️  No se encontro .env");
    return;
  }

  const vars = {};

  vars["CONTRACT_ARCAT_ROOT"]     = output.contracts.ArcatRoot;
  vars["CONTRACT_ARCAT_REGISTRY"] = output.contracts.ArcatRegistry;
  vars["VITE_ARCAT_ROOT"]         = output.contracts.ArcatRoot;
  vars["VITE_ARCAT_REGISTRY"]     = output.contracts.ArcatRegistry;

  // DG addresses
  for (const [code, info] of Object.entries(output.contracts.DireccionesGenerales)) {
    const key = `CONTRACT_DG_${code.replace(/-/g, "_")}`;
    vars[key] = info.address;
    vars[`VITE_${key}`] = info.address;
  }

  // UO addresses
  for (const [dgCode, uos] of Object.entries(output.contracts.UnidadesOperativas)) {
    for (const [uoCode, info] of Object.entries(uos)) {
      const key = `CONTRACT_${uoCode.replace(/-/g, "_")}`;
      vars[key] = info.address;
      vars[`VITE_${key}`] = info.address;
    }
  }

  let content = fs.readFileSync(envPath, "utf-8");

  // Bloque ARCAT en .env
  const arcatBlock = "\n# ─── ARCAT Multicontratos SBT ────────────────────────────────\n";
  if (!content.includes("ARCAT Multicontratos SBT")) {
    content += arcatBlock;
  }

  for (const [key, value] of Object.entries(vars)) {
    const regex = new RegExp(`^${key}=.*$`, "m");
    const line  = `${key}=${value}`;
    if (regex.test(content)) {
      content = content.replace(regex, line);
    } else {
      content += `\n${line}`;
    }
  }

  fs.writeFileSync(envPath, content);
  console.log(`   ✅ .env actualizado con ${Object.keys(vars).length} variables ARCAT`);

  // También guardar un .env.arcat como referencia
  const arcatEnvPath = path.resolve(`.env.arcat.${network}`);
  const arcatEnvContent = Object.entries(vars)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
  fs.writeFileSync(arcatEnvPath, arcatEnvContent);
  console.log(`   📝 Referencia guardada en: .env.arcat.${network}`);
}

main().catch((error) => {
  console.error("\n❌ Deploy ARCAT fallido:", error.message);
  process.exit(1);
});
