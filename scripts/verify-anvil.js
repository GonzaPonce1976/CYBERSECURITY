import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

// Cargar variables de entorno
dotenv.config();

const RPC_URL = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
console.log(`📡 Iniciando verificación sistemática de blockchain...`);
console.log(`🔗 Target RPC URL: ${RPC_URL}`);

async function rpcCall(method, params = []) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method,
      params,
      id: Date.now()
    })
  });
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const json = await response.json();
  if (json.error) {
    throw new Error(`RPC error! message: ${json.error.message}`);
  }
  return json.result;
}

async function verify() {
  try {
    // 1. Verificar si responde
    const chainIdHex = await rpcCall('eth_chainId');
    const chainId = parseInt(chainIdHex, 16);
    console.log(`✅ Conexión establecida exitosamente.`);
    const expectedChainId = parseInt(process.env.VITE_CHAIN_ID || '1', 10);
    console.log(`⛓️  Chain ID: ${chainId} ${chainId === expectedChainId ? '(Coincide con configuración)' : ''}`);

    if (chainId !== expectedChainId) {
      console.warn(`⚠️  Advertencia: El Chain ID actual no es ${expectedChainId}.`);
    }

    // 2. Bloque actual
    const blockNumberHex = await rpcCall('eth_blockNumber');
    const blockNumber = parseInt(blockNumberHex, 16);
    console.log(`📦 Bloque actual: #${blockNumber}`);

    // 3. Obtener cuentas y verificar balances
    const accounts = await rpcCall('eth_accounts');
    console.log(`👥 Cuentas disponibles en el nodo: ${accounts.length}`);
    if (accounts.length > 0) {
      const firstAccount = accounts[0];
      const balanceHex = await rpcCall('eth_getBalance', [firstAccount, 'latest']);
      const balanceEth = parseInt(balanceHex, 16) / 1e18;
      console.log(`💰 Cuenta [0]: ${firstAccount}`);
      console.log(`💎 Balance: ${balanceEth.toFixed(4)} ETH`);
    }

    // 4. Verificar contratos desplegados locales (si existen en el deployments/localhost.json)
    const deploymentsPath = path.resolve('deployments/localhost.json');
    if (fs.existsSync(deploymentsPath)) {
      const deployments = JSON.parse(fs.readFileSync(deploymentsPath, 'utf8'));
      console.log(`\n📄 Verificando código de contratos en deployments/localhost.json:`);
      for (const [contractName, address] of Object.entries(deployments.contracts)) {
        const code = await rpcCall('eth_getCode', [address, 'latest']);
        if (code && code !== '0x') {
          console.log(`   ✅ ${contractName} (${address}): ACTIVO (Código bytecode presente)`);
        } else {
          console.log(`   ❌ ${contractName} (${address}): INACTIVO / NO DESPLEGADO (Sin bytecode)`);
        }
      }
    }

    console.log(`\n🎉 Verificación finalizada con éxito.`);
  } catch (err) {
    console.error(`\n❌ Falló la verificación sistemática:`);
    console.error(`   ${err.message}`);
    console.error(`\n⚠️  Asegúrate de que Anvil o Hardhat estén corriendo en ${RPC_URL}`);
    process.exitCode = 1;
  }
}

verify();
