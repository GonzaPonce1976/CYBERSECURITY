/**
 * check_contracts_alive.js  v1.2
 * Soporte dual: Anvil (--state) y Hardhat (sin persistencia nativa).
 *
 * Exit 0 = contratos ACTIVOS en blockchain (skip redeploy)
 * Exit 1 = contratos INACTIVOS o modo Hardhat (requiere deploy)
 *
 * Logica:
 *   - Si existe .hardhat_mode  → siempre exit 1 (Hardhat no persiste)
 *   - Si existe .anvil_state.json → verificar bytecode on-chain
 *   - Si ninguno existe       → exit 1 (primera vez)
 */

import http from 'http';
import fs   from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const RPC_URL           = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';
const DEPLOYMENTS_PATH  = path.resolve('deployments/localhost.json');
const ARCAT_DEPLOYMENTS = path.resolve('deployments/localhost_arcat.json');
const ANVIL_STATE_FILE  = path.resolve('.anvil_state.json');
const HARDHAT_MODE_FLAG = path.resolve('.hardhat_mode');

function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    const urlObj  = new URL(RPC_URL);
    const body    = JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() });
    const options = {
      hostname: urlObj.hostname,
      port:     urlObj.port || 8545,
      path:     urlObj.pathname || '/',
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) reject(new Error(`RPC: ${json.error.message}`));
          else            resolve(json.result);
        } catch (e) { reject(new Error(`Parse error: ${e.message}`)); }
      });
    });
    req.on('error', (e) => reject(new Error(`Connection: ${e.message}`)));
    req.setTimeout(4000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

async function hasCode(address) {
  if (!address || address === '0x0000000000000000000000000000000000000000') return false;
  try {
    const code = await rpcCall('eth_getCode', [address, 'latest']);
    return code && code !== '0x' && code.length > 4;
  } catch { return false; }
}

let exitCode = 1;

async function main() {
  console.log('');
  console.log('  [CHECK] Verificando contratos en blockchain local...');
  console.log(`  [CHECK] RPC: ${RPC_URL}`);

  // MODO HARDHAT: sin persistencia nativa, siempre requiere deploy
  if (fs.existsSync(HARDHAT_MODE_FLAG)) {
    console.log('  [CHECK] Modo Hardhat detectado (.hardhat_mode).');
    console.log('  [CHECK] Hardhat no tiene persistencia nativa -> deploy requerido.');
    console.log('  [CHECK] Para persistencia real, instala Foundry: https://getfoundry.sh/');
    return; // exitCode = 1
  }

  // MODO ANVIL: verificar .anvil_state.json
  if (!fs.existsSync(ANVIL_STATE_FILE)) {
    console.log('  [CHECK] .anvil_state.json no encontrado -> deploy inicial requerido.');
    console.log('  [CHECK] Ejecuta SETUP_ANVIL_STATE.bat para configurar persistencia.');
    return;
  }

  // Verificar conectividad
  try {
    const chainIdHex = await rpcCall('eth_chainId');
    const chainId    = parseInt(chainIdHex, 16);
    const blockHex   = await rpcCall('eth_blockNumber');
    const block      = parseInt(blockHex, 16);
    console.log(`  [CHECK] Nodo activo - Chain ID: ${chainId} | Bloque: #${block}`);
  } catch (err) {
    console.error(`  [CHECK] No se puede conectar al nodo: ${err.message}`);
    return;
  }

  if (!fs.existsSync(DEPLOYMENTS_PATH)) {
    console.log('  [CHECK] deployments/localhost.json no encontrado -> deploy requerido.');
    return;
  }

  let allAlive = true;
  const dep = JSON.parse(fs.readFileSync(DEPLOYMENTS_PATH, 'utf8'));
  for (const [name, address] of Object.entries(dep.contracts || {})) {
    const alive = await hasCode(address);
    console.log(`  [CHECK] ${alive ? 'OK  ' : 'DEAD'} ${name.padEnd(24)} ${address}`);
    if (!alive) allAlive = false;
  }

  if (!fs.existsSync(ARCAT_DEPLOYMENTS)) {
    console.log('  [CHECK] deployments/localhost_arcat.json no encontrado.');
    return;
  }

  const arcat     = JSON.parse(fs.readFileSync(ARCAT_DEPLOYMENTS, 'utf8'));
  const contracts = arcat.contracts || {};

  for (const key of ['ArcatRoot', 'ArcatRegistry']) {
    if (contracts[key]) {
      const alive = await hasCode(contracts[key]);
      console.log(`  [CHECK] ${alive ? 'OK  ' : 'DEAD'} ${key.padEnd(24)} ${contracts[key]}`);
      if (!alive) allAlive = false;
    }
  }

  const staffUOs = contracts.UnidadesOperativas?.STAFF || {};
  for (const [uoCode, info] of Object.entries(staffUOs)) {
    const alive = await hasCode(info.address);
    console.log(`  [CHECK] ${alive ? 'OK  ' : 'DEAD'} ${uoCode.padEnd(24)} ${info.address}`);
    if (!alive) allAlive = false;
  }

  console.log('');
  if (allAlive) {
    console.log('  [CHECK] RESULTADO: Todos los contratos ACTIVOS - redeploy NO necesario.');
    exitCode = 0;
  } else {
    console.log('  [CHECK] RESULTADO: Contratos INACTIVOS - redeploy requerido.');
  }
}

main()
  .catch((err) => {
    console.error(`  [CHECK] Error inesperado: ${err.message}`);
    exitCode = 1;
  })
  .finally(() => {
    process.exitCode = exitCode;
  });
