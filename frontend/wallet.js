/**
 * wallet.js — Integración con MetaMask (ethers.js v6)
 */
import { toast } from './toast.js';

let provider = null;
let signer = null;
let account = null;

const TARGET_CHAIN = parseInt(import.meta.env.VITE_CHAIN_ID || '31337');
const NETWORK_NAME = import.meta.env.VITE_NETWORK_NAME || 'Hardhat/Anvil Local';

/**
 * Reconexión silenciosa al cargar la página.
 * Usa eth_accounts (sin popup) para recuperar la sesión de MetaMask
 * si el usuario ya había autorizado el sitio previamente.
 * Retorna la dirección si hay sesión activa, null en caso contrario.
 */
export async function autoConnectWallet() {
  if (!window.ethereum) return null;
  try {
    // eth_accounts NO muestra popup — devuelve [] si no hay sesión autorizada
    const accounts = await window.ethereum.request({ method: 'eth_accounts' });
    if (!accounts || accounts.length === 0) return null;

    const { BrowserProvider } = await import('ethers');
    provider = new BrowserProvider(window.ethereum);
    signer = await provider.getSigner();
    account = accounts[0];

    updateWalletUI(account);

    // Escuchar cambios de cuenta/red
    window.ethereum.on('accountsChanged', ([addr]) => {
      account = addr || null;
      updateWalletUI(addr);
      // Refrescar el indicador ARCAT si la vista está activa
      refreshArcatChainIndicator();
    });
    window.ethereum.on('chainChanged', () => window.location.reload());

    return account;
  } catch {
    return null;
  }
}

export async function connectWallet() {
  if (!window.ethereum) {
    toast('MetaMask no detectado. Instala la extensión.', 'error');
    return null;
  }
  try {
    const { BrowserProvider } = await import('ethers');
    provider = new BrowserProvider(window.ethereum);
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    signer = await provider.getSigner();
    account = await signer.getAddress();

    updateWalletUI(account);
    toast(`Wallet conectada: ${shortAddr(account)}`, 'success');

    // Escuchar cambios de cuenta/red
    window.ethereum.on('accountsChanged', ([addr]) => {
      account = addr || null;
      updateWalletUI(addr);
      refreshArcatChainIndicator();
    });
    window.ethereum.on('chainChanged', () => window.location.reload());

    // Refrescar el indicador ARCAT inmediatamente tras conectar
    refreshArcatChainIndicator();

    return { provider, signer, account };
  } catch (err) {
    toast('Error conectando wallet: ' + err.message, 'error');
    return null;
  }
}

export function initWalletButton() {
  const btn = document.getElementById('btn-wallet');
  const text = document.getElementById('wallet-text');
  if (!btn) return;
  if (!window.ethereum) {
    btn.disabled = true;
    btn.title = 'MetaMask no detectado';
    if (text) text.textContent = 'Instala MetaMask';
  }
}

/**
 * Actualiza la UI del botón wallet y TODOS los indicadores .chain-dot
 * de la aplicación (incluye el del Audit Trail y el del ARCAT Blockchain).
 */
function updateWalletUI(addr) {
  const btn = document.getElementById('btn-wallet');
  const text = document.getElementById('wallet-text');
  if (text) text.textContent = shortAddr(addr);
  if (btn) btn.style.background = 'linear-gradient(135deg, #065f46, #047857)';

  // Actualizar TODOS los chain-dots de la UI (Audit Trail + ARCAT)
  document.querySelectorAll('.chain-dot').forEach(dot => {
    if (addr) dot.classList.add('connected');
    else dot.classList.remove('connected');
  });

  // Texto descriptivo en el indicador del Audit Trail
  const network = document.getElementById('chain-network');
  if (network) network.textContent = `${NETWORK_NAME} | ${shortAddr(addr)}`;
}

/**
 * Refresca solo el indicador de la vista ARCAT sin necesidad de importar main.js.
 * Usa el mismo patrón que updateArcatChainInfo() en main.js.
 */
function refreshArcatChainIndicator() {
  const dot = document.getElementById('arcat-chain-info')?.querySelector('.chain-dot');
  const networkText = document.getElementById('arcat-chain-network');
  if (!dot && !networkText) return; // Vista no activa
  if (account) {
    if (dot) dot.classList.add('connected');
    if (networkText) networkText.textContent = `${NETWORK_NAME} | Admin: ${shortAddr(account)}`;
  } else {
    if (dot) dot.classList.remove('connected');
    if (networkText) networkText.textContent = 'Sin conexión blockchain';
  }
}

function shortAddr(addr) {
  if (!addr) return '';
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

export function getSigner() { return signer; }
export function getProvider() { return provider; }
export function getAccount() { return account; }

