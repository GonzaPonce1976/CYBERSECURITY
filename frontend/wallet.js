/**
 * wallet.js — Integración con MetaMask (ethers.js v6)
 */
import { toast } from './toast.js';

let provider = null;
let signer = null;
let account = null;

const TARGET_CHAIN = parseInt(import.meta.env.VITE_CHAIN_ID || '31337');
const NETWORK_NAME = import.meta.env.VITE_NETWORK_NAME || 'Hardhat Local';

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
    });
    window.ethereum.on('chainChanged', () => window.location.reload());

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

function updateWalletUI(addr) {
  const btn = document.getElementById('btn-wallet');
  const text = document.getElementById('wallet-text');
  if (text) text.textContent = shortAddr(addr);
  if (btn) btn.style.background = 'linear-gradient(135deg, #065f46, #047857)';

  // Actualizar chain info en audit view
  const dot = document.querySelector('.chain-dot');
  const network = document.getElementById('chain-network');
  if (dot) dot.classList.add('connected');
  if (network) network.textContent = `${NETWORK_NAME} | ${shortAddr(addr)}`;
}

function shortAddr(addr) {
  if (!addr) return '';
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

export function getSigner() { return signer; }
export function getProvider() { return provider; }
export function getAccount() { return account; }
