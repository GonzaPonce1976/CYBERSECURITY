/**
 * toast.js — Sistema de notificaciones
 */

const container = () => document.getElementById('toast-container');

export function toast(message, type = 'info', duration = 4000) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container().appendChild(el);
  setTimeout(() => el.remove(), duration);
}
