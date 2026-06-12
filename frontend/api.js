/**
 * api.js — Capa de comunicación con el Rust Gateway
 */

const GATEWAY = import.meta.env.VITE_GATEWAY_URL || `${window.location.protocol}//${window.location.hostname}:8080`;

async function request(path, options = {}) {
  const res = await fetch(`${GATEWAY}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const message = data?.message || `HTTP ${res.status}`;
    throw new Error(message);
  }

  if (data?.status === 'error') {
    const message = data.message || 'Error en la API';
    throw new Error(message);
  }

  return data;
}

export const api = {
  // Health
  health: () => request('/api/health'),
  checkBlockchain: () => request('/api/health/blockchain'),

  // Alerts
  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/api/alerts${qs ? '?' + qs : ''}`);
  },
  getAlert: (id) => request(`/api/alerts/${id}`),

  // IP Reputation
  checkIp: (ip) => request(`/api/ip/${ip}/reputation`),
  getExposures: () => request('/api/ip/exposures'),

  // CVE
  getCve: (cveId) => request(`/api/cve/${cveId}`),

  // Audit trail
  getAuditTrail: () => request('/api/audit/trail'),
  logEvent: (payload) => request('/api/audit/log', { method: 'POST', body: JSON.stringify(payload) }),

  // IoC Intelligence — MalwareBazaar (abuse.ch)
  queryHash:       (sha256) => request(`/api/ioc/hash/${sha256}`),
  getIocFeed:      ()       => request('/api/ioc/feed/recent'),
  getIocCorrelate: ()       => request('/api/ioc/correlate'),
  getUrlhausFeed:  ()       => request('/api/ioc/urlhaus/recent'),
  getThreatFoxFeed:()       => request('/api/ioc/threatfox/recent'),

  BASE: GATEWAY,
};
