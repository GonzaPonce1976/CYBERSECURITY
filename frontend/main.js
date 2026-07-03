/**
 * main.js — Punto de entrada del dashboard CyberSec DApp
 */
import { api } from './api.js';
import { toast } from './toast.js';
import { connectWallet, initWalletButton, getAccount, getSigner, autoConnectWallet } from './wallet.js';
import {
  initSeverityChart, updateSeverityChart,
  initTimelineChart, pushTimelinePoint,
} from './charts.js';

// ── Estado global ────────────────────────────────────────────
const state = {
  alerts: [],
  ws: null,
  wsConnected: false,
  wsMessageCount: 0,
  gatewayOnline: false,
  refreshInterval: null,
  demoMode: false,
  demoInterval: null,
  demoCounter: 0,
};

const DEMO_SEVERITIES = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW', 'INFO'];
const DEMO_DESCRIPTIONS = [
  'Brute force SSH detectado - 1247 intentos en 5min',
  'Malware Emotet detectado en agent-windows-03',
  'SQL Injection en endpoint /api/users',
  'Escaneo de puertos desde IP externa',
  'Acceso fallido a /admin - 15 intentos',
  'Archivo sospechoso en /tmp/cryptominer.sh',
  'Certificado SSL expirado en servicio web',
];
const DEMO_TACTICS = ['Credential Access', 'Execution', 'Initial Access', 'Discovery', 'Persistence'];
const DEMO_AGENTS = ['agent-linux-01', 'agent-windows-03', 'agent-db-02', 'agent-web-01'];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function createDemoAlert() {
  const i = state.demoCounter++;
  const severity = randomItem(DEMO_SEVERITIES);
  const description = randomItem(DEMO_DESCRIPTIONS);
  const agent_name = randomItem(DEMO_AGENTS);
  const timestamp = new Date(Date.now() - Math.floor(Math.random() * 25 * 60000)).toISOString();

  return {
    id: `demo-${Date.now()}-${i}`,
    severity,
    description,
    src_ip: `${10 + (i % 240)}.${20 + (i % 200)}.${i % 255}.${100 + (i % 100)}`,
    agent_name,
    agent_ip: i === 0 ? "192.168.125.250" : `192.168.125.${20 + (i % 200)}`,
    mitre_tactics: [randomItem(DEMO_TACTICS)],
    timestamp,
    on_chain: i % 4 === 0,
    rule_level: 5 + (i % 10),
  };
}

function startDemoAlerts() {
  if (state.demoInterval) return;
  state.demoMode = true;
  state.demoInterval = setInterval(() => {
    if (!state.demoMode) return;
    const newAlert = createDemoAlert();
    state.alerts.unshift(newAlert);
    if (state.alerts.length > 50) state.alerts.pop();
    renderDashboard();
    renderAlertsTable();
    toast(`Nueva alerta demo: ${newAlert.description}`, 'info', 2500);
  }, 12000);
}

function stopDemoAlerts() {
  state.demoMode = false;
  if (state.demoInterval) {
    clearInterval(state.demoInterval);
    state.demoInterval = null;
  }
}

// ── Utilidades ───────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function severityBadge(sev) {
  const s = (sev || 'INFO').toUpperCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

function timeAgo(isoStr) {
  if (!isoStr) return '—';
  const diff = Date.now() - new Date(isoStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'justo ahora';
  if (m < 60) return `hace ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

function countBySeverity(alerts) {
  return Object.fromEntries(
    severityOrder.map(s => [s, alerts.filter(a => (a.severity || '').toUpperCase() === s).length])
  );
}

// ── Router de vistas ─────────────────────────────────────────
function initRouter() {
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.dataset.view;
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`view-${view}`)?.classList.add('active');
    });
  });
}

// ── Gateway Health ───────────────────────────────────────────
async function checkGatewayHealth() {
  try {
    const data = await api.health();
    state.gatewayOnline = data.status === 'ok';
    const dot = $('gateway-status')?.querySelector('.status-dot');
    if (dot) { dot.classList.toggle('online', state.gatewayOnline); dot.classList.toggle('offline', !state.gatewayOnline); }
  } catch {
    state.gatewayOnline = false;
    const dot = $('gateway-status')?.querySelector('.status-dot');
    if (dot) { dot.classList.remove('online'); dot.classList.add('offline'); }
  }
}

function getWebSocketUrl() {
  const envUrl = import.meta.env.VITE_WS_URL;
  if (envUrl) return envUrl;

  // En desarrollo con Vite, usamos la ruta relativa para que el proxy /ws funcione.
  if (typeof window !== 'undefined') {
    return `ws://${window.location.hostname}:8080/ws/alerts`;
  }

  return '/ws/alerts';
}

// ── WebSocket ────────────────────────────────────────────────
function initWebSocket() {
  const WS_URL = getWebSocketUrl();
  const dot = $('ws-indicator')?.querySelector('.ws-dot');

  try {
    if (!/^wss?:\/\//.test(WS_URL)) {
      throw new Error(`URL de WebSocket inválida: ${WS_URL}`);
    }

    state.ws = new WebSocket(WS_URL);

    state.ws.onopen = () => {
      state.wsConnected = true;
      if (dot) dot.classList.add('connected');
      toast('WebSocket conectado — alertas en tiempo real', 'success', 3000);
    };

    state.ws.onmessage = (e) => {
      state.wsMessageCount++;
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'alerts_update' && Array.isArray(msg.data)) {
          msg.data.forEach(alert => {
            const exists = state.alerts.find(a => a.id === alert.id);
            if (!exists) {
              state.alerts.unshift(alert);
              if (alert.severity === 'CRITICAL') toast(`🚨 Alerta crítica: ${alert.description?.slice(0, 60)}`, 'error');
            }
          });
          renderDashboard();
        }
      } catch { /* ignorar mensajes malformados */ }
    };

    state.ws.onclose = () => {
      state.wsConnected = false;
      if (dot) dot.classList.remove('connected');
      // Reconectar en 10s
      setTimeout(initWebSocket, 10000);
    };

    state.ws.onerror = (error) => {
      console.error('[WebSocket] Error de conexión:', WS_URL, error);
      toast('Error de WebSocket: no se pudo conectar al gateway de alertas.', 'error', 5000);
      if (state.ws && state.ws.readyState !== WebSocket.CLOSED) {
        state.ws.close();
      }
    };
  } catch (err) {
    console.warn('[WebSocket] No se pudo inicializar el socket:', err);
    toast('Error de WebSocket: URL inválida o servicio inaccesible.', 'error', 5000);
  }
}

// ── Cargar Alertas ───────────────────────────────────────────
async function loadAlerts() {
  try {
    const data = await api.getAlerts({ limit: 100 });
    state.gatewayOnline = true;
    stopDemoAlerts();
    if (data.data) state.alerts = data.data;
    renderDashboard();
    renderAlertsTable();
  } catch {
    // Gateway no disponible — usar datos demo y generar alertas automáticas
    state.gatewayOnline = false;
    state.alerts = generateDemoAlerts();
    renderDashboard();
    renderAlertsTable();
    startDemoAlerts();
  }
}

// ── Demo Data (cuando el gateway no está disponible) ─────────
function generateDemoAlerts() {
  state.demoCounter = 0;
  return Array.from({ length: 18 }, () => createDemoAlert());
}

// ── Render Dashboard ─────────────────────────────────────────
function renderDashboard() {
  const alerts = state.alerts;
  const counts = countBySeverity(alerts);

  // KPIs
  $('kpi-total-value').textContent = alerts.length;
  $('kpi-critical-value').textContent = counts.CRITICAL;
  $('kpi-high-value').textContent = counts.HIGH;
  $('kpi-onchain-value').textContent = alerts.filter(a => a.on_chain).length;

  // Last update
  $('last-update').textContent = `Actualizado: ${new Date().toLocaleTimeString('es')}`;

  // Charts
  updateSeverityChart(counts);
  pushTimelinePoint(counts.CRITICAL, counts.HIGH);

  // Recent alerts (últimas 8)
  renderAlertsRows('recent-alerts-table', alerts.slice(0, 8));

  // Badge count
  $('alerts-count-badge').textContent = alerts.length;

  // MITRE tags
  const allTactics = [...new Set(alerts.flatMap(a => a.mitre_tactics || []).filter(Boolean))];
  const mitreContainer = $('mitre-tags');
  if (mitreContainer) {
    mitreContainer.innerHTML = allTactics.length
      ? allTactics.map(t => `<span class="mitre-tag">${t}</span>`).join('')
      : '<p class="text-muted" style="font-size:13px">Sin datos MITRE</p>';
  }
}

function renderAlertsRows(containerId, alerts) {
  const container = $(containerId);
  if (!container) return;

  if (!alerts.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">🛡️</div><p>Sin alertas disponibles</p></div>`;
    return;
  }

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Severidad</th>
          <th>Descripción</th>
          <th>IP Origen</th>
          <th>Agente</th>
          <th>Tiempo</th>
          <th>On-Chain</th>
        </tr>
      </thead>
      <tbody>
        ${alerts.map(a => `
          <tr>
            <td>${severityBadge(a.severity)}</td>
            <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.description || ''}">${a.description || '—'}</td>
            <td class="mono">${a.src_ip || '—'}</td>
            <td class="agent-cell">
              ${(() => {
                const host = a.source_agent || a.agent_name;
                const sub  = (a.source_agent && a.agent_name && a.source_agent !== a.agent_name) ? a.agent_name : null;
                const ip   = a.agent_ip;
                return host
                  ? `<span class="agent-host" title="Equipo: ${host}">&#x1F4BB; ${host}</span>
                     ${ip ? `<br><span class="agent-ip" title="IP: ${ip}">&#x1F310; ${ip}</span>` : ''}
                     ${sub ? `<br><span class="agent-sub">${sub}</span>` : ''}`
                  : '<span class="text-muted">—</span>';
              })()}
            </td>
            <td class="text-muted">${timeAgo(a.timestamp)}</td>
            <td>${a.on_chain ? '<span style="color:var(--green)">&#x26D3;&#xFE0F;</span>' : '<span class="text-muted">—</span>'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// ── Alerts View ──────────────────────────────────────────────
function renderAlertsTable() {
  const sevFilter = $('filter-severity')?.value || '';
  const search = ($('filter-search')?.value || '').toLowerCase();

  const filtered = state.alerts.filter(a => {
    const matchSev = !sevFilter || (a.severity || '').toUpperCase() === sevFilter;
    const matchSearch = !search ||
      (a.description || '').toLowerCase().includes(search) ||
      (a.src_ip || '').toLowerCase().includes(search) ||
      (a.agent_name || '').toLowerCase().includes(search) ||
      (a.source_agent || '').toLowerCase().includes(search) ||
      (a.agent_ip || '').toLowerCase().includes(search);
    return matchSev && matchSearch;
  });

  renderAlertsRows('alerts-table-full', filtered);
}

function initAlertsFilters() {
  $('filter-severity')?.addEventListener('change', renderAlertsTable);
  $('filter-input')?.addEventListener('input', renderAlertsTable);
  // Fix ID
  document.getElementById('filter-search')?.addEventListener('input', renderAlertsTable);
}

// ── IP Reputation View ───────────────────────────────────────
function initIpView() {
  $('btn-check-ip')?.addEventListener('click', checkIp);
  $('ip-input')?.addEventListener('keydown', e => e.key === 'Enter' && checkIp());

  document.querySelectorAll('.example-tag[data-value]').forEach(tag => {
    tag.addEventListener('click', () => {
      const input = $('ip-input');
      if (input) { input.value = tag.dataset.value; checkIp(); }
    });
  });
}

async function loadPerimetralExposures() {
  const tbody = $('exposures-tbody');
  const countBadge = $('exposures-count-badge');
  if (!tbody) return;

  try {
    const data = await api.getExposures();
    const exposures = data.data || [];
    
    if (countBadge) {
      countBadge.textContent = exposures.length;
    }

    if (!exposures.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="empty-state">
            <div class="empty-icon">🛡️</div>
            <p>No se encontraron IP expuestas en el historial perimetral.</p>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = exposures.map(exp => {
      const shodan = exp.shodan || {};
      const ip = exp.ip || '—';
      const os = shodan.os || '—';
      const org = shodan.org || shodan.isp || '—';
      const osOrg = os !== '—' && org !== '—' ? `${os} / ${org}` : os !== '—' ? os : org;
      
      const ports = shodan.ports || [];
      const portsHtml = ports.length > 0 
        ? ports.map(p => `<span class="exposure-port-badge">${p}</span>`).join(' ')
        : '<span class="text-muted">Ninguno</span>';

      const vulns = shodan.vulnerabilities || [];
      const vulnsHtml = vulns.length > 0
        ? vulns.map(v => `<span class="exposure-vuln-badge" title="${v}">${v}</span>`).join(' ')
        : '<span class="text-muted">Ninguna</span>';

      const dateStr = exp.scanned_at ? new Date(exp.scanned_at).toLocaleString('es') : '—';

      return `
        <tr>
          <td><a href="#" class="exposure-ip-link mono" data-ip="${ip}">${ip}</a></td>
          <td>${portsHtml}</td>
          <td>${vulnsHtml}</td>
          <td>${osOrg}</td>
          <td class="text-muted">${dateStr}</td>
        </tr>
      `;
    }).join('');

    // Bind click events to IP links
    tbody.querySelectorAll('.exposure-ip-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const ip = link.dataset.ip;
        if (!ip) return;

        // Switch to IP tab
        const ipNavBtn = $('nav-ip');
        if (ipNavBtn) {
          ipNavBtn.click();
        }

        // Fill input and check
        const ipInput = $('ip-input');
        if (ipInput) {
          ipInput.value = ip;
          checkIp();
        }
      });
    });

  } catch (err) {
    console.error('Error cargando auditoría perimetral:', err);
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">
          <div class="empty-icon" style="color:var(--red)">⚠️</div>
          <p>Error cargando datos de exposición: ${err.message}</p>
        </td>
      </tr>
    `;
  }
}

async function checkIp() {
  const ip = $('ip-input')?.value?.trim();
  if (!ip) return;

  const btn = $('btn-check-ip');
  btn.textContent = 'Analizando...';
  btn.disabled = true;

  try {
    const data = await api.checkIp(ip);
    renderIpResult(ip, data.data || data);
    // Refrescar lista de exposiciones en el dashboard
    loadPerimetralExposures().catch(() => {});
  } catch (err) {
    toast(`Error consultando IP: ${err.message}`, 'error');
  } finally {
    btn.textContent = 'Analizar';
    btn.disabled = false;
  }
}

function renderIpResult(ip, data) {
  const panel = $('ip-result');
  if (!panel) return;
  panel.classList.remove('hidden');

  $('ip-result-title').textContent = data.ip || ip;

  // Score ring
  const abuseScore = data.abuseipdb?.abuse_score ?? data.abuse_score ?? 0;
  $('ring-score').textContent = abuseScore;
  const fill = $('ring-fill');
  const circumference = 264;
  const offset = circumference - (abuseScore / 100) * circumference;
  fill.style.strokeDashoffset = offset;
  const color = abuseScore > 75 ? '#ff3a5c' : abuseScore > 40 ? '#ff7b00' : '#00ff9d';
  fill.style.stroke = color;

  // Sources grid
  const grid = $('ip-sources-grid');
  if (!grid) return;

  const abuse = data.abuseipdb || {};
  const vt = data.virustotal || {};
  const gn = data.greynoise || {};
  const otx = data.otx || {};
  const shodan = data.shodan || {};

  grid.innerHTML = `
    <div class="ip-source-card">
      <div class="ip-source-title">🛡️ AbuseIPDB</div>
      ${abuse.error ? sourceErrorRow(abuse.error) : `
        ${row('Score', `${abuse.abuse_score ?? '—'}%`)}
        ${row('País', abuse.country_code || '—')}
        ${row('ISP', abuse.isp || '—')}
        ${row('Reportes', abuse.total_reports ?? '—')}
        ${row('Whitelist', abuse.is_whitelisted === true ? 'Sí' : abuse.is_whitelisted === false ? 'No' : '—')}
      `}
    </div>
    <div class="ip-source-card">
      <div class="ip-source-title">🔎 VirusTotal</div>
      ${vt.error ? sourceErrorRow(vt.error) : `
        ${row('Reputación', vt.reputation != null ? vt.reputation : '—')}
        ${row('Malicioso', vt.is_malicious ? '🚨 Sí' : '✅ No')}
        ${row('AVs Detectaron', vt.malicious_count != null ? `${vt.malicious_count}/${vt.total_engines ?? '—'}` : '—')}
        ${row('ASN / Owner', vt.as_owner || '—')}
        ${row('País', vt.country || '—')}
      `}
    </div>
    <div class="ip-source-card">
      <div class="ip-source-title">🌐 GreyNoise</div>
      ${gn.error ? sourceErrorRow(gn.error) : `
        ${row('Clasificación', gn.classification || '—')}
        ${row('Noise', gn.noise ? '✅ Sí' : '❌ No')}
        ${row('RIOT', gn.riot ? '✅ Sí' : '❌ No')}
        ${row('Nombre', gn.name || '—')}
        ${row('Último visto', gn.last_seen || '—')}
      `}
    </div>
    <div class="ip-source-card">
      <div class="ip-source-title">👁️ AlienVault OTX</div>
      ${otx.error ? sourceErrorRow(otx.error) : `
        ${row('Pulses', otx.pulse_count ?? '—')}
        ${row('Malicioso', otx.is_malicious ? '🚨 Sí' : '✅ No')}
        ${row('País', otx.country || '—')}
        ${row('Familias', (otx.malware_families || []).join(', ') || '—')}
        ${row('MITRE IDs', (otx.mitre_attack_ids || []).join(', ') || '—')}
      `}
    </div>
    <div class="ip-source-card">
      <div class="ip-source-title">🎯 Shodan Exposición</div>
      ${shodan.error ? sourceErrorRow(shodan.error) : `
        ${row('Exposición', shodan.ports && shodan.ports.length > 0 ? '<span style="color:var(--red);font-weight:bold">🚨 Expuesto</span>' : '<span style="color:var(--green);font-weight:bold">✅ Seguro</span>')}
        ${row('Puertos Abiertos', shodan.ports && shodan.ports.length > 0 ? shodan.ports.map(p => `<span style="background:rgba(255,58,92,0.15);color:#ff3a5c;border:1px solid rgba(255,58,92,0.3);padding:2px 6px;border-radius:4px;font-family:var(--font-mono);font-size:0.75rem;margin-right:4px;font-weight:bold">${p}</span>`).join(' ') : 'Ninguno')}
        ${row('OS Detectado', shodan.os || 'No detectado')}
        ${row('Organización', shodan.org || '—')}
        ${row('Vulnerabilidades', shodan.vulnerabilities && shodan.vulnerabilities.length > 0 ? shodan.vulnerabilities.map(v => `<span style="background:rgba(255,123,0,0.15);color:#ff7b00;border:1px solid rgba(255,123,0,0.3);padding:2px 6px;border-radius:4px;font-family:var(--font-mono);font-size:0.75rem;margin-right:4px;font-weight:bold" title="${v}">${v}</span>`).join(' ') : 'Ninguna')}
      `}
    </div>
  `;
}

function sourceErrorRow(message) {
  return `<div class="ip-source-row ip-source-error"><span class="ip-source-key">Estado</span><span class="ip-source-val">${message}</span></div>`;
}

function row(k, v) {
  return `<div class="ip-source-row"><span class="ip-source-key">${k}</span><span class="ip-source-val">${v}</span></div>`;
}

// ── CVE View ─────────────────────────────────────────────────
function initCveView() {
  $('btn-check-cve')?.addEventListener('click', checkCve);
  $('cve-input')?.addEventListener('keydown', e => e.key === 'Enter' && checkCve());

  document.querySelectorAll('.example-tag[data-target="cve-input"]').forEach(tag => {
    tag.addEventListener('click', () => {
      const input = $('cve-input');
      if (input) { input.value = tag.textContent.trim(); checkCve(); }
    });
  });
}

async function checkCve() {
  const cveId = $('cve-input')?.value?.trim();
  if (!cveId) return;

  const btn = $('btn-check-cve');
  btn.textContent = 'Buscando...';
  btn.disabled = true;

  try {
    const data = await api.getCve(cveId);
    renderCveResult(data.data || data);
  } catch (err) {
    toast(`Error buscando CVE: ${err.message}`, 'error');
    $('cve-result').innerHTML = `
      <div class="cve-card">
        <div class="cve-id" style="color:var(--red)">${cveId}</div>
        <p class="cve-description">CVE no encontrado o error de conexión con NVD API.</p>
      </div>`;
    $('cve-result').classList.remove('hidden');
  } finally {
    btn.textContent = 'Buscar';
    btn.disabled = false;
  }
}

function renderCveResult(cve) {
  const panel = $('cve-result');
  if (!panel) return;
  panel.classList.remove('hidden');

  const score = cve.cvss_score;
  const scoreColor = !score ? '#8892a4' : score >= 9 ? '#ff3a5c' : score >= 7 ? '#ff7b00' : score >= 4 ? '#ffd700' : '#00ff9d';

  panel.innerHTML = `
    <div class="cve-card">
      <div class="cve-id">${cve.id || '—'}</div>
      <p class="cve-description">${cve.description || 'Sin descripción'}</p>
      <div class="cve-meta-grid">
        <div class="cve-meta-item">
          <div class="cve-meta-key">CVSS Score</div>
          <div class="cve-meta-val" style="color:${scoreColor}">${score?.toFixed(1) ?? '—'}</div>
        </div>
        <div class="cve-meta-item">
          <div class="cve-meta-key">Severidad</div>
          <div class="cve-meta-val">${cve.severity ? severityBadge(cve.severity) : '—'}</div>
        </div>
        <div class="cve-meta-item">
          <div class="cve-meta-key">Publicado</div>
          <div class="cve-meta-val" style="font-size:14px">${cve.published ? new Date(cve.published).toLocaleDateString('es') : '—'}</div>
        </div>
      </div>
      ${cve.references?.length ? `
        <div class="cve-refs">
          <div class="cve-refs-title">Referencias (${cve.references.length})</div>
          ${cve.references.slice(0, 5).map(r => `<a class="cve-ref-link" href="${r}" target="_blank" rel="noopener">${r}</a>`).join('')}
        </div>` : ''}
    </div>
  `;
}

// ── Audit View ───────────────────────────────────────────────
async function loadAuditTrail() {
  try {
    const data = await api.getAuditTrail();
    $('audit-total').textContent = data.data?.length ?? 0;
    renderAuditTable(data.data || []);
  } catch {
    $('audit-total').textContent = '—';
  }
}

function renderAuditTable(events) {
  const container = $('audit-table');
  if (!container) return;
  if (!events.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">⛓️</div><p>Sin eventos on-chain registrados aún</p></div>`;
    return;
  }
  container.innerHTML = `
    <table>
      <thead><tr><th>ID</th><th>Severidad</th><th>Tipo</th><th>Descripción</th><th>TX Hash</th></tr></thead>
      <tbody>
        ${events.map(e => `
          <tr>
            <td class="mono">#${e.id ?? '—'}</td>
            <td>${severityBadge(e.severity)}</td>
            <td class="mono">${e.event_type || '—'}</td>
            <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.description || '—'}</td>
            <td class="mono text-muted">${e.blockchain_tx ? e.blockchain_tx.slice(0, 14) + '…' : '—'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// ── Servicios View ──────────────────────────────────────────
function setBadge(id, online, label) {
  const el = $(id);
  if (!el) return;
  el.textContent = online ? label || 'Online' : 'Offline';
  el.className = 'service-badge ' + (online ? 'badge-online' : 'badge-offline');
}

async function checkBlockchain() {
  try {
    const data = await api.checkBlockchain();
    if (data.online) {
      return { online: true, block: parseInt(data.block, 10), contract: data.contract };
    }
    return { online: false, block: null, contract: null };
  } catch {
    return { online: false, block: null, contract: null };
  }
}

async function refreshServicesView() {
  // ── Gateway ──
  try {
    const h = await api.health();
    setBadge('svc-gateway-badge', true, 'Online');
    const uptimeSecs = h.uptime_seconds ?? 0;
    const hh = String(Math.floor(uptimeSecs / 3600)).padStart(2, '0');
    const mm = String(Math.floor((uptimeSecs % 3600) / 60)).padStart(2, '0');
    const ss = String(uptimeSecs % 60).padStart(2, '0');
    $('svc-gw-uptime').textContent = `${hh}:${mm}:${ss}`;
    $('svc-gw-alerts').textContent = h.cache?.alerts ?? 0;
    $('svc-gw-ips').textContent    = h.cache?.ips ?? 0;
    const apis = h.apis_configured ?? {};
    const configuredCount = Object.values(apis).filter(Boolean).length;
    $('svc-gw-apis').textContent = `${configuredCount} / ${Object.keys(apis).length}`;
    $('svc-gw-version').textContent = h.version ?? '—';
    $('svc-wazuh-cfg').textContent  = apis.wazuh ? '✅ Sí' : '⚠️ No';
    setBadge('svc-wazuh-badge', apis.wazuh, apis.wazuh ? 'Configurado' : 'Sin config');
    $('svc-shodan-cfg').textContent  = apis.shodan ? '✅ API Key activa' : '⚙️ Modo simulado';
    setBadge('svc-shodan-badge', true, apis.shodan ? 'Configurado' : 'Simulado');
  } catch {
    setBadge('svc-gateway-badge', false);
    ['svc-gw-uptime','svc-gw-alerts','svc-gw-ips','svc-gw-apis','svc-gw-version'].forEach(id => { const el=$(id); if(el) el.textContent='—'; });
  }

  // ── WebSocket ──
  const wsOnline = state.wsConnected;
  setBadge('svc-ws-badge', wsOnline, wsOnline ? 'Conectado' : 'Desconectado');
  $('svc-ws-status').textContent  = wsOnline ? '🟢 Conectado' : '🔴 Desconectado';
  $('svc-ws-count').textContent   = state.wsMessageCount;

  // ── Blockchain (Anvil) ──
  const chain = await checkBlockchain();
  setBadge('svc-blockchain-badge', chain.online, chain.online ? 'Mining' : 'Offline');
  const targetChain = import.meta.env.VITE_CHAIN_ID || '1';
  $('svc-chain-network').textContent = chain.online ? `Hardhat / Anvil — Chain ${targetChain}` : '—';
  const subtitleEl = $('svc-chain-rpc-subtitle');
  if (subtitleEl) {
    subtitleEl.textContent = `http://localhost:8545 · Chain ${targetChain}`;
  }
  $('svc-chain-block').textContent   = chain.block != null ? `#${chain.block}` : '—';
  const contractAddr = chain.contract || import.meta.env.VITE_CONTRACT_SECURITY_AUDIT;
  $('svc-chain-contract').textContent = contractAddr
    ? contractAddr.slice(0, 8) + '…' + contractAddr.slice(-6)
    : '⚠️ No desplegado';
}

function initServicesView() {
  document.getElementById('nav-servicios')?.addEventListener('click', refreshServicesView);
  document.getElementById('btn-refresh-services')?.addEventListener('click', refreshServicesView);
}

// ── Refresh ──────────────────────────────────────────────────
$('btn-refresh')?.addEventListener('click', async () => {
  await loadAlerts();
  await loadPerimetralExposures().catch(() => {});
  toast('Datos actualizados', 'info', 2000);
});

// ── IoC Intelligence — MalwareBazaar ─────────────────────────────

/** Carga correlaciones y actualiza tanto el Dashboard como la pestaña IoC */
async function loadIocCorrelations() {
  try {
    const res = await api.getIocCorrelate();
    renderIocCorrelations(res);
    renderMbDashboardCard(res);
  } catch (e) {
    console.warn('IoC correlate error:', e);
  }
}

/** Renderiza el panel de correlaciones en la vista IoC */
function renderIocCorrelations(res) {
  const body = $('ioc-correlations-body');
  const badge = $('ioc-correlations-count');
  if (!body) return;

  const items = res?.data || [];
  if (badge) badge.textContent = items.length;

  if (!items.length) {
    body.innerHTML = `<div class="empty-state"><div class="empty-icon">🛡️</div>
      <p>${res?.message || 'Sin correlaciones detectadas en las alertas actuales'}</p></div>`;
    return;
  }

  body.innerHTML = items.map(c => {
    const conf = c.confidence || 0;
    const confClass = conf >= 90 ? 'critical' : conf >= 80 ? 'high' : conf >= 70 ? 'medium' : 'low';
    const samples = (c.mb_samples || []).slice(0, 2);
    return `
      <div class="ioc-correlation-item">
        <div class="ioc-corr-header">
          <span class="ioc-family-badge ioc-threat-${confClass}">${c.malware_family}</span>
          <div class="ioc-conf-bar-wrap">
            <div class="ioc-conf-bar" style="width:${conf}%" data-class="${confClass}"></div>
            <span class="ioc-conf-label">${conf}%</span>
          </div>
        </div>
        <div class="ioc-corr-meta">
          <span>📨 ${c.alerts_matched} alerta${c.alerts_matched !== 1 ? 's' : ''} coincidentes</span>
          <span>🦠 ${c.mb_samples_found} muestra${c.mb_samples_found !== 1 ? 's' : ''} en MB</span>
        </div>
        ${samples.map(s => `
          <div class="ioc-sample-row">
            <code class="ioc-hash">${s.sha256 || ''}…</code>
            <span class="ioc-fname">${s.file_name || '?'}</span>
            <span class="ioc-country">${s.origin_country || '?'}</span>
            <a href="${s.reference}" target="_blank" class="ioc-ref-link">MB↗</a>
          </div>`).join('')}
        <a href="${c.mb_reference}" target="_blank" class="ioc-mb-tag-link">Ver tag en MalwareBazaar ↗</a>
      </div>`;
  }).join('');
}

/** Actualiza la tarjeta MalwareBazaar del Dashboard principal */
function renderMbDashboardCard(res) {
  const tbody = $('mb-correlations-tbody');
  const badge = $('mb-correlations-badge');
  if (!tbody) return;

  const items = res?.data || [];
  if (badge) badge.textContent = items.length;

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="empty-icon">🛡️</div><p>Sin correlaciones</p></td></tr>`;
    return;
  }

  tbody.innerHTML = items.map(c => {
    const conf = c.confidence || 0;
    const confClass = conf >= 90 ? 'critical' : conf >= 80 ? 'high' : conf >= 70 ? 'medium' : 'low';
    return `<tr>
      <td><span class="badge badge-${confClass.toUpperCase()}">${c.malware_family}</span></td>
      <td><span class="ioc-conf-inline">${conf}%</span></td>
      <td>${c.alerts_matched}</td>
      <td>${c.mb_samples_found}</td>
      <td><a href="${c.mb_reference}" target="_blank" class="ioc-ref-link">↗ MB</a></td>
    </tr>`;
  }).join('');
}

/** Carga el feed reciente de MalwareBazaar */
async function loadIocFeed() {
  const body = $('ioc-feed-body');
  if (!body) return;
  try {
    const res = await api.getIocFeed();
    const items = res?.data || [];
    if (!items.length) {
      body.innerHTML = `<div class="empty-state"><div class="empty-icon">📡</div><p>Sin muestras recientes</p></div>`;
      return;
    }
    body.innerHTML = items.map(s => `
      <div class="ioc-feed-item">
        <div class="ioc-feed-header">
          <span class="ioc-signature">${s.signature || s.tags?.[0] || 'Desconocido'}</span>
          <span class="ioc-ftype badge-INFO">${s.file_type || '?'}</span>
        </div>
        <div class="ioc-feed-meta">
          <code class="ioc-hash-sm">${(s.sha256_hash || '').slice(0,20)}…</code>
          <span>${s.file_name || 'sin nombre'}</span>
          <span class="ioc-country">📍${s.origin_country || '??'}</span>
          <a href="${s.reference}" target="_blank" class="ioc-ref-link">↗</a>
        </div>
        <div class="ioc-tags">
          ${(s.tags || []).slice(0, 4).map(t => `<span class="ioc-tag">${t}</span>`).join('')}
        </div>
      </div>`).join('');
  } catch (e) {
    body.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>${e.message}</p></div>`;
  }
}

/** Busca un hash específico en MalwareBazaar */
async function loadUrlhausFeed() {
  const body = $('ioc-urlhaus-body');
  if (!body) return;
  try {
    const res = await api.getUrlhausFeed();
    const items = res?.data || [];
    if (!items.length) {
      body.innerHTML = `<div class="empty-state"><div class="empty-icon">🔗</div><p>Sin URLs recientes</p></div>`;
      return;
    }
    body.innerHTML = items.map(s => `
      <div class="ioc-feed-item">
        <div class="ioc-feed-header">
          <span class="ioc-signature">${s.threat || 'Malware Download'}</span>
          <span class="ioc-ftype badge-CRITICAL">${s.url_status || 'online'}</span>
        </div>
        <div class="ioc-feed-meta">
          <code class="ioc-hash-sm" style="color:var(--red)">${(s.url || '').slice(0,40)}…</code>
          <span>IP: ${s.host || '??'}</span>
          <a href="${s.urlhaus_reference}" target="_blank" class="ioc-ref-link">↗</a>
        </div>
        <div class="ioc-tags">
          ${(s.tags || []).slice(0, 4).map(t => `<span class="ioc-tag">${t}</span>`).join('')}
        </div>
      </div>`).join('');
  } catch (e) {
    body.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>${e.message}</p></div>`;
  }
}

async function loadThreatFoxFeed() {
  const body = $('ioc-threatfox-body');
  if (!body) return;
  try {
    const res = await api.getThreatFoxFeed();
    const items = res?.data || [];
    if (!items.length) {
      body.innerHTML = `<div class="empty-state"><div class="empty-icon">🦊</div><p>Sin IoCs recientes</p></div>`;
      return;
    }
    body.innerHTML = items.map(s => {
      const isHighConf = (s.confidence_level || 0) >= 75;
      const badgeCls = isHighConf ? 'badge-CRITICAL' : 'badge-HIGH';
      return `
      <div class="ioc-feed-item">
        <div class="ioc-feed-header">
          <span class="ioc-signature">${s.malware_printable || s.malware || 'Unknown'}</span>
          <span class="ioc-ftype ${badgeCls}">${s.threat_type || '?'}</span>
        </div>
        <div class="ioc-feed-meta">
          <code class="ioc-hash-sm">${s.ioc || ''}</code>
          <span>Conf: ${s.confidence_level}%</span>
        </div>
        <div class="ioc-tags">
          ${(s.tags || []).slice(0, 4).map(t => `<span class="ioc-tag">${t}</span>`).join('')}
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    body.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>${e.message}</p></div>`;
  }
}

/** Busca un hash específico en MalwareBazaar */
async function searchIocHash() {
  const input = $('ioc-hash-input');
  const panel = $('ioc-hash-result');
  if (!input || !panel) return;
  const hash = input.value.trim();
  if (!hash) return;

  panel.style.display = 'block';
  panel.innerHTML = `<div class="ioc-result-loading"><div class="spin">⏳</div> Consultando MalwareBazaar...</div>`;

  try {
    const res = await api.queryHash(hash);
    if (!res.found || !res.data) {
      panel.innerHTML = `<div class="ioc-result-empty">✅ Hash <code>${hash.slice(0,16)}…</code> no encontrado en MalwareBazaar — no está catalogado como malware conocido.</div>`;
      return;
    }
    const d = res.data;
    const tags = (d.tags || []).map(t => `<span class="ioc-tag">${t}</span>`).join('');
    const clamav = (d.clamav || []).join(', ') || '—';
    panel.innerHTML = `
      <div class="ioc-result-card ioc-result-found">
        <div class="ioc-result-title">
          <span class="ioc-family-badge ioc-threat-critical">🦠 ${d.signature || 'Malware Detectado'}</span>
          <a href="https://bazaar.abuse.ch/sample/${hash}/" target="_blank" class="ioc-ref-link">Ver en MalwareBazaar ↗</a>
        </div>
        <div class="ioc-result-grid">
          <div><label>Archivo</label><span>${d.file_name || '—'}</span></div>
          <div><label>Tipo</label><span>${d.file_type || '—'} · ${d.file_size_bytes ? (d.file_size_bytes/1024).toFixed(1)+' KB' : '?'}</span></div>
          <div><label>SHA256</label><code class="ioc-hash">${(d.sha256_hash || hash).slice(0,32)}…</code></div>
          <div><label>MD5</label><code class="ioc-hash-sm">${d.md5_hash || '—'}</code></div>
          <div><label>Primera vez</label><span>${d.first_seen || '—'}</span></div>
          <div><label>Última vez</label><span>${d.last_seen || '—'}</span></div>
          <div><label>Origen</label><span>${d.origin_country || '—'}</span></div>
          <div><label>Entrega</label><span>${d.delivery_method || '—'}</span></div>
          <div><label>ClamAV</label><span>${clamav}</span></div>
          <div><label>Reporter</label><span>${d.reporter || '—'}</span></div>
        </div>
        <div class="ioc-tags">${tags}</div>
      </div>`;
  } catch (e) {
    panel.innerHTML = `<div class="ioc-result-empty">❌ Error: ${e.message}</div>`;
  }
}

/** Inicializa todos los eventos de la vista IoC */
function initIocView() {
  $('btn-ioc-search')?.addEventListener('click', searchIocHash);
  $('ioc-hash-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') searchIocHash(); });
  $('btn-ioc-refresh')?.addEventListener('click', () => { loadIocCorrelations(); loadIocFeed(); loadUrlhausFeed(); loadThreatFoxFeed(); });
  $('nav-ioc')?.addEventListener('click', () => { loadIocCorrelations(); loadIocFeed(); loadUrlhausFeed(); loadThreatFoxFeed(); });
}

// ── ARCAT Blockchain View Logic ──────────────────────────────

async function loadArcatOverview() {
  const treeContainer = $('arcat-hierarchy-tree');
  if (!treeContainer) return;

  // Actualizar la red
  updateArcatChainInfo();

  treeContainer.innerHTML = `<div class="empty-state"><div class="spin">⏳</div> Cargando jerarquía de ARCAT...</div>`;

  try {
    const res = await api.getArcatOverview();
    if (!res.arcat || !res.arcat.configured) {
      treeContainer.innerHTML = `<div class="empty-state">
        <div class="empty-icon">⚠️</div>
        <p>Contratos ARCAT no configurados en el Gateway.</p>
        <p style="font-size:12px;color:var(--text-muted)">Asegúrate de que Hardhat local está corriendo y que se han ejecutado los deploys correspondientes.</p>
      </div>`;
      return;
    }

    renderArcatTree(res);
  } catch (e) {
    treeContainer.innerHTML = `<div class="empty-state">
      <div class="empty-icon">⚠️</div>
      <p>Error de conexión con el Gateway: ${e.message}</p>
    </div>`;
  }
}

function updateArcatChainInfo() {
  const dot = $('arcat-chain-info')?.querySelector('.chain-dot');
  const networkText = $('arcat-chain-network');

  // Usar cuenta del módulo wallet, o como fallback la cuenta activa de MetaMask
  const walletAccount = getAccount() || window.ethereum?.selectedAddress || null;

  if (walletAccount) {
    if (dot) dot.classList.add('connected');
    const networkName = import.meta.env.VITE_NETWORK_NAME || 'Hardhat/Anvil Local';
    if (networkText) networkText.textContent = `${networkName} | Admin: ${walletAccount.slice(0, 6)}…${walletAccount.slice(-4)}`;
  } else {
    if (dot) dot.classList.remove('connected');
    if (networkText) networkText.textContent = 'Sin conexión blockchain';
  }
}

function renderArcatTree(res) {
  const treeContainer = $('arcat-hierarchy-tree');
  if (!treeContainer) return;

  const data = res.unidades;
  const overview = res.arcat;

  const treeStructure = [
    {
      name: "Dirección General de Rentas",
      code: "DGR",
      address: overview.dg_rentas,
      unidades: [
        { name: "De Recaudación", code: "UO-REC", address: data.dgr.uo_recaudacion },
        { name: "De Fiscalización", code: "UO-FIS", address: data.dgr.uo_fiscalizacion }
      ]
    },
    {
      name: "Dirección General de Catastro",
      code: "DGC",
      address: overview.dg_catastro,
      unidades: [
        { name: "De Saneamiento de Título", code: "UO-SAN", address: data.dgc.uo_saneamiento },
        { name: "De Cartografía", code: "UO-CAR", address: data.dgc.uo_cartografia },
        { name: "De Registro Territorial", code: "UO-REG", address: data.dgc.uo_registro_territorial }
      ]
    },
    {
      name: "Dir. Gral. de Registro de la Propiedad Inmueble",
      code: "DGRPI",
      address: overview.dg_dgrpi,
      unidades: [
        { name: "De Registración Inmobiliaria", code: "UO-RIN", address: data.dgrpi.uo_registracion },
        { name: "De Publicidad Inmob. y Medidas Cautelares", code: "UO-PUB", address: data.dgrpi.uo_publicidad }
      ]
    },
    {
      name: "Dependencias Staff ARCAT",
      code: "STAFF",
      address: overview.dg_staff,
      unidades: [
        { name: "De Administración", code: "UO-ADM", address: data.staff.uo_administracion },
        { name: "De Capital Humano", code: "UO-RHH", address: data.staff.uo_capital_humano },
        { name: "De Tecnologías / Sistemas", code: "UO-TEC", address: data.staff.uo_tecnologias },
        { name: "De Asuntos Jurídicos", code: "UO-JUR", address: data.staff.uo_juridicos },
        { name: "De Gestión y Recaudación", code: "UO-GRE", address: data.staff.uo_gre },
        { name: "Auditoría Interna", code: "UO-AUD", address: data.staff.uo_auditoria },
        { name: "Secretaría General", code: "UO-SEC", address: data.staff.uo_secretaria }
      ]
    }
  ];

  treeContainer.innerHTML = treeStructure.map(dg => {
    return `
      <div class="dg-node collapsed" id="dg-node-${dg.code}">
        <div class="dg-header" id="dg-header-${dg.code}">
          <div class="dg-header-title">
            <span>📁</span>
            <span>${dg.name} (${dg.code})</span>
          </div>
          <span class="dg-icon-arrow">▼</span>
        </div>
        <div class="uo-list">
          ${dg.unidades.map(uo => `
            <div class="uo-item" data-address="${uo.address}" data-code="${uo.code}" data-name="${uo.name}" data-dg="${dg.code}">
              <div class="uo-item-name">
                <span>🏛️</span>
                <span>${uo.name}</span>
              </div>
              <span class="uo-device-count" id="count-${uo.address}">Cargando...</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Toggles de Dirección General
  treeStructure.forEach(dg => {
    document.getElementById(`dg-header-${dg.code}`)?.addEventListener('click', () => {
      document.getElementById(`dg-node-${dg.code}`)?.classList.toggle('collapsed');
    });
  });

  // Agregar event listener a cada UO
  treeContainer.querySelectorAll('.uo-item').forEach(item => {
    item.addEventListener('click', () => {
      treeContainer.querySelectorAll('.uo-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      selectUnidadOperativa(item.dataset.address, item.dataset.name, item.dataset.code, item.dataset.dg);
    });

    // Cargar número de dispositivos asíncronamente
    updateUODeviceCount(item.dataset.address);
  });
}

async function updateUODeviceCount(address) {
  const el = document.getElementById(`count-${address}`);
  if (!el) return;
  try {
    const res = await api.getArcatUnitDevices(address);
    if (res.total_devices !== undefined) {
      el.textContent = `${res.total_devices} SBT`;
    }
  } catch (e) {
    el.textContent = "0 SBT";
  }
}

async function selectUnidadOperativa(address, name, code, dgCode) {
  const titleEl = $('arcat-uo-title');
  const contentEl = $('arcat-uo-content');
  const btnRegister = $('btn-register-device');

  if (titleEl) titleEl.textContent = `${name} (${code})`;
  if (btnRegister) {
    btnRegister.classList.remove('hidden');
    // Guardar metadata en el botón para usarla al registrar
    btnRegister.dataset.address = address;
    btnRegister.dataset.name = name;
    btnRegister.dataset.code = code;
    btnRegister.dataset.dg = dgCode;
  }

  if (contentEl) {
    contentEl.innerHTML = `
      <div class="uo-info-banner">
        <div class="uo-info-block">
          <span class="uo-info-label">Dirección General</span>
          <span class="uo-info-value">${dgCode}</span>
        </div>
        <div class="uo-info-block">
          <span class="uo-info-label">Unidad Operativa</span>
          <span class="uo-info-value">${name}</span>
        </div>
        <div class="uo-info-block">
          <span class="uo-info-label">Contrato Blockchain</span>
          <span class="uo-info-value addr">${address}</span>
        </div>
      </div>
      
      <div class="section-title">Inventario de Dispositivos Tokenizados (SBT)</div>
      <div class="table-container" id="arcat-devices-table">
        <div class="empty-state"><div class="spin">⏳</div> Cargando dispositivos...</div>
      </div>

      <div class="section-title">⛓️ Timeline de Trazabilidad y Auditorías On-Chain</div>
      <div class="audits-timeline" id="arcat-audits-timeline">
        <div class="audit-select-hint">
          <div class="audit-select-icon">👆</div>
          <div class="audit-select-text">Haz clic en una fila del inventario para cargar el historial de auditorías on-chain del dispositivo</div>
        </div>
      </div>
    `;

    // Cargar inventario de dispositivos
    loadUODevices(address, code, dgCode);
  }
}

async function loadUODevices(address, uoCode, dgCode) {
  const tableContainer = $('arcat-devices-table');
  if (!tableContainer) return;

  try {
    const res = await api.getArcatUnitDevices(address);
    const devices = res.devices || [];

    if (!devices.length) {
      tableContainer.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🖥️</div>
          <p>No hay dispositivos tokenizados en esta Unidad Operativa.</p>
        </div>
      `;
      return;
    }

    tableContainer.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Token ID</th>
            <th>IP de Dispositivo</th>
            <th>Hostname</th>
            <th>UUID</th>
            <th>Tipo</th>
            <th>Estado</th>
            <th>Threat Score</th>
            <th>Auditorías</th>
          </tr>
        </thead>
        <tbody>
          ${devices.map(d => {
            const dev = d.device;
            const activeStatus = dev.is_active
              ? '<span class="status-dot online" style="display:inline-block;position:static;margin-right:5px"></span>Activo'
              : '<span class="status-dot offline" style="display:inline-block;position:static;margin-right:5px"></span>Inactivo';
            const threatClass = (d.threat_level || 'CLEAN').toLowerCase();
            const isIp = (val) => val && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val);
            const deviceIp = isIp(dev.device_name) ? dev.device_name : (isIp(dev.hostname) ? dev.hostname : '—');
            const audCount = parseInt(dev.audits_count || '0', 10);
            const audBadge = audCount > 0
              ? `<span class="audit-count-badge has-audits" title="${audCount} auditoría(s) on-chain">${audCount} 📋</span>`
              : `<span class="audit-count-badge" title="Sin auditorías registradas">0</span>`;
            return `
              <tr class="device-row" data-token-id="${dev.token_id}" data-hostname="${dev.hostname}"
                  data-device-ip="${deviceIp}" data-device-type="${dev.device_type}"
                  data-registered-at="${dev.registered_at}" data-audits-count="${audCount}"
                  data-uuid="${dev.uuid}">
                <td class="mono">#${dev.token_id}</td>
                <td style="font-weight:600">${deviceIp}</td>
                <td class="mono">${dev.hostname}</td>
                <td class="mono" style="font-size:0.68rem">${dev.uuid}</td>
                <td><span class="badge badge-INFO">${dev.device_type}</span></td>
                <td>${activeStatus}</td>
                <td><span class="threat-badge ${threatClass}">${d.threat_level || 'CLEAN'} (${dev.threat_score})</span></td>
                <td>${audBadge}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;

    // Agregar event listener a las filas
    tableContainer.querySelectorAll('.device-row').forEach(row => {
      row.addEventListener('click', () => {
        tableContainer.querySelectorAll('.device-row').forEach(r => r.classList.remove('selected'));
        row.classList.add('selected');
        const tokenId = row.dataset.tokenId;
        const hostname = row.dataset.hostname;
        const deviceIp = row.dataset.deviceIp;
        const deviceType = row.dataset.deviceType;
        const registeredAt = row.dataset.registeredAt;
        const auditsCount = row.dataset.auditsCount;
        const uuid = row.dataset.uuid;
        loadDeviceAudits(address, tokenId, hostname, { deviceIp, deviceType, registeredAt, auditsCount, uuid });
      });
    });

  } catch (e) {
    tableContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⚠️</div>
        <p>Error cargando dispositivos: ${e.message}</p>
      </div>
    `;
  }
}

/**
 * Formatea un timestamp del API: puede ser string ISO-8601 (del Rust) o número Unix.
 * @param {string|number} ts
 * @returns {string}
 */
function formatAuditTimestamp(ts) {
  if (!ts) return '—';
  // Si es un string ISO (como retorna el cliente Rust), parsear directamente
  if (typeof ts === 'string' && ts.includes('T')) {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? ts : d.toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'medium' });
  }
  // Si es Unix timestamp numérico (segundos)
  const num = Number(ts);
  if (!isNaN(num) && num > 0) {
    return new Date(num * 1000).toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'medium' });
  }
  return String(ts);
}

/**
 * Carga y renderiza el historial de auditorías on-chain para un dispositivo específico.
 * @param {string} uoAddress  - Dirección del contrato UO
 * @param {string|number} tokenId - ID del token SBT
 * @param {string} hostname  - Hostname del dispositivo
 * @param {object} [deviceMeta] - Metadata adicional del dispositivo (IP, tipo, etc.)
 */
async function loadDeviceAudits(uoAddress, tokenId, hostname, deviceMeta = {}) {
  const timeline = $('arcat-audits-timeline');
  if (!timeline) return;

  timeline.innerHTML = `
    <div class="empty-state" style="padding:24px 20px">
      <div class="spin" style="font-size:1.5rem">⏳</div>
      <p style="margin-top:8px">Consultando auditorías on-chain para <strong>${hostname}</strong>...</p>
    </div>`;

  try {
    const res = await api.getArcatUnitAudits(uoAddress);
    const audits = res.audits || [];

    // Filtrar auditorías para este tokenId específico
    const deviceAudits = audits.filter(a => String(a.token_id) === String(tokenId));

    // ── Construir cabecera del dispositivo seleccionado ──
    const regDate = deviceMeta.registeredAt
      ? formatAuditTimestamp(deviceMeta.registeredAt)
      : '—';
    const deviceHeaderHtml = `
      <div class="audit-device-detail">
        <div class="audit-device-row">
          <span class="audit-device-label">🖥️ Hostname</span>
          <span class="audit-device-val mono">${hostname}</span>
        </div>
        <div class="audit-device-row">
          <span class="audit-device-label">🌐 IP Dispositivo</span>
          <span class="audit-device-val">${deviceMeta.deviceIp || '—'}</span>
        </div>
        <div class="audit-device-row">
          <span class="audit-device-label">🔧 Tipo</span>
          <span class="audit-device-val">${deviceMeta.deviceType || '—'}</span>
        </div>
        <div class="audit-device-row">
          <span class="audit-device-label">🔑 UUID</span>
          <span class="audit-device-val mono" style="font-size:0.72rem; word-break:break-all; letter-spacing:0.02em">${deviceMeta.uuid || '—'}</span>
        </div>
        <div class="audit-device-row">
          <span class="audit-device-label">📅 Registrado</span>
          <span class="audit-device-val">${regDate}</span>
        </div>
        <div class="audit-device-row">
          <span class="audit-device-label">📋 Auditorías on-chain</span>
          <span class="audit-device-val" style="color: ${deviceAudits.length > 0 ? 'var(--orange)' : 'var(--green)'}; font-weight:700">
            ${deviceAudits.length}
          </span>
        </div>
      </div>`;

    // ── Botón de recarga ──
    const reloadBtnHtml = `
      <div style="display:flex; justify-content:flex-end; margin-bottom:0.5rem;">
        <button id="btn-reload-audits" class="btn-secondary btn-sm" style="font-size:0.72rem; padding:4px 10px; display:flex; align-items:center; gap:6px;">
          🔄 Actualizar Auditorías
        </button>
      </div>`;

    if (!deviceAudits.length) {
      timeline.innerHTML = deviceHeaderHtml + `
        <div class="audit-clean-state">
          <div class="audit-clean-icon">🛡️</div>
          <div class="audit-clean-title">Dispositivo Sin Alertas</div>
          <p class="audit-clean-desc">No se registran eventos de seguridad on-chain para el token <strong>#${tokenId}</strong>.
          Esto indica que el dispositivo <strong>${hostname}</strong> opera sin incidentes detectados.</p>
          ${reloadBtnHtml}
        </div>
      `;
      // Bind reload
      document.getElementById('btn-reload-audits')?.addEventListener('click', () => {
        loadDeviceAudits(uoAddress, tokenId, hostname, deviceMeta);
      });
      return;
    }

    // ── Renderizar eventos de auditoría ──
    const itemsHtml = deviceAudits.map((a, idx) => {
      const aud = a.audit || {};
      const sevClass = (aud.severity || 'INFO').toLowerCase();
      const dateStr = formatAuditTimestamp(aud.timestamp);

      // data_hash: mostrar los primeros 10 y últimos 8 caracteres
      const dataHash = aud.data_hash || '';
      const hashDisplay = dataHash.length > 20
        ? dataHash.slice(0, 10) + '…' + dataHash.slice(-8)
        : (dataHash || '—');

      // IOC hashes
      const iocHashes = Array.isArray(aud.ioc_hashes) ? aud.ioc_hashes : [];
      const iocHtml = iocHashes.length > 0
        ? `<div class="audit-ioc-list">
             <span class="audit-ioc-label">🔍 IoC Hashes:</span>
             ${iocHashes.map(h => `<span class="audit-ioc-hash" title="${h}">${h.slice(0, 12)}…</span>`).join('')}
           </div>`
        : '';

      // Reporter address
      const reporter = aud.reporter || '';
      const reporterDisplay = reporter.length > 12
        ? reporter.slice(0, 8) + '…' + reporter.slice(-6)
        : (reporter || 'N/A');

      return `
        <div class="audit-timeline-item severity-${sevClass}" style="animation-delay: ${idx * 60}ms">
          <div class="audit-timeline-header">
            <span class="audit-timeline-title">
              <span class="threat-badge ${sevClass}">${aud.severity || 'INFO'}</span>
              <strong>${aud.event_type || 'Auditoría'}</strong>
            </span>
            <span class="audit-timeline-time">🕐 ${dateStr}</span>
          </div>
          <div class="audit-timeline-desc">${aud.description || '—'}</div>
          ${iocHtml}
          <div class="audit-timeline-footer">
            <span class="audit-timeline-meta">📍 IP Origen: <strong>${aud.src_ip || 'N/A'}</strong></span>
            ${aud.malware_family ? `<span class="audit-timeline-meta">🦠 Familia: <strong>${aud.malware_family}</strong></span>` : ''}
            <span class="audit-timeline-meta" title="SHA-256 del payload Wazuh">🔐 Hash: <code style="font-size:0.65rem;color:var(--cyan)">${hashDisplay}</code></span>
            ${reporter ? `<span class="audit-timeline-meta" title="Dirección del reporter on-chain">🤖 Reporter: <code style="font-size:0.65rem">${reporterDisplay}</code></span>` : ''}
          </div>
        </div>
      `;
    }).join('');

    timeline.innerHTML = deviceHeaderHtml + reloadBtnHtml + `
      <div class="audit-items-list">${itemsHtml}</div>
    `;

    // Bind reload button
    document.getElementById('btn-reload-audits')?.addEventListener('click', () => {
      loadDeviceAudits(uoAddress, tokenId, hostname, deviceMeta);
    });

  } catch (e) {
    timeline.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⚠️</div>
        <p>Error cargando auditorías: <strong>${e.message}</strong></p>
        <button onclick="loadDeviceAudits('${uoAddress}','${tokenId}','${hostname}')" class="btn-secondary btn-sm" style="margin-top:1rem">Reintentar</button>
      </div>
    `;
  }
}

// Inyectar estilos CSS para el modal de acuñación automatizada
const arcatModalStyle = document.createElement('style');
arcatModalStyle.innerHTML = `
  .arcat-modal-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(6px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    animation: arcatFadeIn 0.25s ease-out;
  }
  .arcat-modal {
    background: #0b1329;
    border: 1px solid #1e293b;
    border-radius: 16px;
    width: 92%;
    max-width: 520px;
    padding: 28px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
    color: #e2e8f0;
    font-family: inherit;
    animation: arcatScaleIn 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  .arcat-modal-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #10b981;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .arcat-modal-desc {
    font-size: 0.9rem;
    color: #94a3b8;
    margin-bottom: 24px;
    line-height: 1.5;
  }
  .arcat-device-list {
    max-height: 280px;
    overflow-y: auto;
    margin-bottom: 24px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-right: 4px;
  }
  .arcat-device-list::-webkit-scrollbar {
    width: 6px;
  }
  .arcat-device-list::-webkit-scrollbar-track {
    background: #0f172a;
    border-radius: 4px;
  }
  .arcat-device-list::-webkit-scrollbar-thumb {
    background: #334155;
    border-radius: 4px;
  }
  .arcat-device-list::-webkit-scrollbar-thumb:hover {
    background: #475569;
  }
  .arcat-device-item {
    background: #111d35;
    border: 1px solid #27354f;
    border-radius: 10px;
    padding: 14px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .arcat-device-item:hover {
    border-color: #10b981;
    background: rgba(16, 185, 129, 0.08);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.1);
  }
  .arcat-device-icon {
    font-size: 1.8rem;
    color: #10b981;
    background: rgba(16, 185, 129, 0.1);
    padding: 8px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .arcat-device-info {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex-grow: 1;
  }
  .arcat-device-name {
    font-weight: 600;
    color: #ffffff;
    font-size: 1rem;
  }
  .arcat-device-details {
    font-size: 0.8rem;
    color: #94a3b8;
  }
  .arcat-device-meta {
    font-size: 0.75rem;
    color: #64748b;
    font-family: monospace;
    margin-top: 2px;
  }
  .arcat-modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    border-top: 1px solid #1e293b;
    padding-top: 20px;
  }
  .arcat-btn {
    padding: 10px 18px;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.88rem;
    cursor: pointer;
    transition: all 0.2s;
    border: 1px solid transparent;
  }
  .arcat-btn-primary {
    background: #10b981;
    color: #0b1329;
  }
  .arcat-btn-primary:hover {
    background: #059669;
    box-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
  }
  .arcat-btn-secondary {
    background: transparent;
    border-color: #334155;
    color: #94a3b8;
  }
  .arcat-btn-secondary:hover {
    border-color: #475569;
    color: #e2e8f0;
  }
  .arcat-spin {
    display: inline-block;
    animation: arcatRotate 1.2s infinite linear;
  }
  @keyframes arcatFadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes arcatScaleIn {
    from { transform: scale(0.92); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
  }
  @keyframes arcatRotate {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  @keyframes popGreen {
    0% { transform: scale(0.5); opacity: 0; }
    80% { transform: scale(1.1); }
    100% { transform: scale(1); opacity: 1; }
  }
`;
document.head.appendChild(arcatModalStyle);

async function registerDeviceMetaMask() {
  const btn = $('btn-register-device');
  if (!btn) return;

  const uoAddress = btn.dataset.address;
  if (!uoAddress) return;

  const account = getAccount();
  const signer = getSigner();

  if (!account || !signer) {
    toast("Por favor conecta tu wallet MetaMask primero", "error");
    return;
  }

  // 1. Mostrar pantalla de carga (overlay)
  const overlay = document.createElement('div');
  overlay.className = 'arcat-modal-overlay';
  overlay.innerHTML = `
    <div class="arcat-modal" style="text-align: center;">
      <div class="arcat-modal-title" style="justify-content: center;">
        <span class="arcat-spin">⏳</span> Buscando nuevos dispositivos
      </div>
      <p class="arcat-modal-desc">
        Consultando el historial de alertas del Gateway en busca de clientes recién instalados...
      </p>
    </div>
  `;
  document.body.appendChild(overlay);

  try {
    // 2. Obtener alertas recientes y filtrar NEW_DEVICE_DETECTED
    const alertsData = await api.getAlerts({ limit: 100 });
    const alerts = alertsData.data || [];
    const pendingAlerts = alerts.filter(a => a.event_type === "NEW_DEVICE_DETECTED");

    // 3. Parsear y validar contra blockchain cuáles están realmente pendientes
    const pendingDevices = [];
    const { Contract } = await import('ethers');

    // Instanciar contrato de la UO actual para consultar on-chain
    const uoContract = new Contract(uoAddress, [
      "function getTokenByHostname(string hostname) external view returns (uint256, bool)"
    ], signer);

    // Instanciar contrato de la Registry global para consultar on-chain
    let registryContract = null;
    try {
      const overview = await api.getArcatOverview();
      const registryAddr = overview.arcat.arcat_registry;
      if (registryAddr && registryAddr !== "0x0000000000000000000000000000000000000000") {
        registryContract = new Contract(registryAddr, [
          "function lookupByHostname(string hostname) external view returns (address, uint256, bool)"
        ], signer);
      }
    } catch (e) {
      console.warn("No se pudo instanciar ArcatRegistry para chequeo:", e);
    }

    for (const alert of pendingAlerts) {
      const desc = alert.description;
      const nameMatch = desc.match(/Nombre:\s*([^|]+)/);
      const hostMatch = desc.match(/Hostname:\s*([^|]+)/);
      const uuidMatch = desc.match(/UUID:\s*([^|]+)/);
      const typeMatch = desc.match(/Tipo:\s*(\d+)/);

      if (hostMatch && uuidMatch) {
        const hostname = hostMatch[1].trim();
        const uuid = uuidMatch[1].trim();
        const name = alert.src_ip || (nameMatch ? nameMatch[1].trim() : '192.168.125.5');
        const type = typeMatch ? parseInt(typeMatch[1]) : 1;

        let isAlreadyRegistered = false;

        // Check 1: Directamente en el contrato de la UO actual
        try {
          const [_, foundInUO] = await uoContract.getTokenByHostname(hostname);
          if (foundInUO) {
            isAlreadyRegistered = true;
          }
        } catch (err) {
          console.error("Error verificando en UO:", err);
        }

        // Check 2: Directamente en el contrato Registry global
        if (!isAlreadyRegistered && registryContract) {
          try {
            const [_, __, foundInRegistry] = await registryContract.lookupByHostname(hostname);
            if (foundInRegistry) {
              isAlreadyRegistered = true;
            }
          } catch (err) {
            console.error("Error verificando en Registry:", err);
          }
        }

        // Check 3: Fallback al Gateway API
        if (!isAlreadyRegistered) {
          try {
            const check = await api.getArcatDevice(hostname);
            if (check.status === 'ok') {
              isAlreadyRegistered = true;
            }
          } catch {}
        }

        if (!isAlreadyRegistered) {
          if (!pendingDevices.some(d => d.hostname === hostname)) {
            pendingDevices.push({ name, hostname, uuid, type });
          }
        }
      }
    }

    // 4. Mostrar modal con opciones de selección
    if (pendingDevices.length === 0) {
      // Caso A: No hay dispositivos pendientes
      overlay.innerHTML = `
        <div class="arcat-modal">
          <div class="arcat-modal-title">
            <span>🖥️</span> No hay dispositivos pendientes
          </div>
          <p class="arcat-modal-desc">
            No se detectaron nuevas instalaciones de clientes en la red LAN. ¿Deseas realizar una carga manual ingresando los datos tú mismo?
          </p>
          <div class="arcat-modal-actions">
            <button class="arcat-btn arcat-btn-secondary" id="btn-modal-cancel">Cancelar</button>
            <button class="arcat-btn arcat-btn-primary" id="btn-modal-manual">Carga Manual</button>
          </div>
        </div>
      `;

      document.getElementById('btn-modal-cancel').onclick = () => overlay.remove();
      document.getElementById('btn-modal-manual').onclick = () => {
        overlay.remove();
        triggerManualPromptMinting(uoAddress, btn.dataset.dg, btn.dataset.code, account, signer);
      };
    } else {
      // Caso B: Hay dispositivos detectados listos para acuñar automáticamente
      overlay.innerHTML = `
        <div class="arcat-modal">
          <div class="arcat-modal-title">
            <span>🖥️</span> Dispositivos Pendientes Detectados
          </div>
          <p class="arcat-modal-desc">
            Selecciona un dispositivo instalado en la red LAN para acuñar su token SBT de forma automatizada:
          </p>
          <div class="arcat-device-list">
            ${pendingDevices.map((d, index) => `
              <div class="arcat-device-item" data-index="${index}">
                <div class="arcat-device-icon">💻</div>
                <div class="arcat-device-info">
                  <div class="arcat-device-name">IP: ${d.name}</div>
                  <div class="arcat-device-details">
                    Hostname: <strong>${d.hostname}</strong> · Tipo: ${d.type === 0 ? 'Server' : 'Workstation'}
                  </div>
                  <div class="arcat-device-meta">UUID: ${d.uuid}</div>
                </div>
              </div>
            `).join('')}
          </div>
          <div class="arcat-modal-actions">
            <button class="arcat-btn arcat-btn-secondary" id="btn-modal-cancel">Cancelar</button>
            <button class="arcat-btn arcat-btn-secondary" id="btn-modal-manual" style="border-style: dashed;">Ingreso Manual</button>
          </div>
        </div>
      `;

      document.getElementById('btn-modal-cancel').onclick = () => overlay.remove();
      document.getElementById('btn-modal-manual').onclick = () => {
        overlay.remove();
        triggerManualPromptMinting(uoAddress, btn.dataset.dg, btn.dataset.code, account, signer);
      };

      // Listener para cada ítem de dispositivo detectado
      overlay.querySelectorAll('.arcat-device-item').forEach(item => {
        item.onclick = async () => {
          const dev = pendingDevices[parseInt(item.dataset.index)];
          overlay.remove();
          // Proceder directamente a acuñar con los datos automatizados!
          await executeBlockchainMinting(uoAddress, dev.name, dev.uuid, dev.hostname, dev.type, btn.dataset.dg, btn.dataset.code, account, signer);
        };
      });
    }

  } catch (err) {
    console.error(err);
    overlay.remove();
    toast("Error consultando dispositivos pendientes: " + err.message, "error");
    // Fallback a carga manual
    triggerManualPromptMinting(uoAddress, btn.dataset.dg, btn.dataset.code, account, signer);
  }
}

async function triggerManualPromptMinting(uoAddress, dgCode, uoCode, account, signer) {
  const name = prompt("Ingrese IP del Dispositivo:", "192.168.125.5");
  if (!name) return;
  const hostname = prompt("Ingrese Hostname (debe coincidir con Wazuh):", (dgCode + "-" + uoCode + "-01").toLowerCase());
  if (!hostname) return;
  const uuid = prompt("Ingrese UUID del Hardware:", "UUID-" + Math.floor(Math.random()*1000000));
  if (!uuid) return;
  
  const dTypeStr = prompt("Ingrese Tipo (0=Server, 1=Workstation, 2=Firewall, 3=Switch):", "0");
  if (dTypeStr === null) return;
  const dType = parseInt(dTypeStr) || 0;

  await executeBlockchainMinting(uoAddress, name, uuid, hostname, dType, dgCode, uoCode, account, signer);
}

function showSuccessModal(title, message, details = {}) {
  const existing = document.getElementById('arcat-success-modal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'arcat-success-modal';
  overlay.className = 'arcat-modal-overlay';
  
  let detailsHtml = '';
  if (Object.keys(details).length > 0) {
    detailsHtml = `
      <div style="background: #111d35; border: 1px solid #27354f; border-radius: 10px; padding: 16px; margin: 20px 0; text-align: left; font-size: 0.88rem; display: flex; flex-direction: column; gap: 8px;">
        ${Object.entries(details).map(([key, val]) => `
          <div><strong style="color: #94a3b8; margin-right: 8px;">${key}:</strong> <span style="color: #ffffff; font-family: monospace;">${val}</span></div>
        `).join('')}
      </div>
    `;
  }

  overlay.innerHTML = `
    <div class="arcat-modal" style="text-align: center; max-width: 450px;">
      <div style="font-size: 3.5rem; color: #10b981; margin-bottom: 16px; animation: popGreen 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);">✓</div>
      <div class="arcat-modal-title" style="justify-content: center; font-size: 1.5rem; margin-bottom: 12px; color: #ffffff;">
        ${title}
      </div>
      <p class="arcat-modal-desc" style="margin-bottom: 16px; font-size: 0.95rem; color: #94a3b8;">
        ${message}
      </p>
      ${detailsHtml}
      <div class="arcat-modal-actions" style="justify-content: center; border-top: none; padding-top: 10px;">
        <button class="arcat-btn arcat-btn-primary" id="btn-success-modal-close" style="padding: 12px 30px; font-size: 0.95rem;">Aceptar</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById('btn-success-modal-close').onclick = () => {
    overlay.remove();
  };
}

async function executeBlockchainMinting(uoAddress, name, uuid, hostname, dType, dgCode, uoCode, account, signer) {
  try {
    const { Contract } = await import('ethers');

    // 1. Registrar dispositivo en el contrato UO
    const uoContract = new Contract(uoAddress, [
      "function registerDevice(address deviceOwner, string deviceName, string uuid, string hostname, uint8 dType) external returns (uint256)",
      "function getTokenByHostname(string hostname) external view returns (uint256, bool)"
    ], signer);

    toast(`Iniciando acuñación automatizada de SBT para ${hostname} en MetaMask...`, "info");
    const tx = await uoContract.registerDevice(account, name, uuid, hostname, dType);
    toast(`Transacción de acuñación enviada. Esperando confirmación de bloque...`, "info");
    await tx.wait();

    // 2. Obtener tokenId asignado
    const [tokenId, found] = await uoContract.getTokenByHostname(hostname);
    if (!found) {
      throw new Error(`El dispositivo con hostname ${hostname} no se encontró en la blockchain.`);
    }
    toast(`Dispositivo acuñado con Token ID #${tokenId}. Iniciando registro global...`, "success");

    // 3. Obtener dirección de ArcatRegistry desde el Gateway
    const overview = await api.getArcatOverview();
    const registryAddr = overview.arcat.arcat_registry;

    if (!registryAddr || registryAddr === "0x0000000000000000000000000000000000000000") {
      toast("Error: No se pudo obtener la dirección de ArcatRegistry", "error");
      return;
    }

    // 4. Indexar en ArcatRegistry
    const registryContract = new Contract(registryAddr, [
      "function adminIndexDevice(address uoContract, uint256 tokenId, string hostname, string uuid, string dgCode, string uoCode) external"
    ], signer);

    toast("Iniciando indexación global en MetaMask...", "info");
    const tx2 = await registryContract.adminIndexDevice(uoAddress, tokenId, hostname, uuid, dgCode, uoCode);
    toast(`Transacción de indexación enviada. Esperando confirmación...`, "info");
    await tx2.wait();

    // Simular costo de gas y resta en USD
    const ethPrice = 3500; // Valor simulado de ETH a USD
    const gasEth = (0.00035 + Math.random() * 0.00015).toFixed(6);
    const gasUsd = (parseFloat(gasEth) * ethPrice).toFixed(2);

    // Mostrar el popup de confirmación exitosa con detalles
    showSuccessModal(
      "¡Tokenización Exitosa!",
      `El dispositivo ha sido acuñado e indexado correctamente en la red blockchain.`,
      {
        "Token ID": `#${tokenId}`,
        "IP Dispositivo": name,
        "Hostname": hostname,
        "UUID": uuid,
        "Costo de Gas": `${gasEth} ETH (~$${gasUsd} USD)`,
        "Deducción (USD)": `-$${gasUsd} USD`,
        "Dirección Contrato": uoAddress
      }
    );

    // Recargar vistas
    selectUnidadOperativa(uoAddress, name, uoCode, dgCode);
    updateUODeviceCount(uoAddress);

  } catch (e) {
    console.error(e);
    toast("Error en la transacción: " + e.message, "error");
  }
}

function initArcatView() {
  $('nav-arcat')?.addEventListener('click', loadArcatOverview);
  $('btn-register-device')?.addEventListener('click', registerDeviceMetaMask);
}

// ── Bootstrap ────────────────────────────────────────────────
async function init() {
  initRouter();
  initSeverityChart();
  initTimelineChart();
  initIpView();
  initCveView();
  initAlertsFilters();
  initServicesView();
  initIocView();
  initArcatView();

  // Wallet — detectar sesión previa sin popup (auto-connect silencioso)
  initWalletButton();
  await autoConnectWallet();  // Recupera sesión de MetaMask si ya fue autorizada
  $('btn-wallet')?.addEventListener('click', connectWallet);

  // Datos iniciales
  await checkGatewayHealth();
  await loadAlerts();
  await loadPerimetralExposures().catch(() => {});
  await loadIocCorrelations().catch(() => {});

  // Auto-refresh cada 30s
  state.refreshInterval = setInterval(async () => {
    await checkGatewayHealth();
    await loadAlerts();
    await loadPerimetralExposures().catch(() => {});
    await loadIocCorrelations().catch(() => {});
  }, 30000);

  // WebSocket
  initWebSocket();

  // Audit cuando se cambia a esa vista
  document.getElementById('nav-audit')?.addEventListener('click', loadAuditTrail);
  document.getElementById('nav-arcat')?.addEventListener('click', loadArcatOverview);

  // ── Antivirus — cargar cuando se activa la vista ──────────────────────────
  document.getElementById('nav-antivirus')?.addEventListener('click', () => {
    loadAntivirusView();
  });

  // Contrato SecurityAudit — mostrar dirección dinámica real del gateway al iniciar
  try {
    const chain = await api.checkBlockchain(); // Corrección: usar api.checkBlockchain() en vez de checkBlockchain() ya que se define en api.js
    const contractAddr = chain.contract || import.meta.env.VITE_CONTRACT_SECURITY_AUDIT;
    const auditContractEl = $('audit-contract');
    if (auditContractEl) {
      if (contractAddr && contractAddr.startsWith('0x') && contractAddr.length === 42) {
        // Mostrar dirección abreviada con tooltip de la dirección completa
        auditContractEl.textContent = contractAddr.slice(0, 6) + '…' + contractAddr.slice(-4);
        auditContractEl.title = contractAddr;
        auditContractEl.style.cursor = 'help';
        auditContractEl.style.color = 'var(--cyan, #00d4ff)';
      } else {
        auditContractEl.textContent = 'No desplegado';
        auditContractEl.style.color = 'var(--yellow, #ffd700)';
        auditContractEl.style.fontSize = '14px';
      }
    }
  } catch (e) {
    console.error("No se pudo obtener el contrato dinámico de la blockchain:", e);
  }
}

init();

// ═══════════════════════════════════════════════════════════════════════════════
// 🛡️  MÓDULO ANTIVIRUS — ClamAV Integration
// ═══════════════════════════════════════════════════════════════════════════════

/** Cache interno de resultados antivirus para filtrado client-side */
let _avResultsCache = [];

/** Carga la vista antivirus completa: KPIs + tabla de dispositivos */
async function loadAntivirusView() {
  await Promise.all([loadAntivirusSummary(), loadAntivirusResults()]);
  const now = new Date().toLocaleTimeString('es-AR');
  const el = document.getElementById('av-last-updated');
  if (el) el.textContent = `Actualizado: ${now}`;
}

/** Carga y renderiza las tarjetas KPI de estadísticas */
async function loadAntivirusSummary() {
  try {
    const BASE = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';
    const res  = await fetch(`${BASE}/api/antivirus/summary`);
    const json = await res.json();
    const d    = json.data || {};

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val ?? '--';
    };

    set('av-kpi-total',    d.total_devices ?? 0);
    set('av-kpi-clean',    d.clean         ?? 0);
    set('av-kpi-infected', d.infected      ?? 0);
    set('av-kpi-error',    (d.error ?? 0) + (d.pending ?? 0));
    set('av-kpi-threats',  d.total_infected_files ?? 0);

    // Resaltar tarjeta infectados si hay amenazas
    const infCard = document.querySelector('.av-kpi-infected');
    if (infCard) {
      infCard.classList.toggle('av-kpi-alert', (d.infected ?? 0) > 0);
    }
  } catch (e) {
    console.warn('Antivirus summary error:', e);
  }
}

/** Carga todos los resultados de escaneo y pobla la tabla */
async function loadAntivirusResults() {
  try {
    const BASE = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';
    const res  = await fetch(`${BASE}/api/antivirus/results?limit=200`);
    const json = await res.json();
    _avResultsCache = json.data || [];
    await renderAntivirusTable(_avResultsCache);
  } catch (e) {
    console.warn('Antivirus results error:', e);
    const tbody = document.getElementById('av-devices-tbody');
    if (tbody) tbody.innerHTML = `
      <tr><td colspan="10" class="empty-state">
        <div class="empty-icon">⚠️</div>
        <div>Gateway no disponible o endpoint /api/antivirus/results no responde</div>
      </td></tr>`;
  }
}

/** Renderiza la tabla de dispositivos con resultados de escaneo.
 *
 *  AGRUPACIÓN POR HOSTNAME (1 fila por dispositivo):
 *  - Si el dispositivo tiene resultados DAILY o WEEKLY se muestra el más reciente.
 *  - Si solo tiene SELFTEST se muestra ese resultado.
 *  - El estado de la autoprueba (SELFTEST) aparece como chip secundario
 *    en la columna MODO, sin crear una fila duplicada.
 *
 *  Los datos originales NO se modifican — solo cambia la vista.
 */
async function renderAntivirusTable(results) {
  const tbody = document.getElementById('av-devices-tbody');
  const count = document.getElementById('av-table-count');
  if (!tbody) return;

  if (!results.length) {
    if (count) count.textContent = '0 dispositivos';
    tbody.innerHTML = `
      <tr><td colspan="10" class="empty-state">
        <div class="empty-icon">🛡️</div>
        <div>Ningún dispositivo ha reportado resultados de escaneo aún.</div>
        <div style="font-size:12px;margin-top:8px;opacity:.6">
          Instala ClamAV en los endpoints usando el botón <strong>Instalar en Endpoint</strong>
        </div>
      </td></tr>`;
    return;
  }

  // ── 1. AGRUPAR POR HOSTNAME ───────────────────────────────────────────────
  // Para cada dispositivo conservamos:
  //   primary  → el resultado más reciente de modo DAILY o WEEKLY
  //   selftest → el resultado más reciente de modo SELFTEST
  const grouped = new Map(); // key: hostname.toLowerCase()

  for (const r of results) {
    const key  = (r.hostname || 'unknown').toLowerCase();
    const mode = (r.scan_mode || 'Daily').toUpperCase();

    if (!grouped.has(key)) {
      grouped.set(key, { primary: null, selftest: null });
    }
    const entry = grouped.get(key);

    if (mode === 'SELFTEST') {
      // Conservar el selftest más reciente
      if (!entry.selftest || (r.timestamp || '') > (entry.selftest.timestamp || '')) {
        entry.selftest = r;
      }
    } else {
      // Conservar el resultado de escaneo real más reciente (DAILY / WEEKLY / …)
      if (!entry.primary || (r.timestamp || '') > (entry.primary.timestamp || '')) {
        entry.primary = r;
      }
    }
  }

  // ── 2. CONSTRUIR LISTA DE VISUALIZACIÓN ───────────────────────────────────
  // Cada entrada del Map produce exactamente 1 fila.
  const displayList = [];
  for (const [, entry] of grouped) {
    const row = { ...(entry.primary ?? entry.selftest) };
    // Adjuntar info de selftest para usarla en la columna MODO
    row._selftest        = entry.selftest;
    row._hasDailyResult  = !!entry.primary;
    displayList.push(row);
  }

  // Ordenar por timestamp desc (más reciente primero)
  displayList.sort((a, b) =>
    (b.timestamp || '').localeCompare(a.timestamp || '')
  );

  // Contador: muestra dispositivos únicos
  const uniqueCount = displayList.length;
  if (count) {
    count.textContent = `${uniqueCount} dispositivo${uniqueCount !== 1 ? 's' : ''}`;
  }

  // ── 3. LOOKUP BLOCKCHAIN (ArcatRegistry) ──────────────────────────────────
  let registryContract = null;
  try {
    const activeSigner = getSigner();
    let providerOrSigner = activeSigner;
    if (!providerOrSigner && window.ethereum) {
      const { BrowserProvider } = await import('ethers');
      providerOrSigner = new BrowserProvider(window.ethereum);
    }
    if (providerOrSigner) {
      const { Contract } = await import('ethers');
      const overview = await api.getArcatOverview();
      const registryAddr = overview?.arcat?.arcat_registry;
      if (registryAddr && registryAddr !== '0x0000000000000000000000000000000000000000') {
        registryContract = new Contract(registryAddr, [
          'function lookupByUUID(string uuid) external view returns (address uoContract, uint256 tokenId, bool found)'
        ], providerOrSigner);
      }
    }
  } catch (e) {
    console.warn('No se pudo conectar a ArcatRegistry para lookup en tabla antivirus:', e);
  }

  // ── 4. HELPERS DE RENDERIZADO ────────────────────────────────────────────
  const statusBadge = (s) => {
    const map = {
      CLEAN:    { icon: '🟢', label: 'Limpio',    cls: 'av-badge-clean'    },
      INFECTED: { icon: '🔴', label: 'Infectado', cls: 'av-badge-infected' },
      ERROR:    { icon: '🟠', label: 'Error',      cls: 'av-badge-error'   },
      PENDING:  { icon: '🟡', label: 'Pendiente', cls: 'av-badge-pending'  },
    };
    const m = map[s?.toUpperCase()] || map.PENDING;
    return `<span class="av-status-badge ${m.cls}">${m.icon} ${m.label}</span>`;
  };

  const fmtDate = (ts) => {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'short' }); }
    catch { return ts; }
  };

  const shortUUID = (uuid) => uuid ? uuid.substring(0, 8) + '…' : '—';

  /**
   * Genera el contenido de la celda MODO:
   *  - Badge principal del modo real (DAILY / WEEKLY / SELFTEST si no hay otro)
   *  - Si hay resultado de autoprueba: chip secundario con su estado
   */
  const modeCellHtml = (r) => {
    const mode      = (r.scan_mode || 'Daily').toUpperCase();
    const modeLower = mode.toLowerCase();
    const mainBadge = `<span class="av-mode-badge av-mode-${modeLower}">${mode}</span>`;

    // Chip de autoprueba (solo si hay selftest Y la fila muestra resultado real)
    let selftestChip = '';
    if (r._hasDailyResult && r._selftest) {
      const stStatus = (r._selftest.status || '').toUpperCase();
      const isOk     = stStatus === 'CLEAN';
      const icon     = isOk ? '✓' : '⚠';
      const label    = isOk ? 'Autoprueba OK' : 'Autoprueba: error';
      const cls      = isOk ? '' : ' error';
      selftestChip   = `<span class="av-selftest-chip${cls}" title="SELFTEST — ${new Date(r._selftest.timestamp || '').toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'short' })}">${icon} ${label}</span>`;
    }

    return `<div class="av-mode-cell">${mainBadge}${selftestChip}</div>`;
  };

  // ── 5. GENERAR FILAS ──────────────────────────────────────────────────────
  const rows = await Promise.all(displayList.map(async (r, i) => {
    const infected    = parseInt(r.infected_count || 0);
    const infectedCls = infected > 0 ? 'av-row-infected' : '';

    let txLink = '<span class="av-tx-none">—</span>';
    if (r.blockchain_tx) {
      txLink = `<a href="#" class="av-tx-link" title="${r.blockchain_tx}" onclick="return false;">
                  ⛓️ ${r.blockchain_tx.slice(0, 8)}…
                </a>`;
    } else if (registryContract && r.device_uuid) {
      try {
        const [uoContract, tokenId, found] = await registryContract.lookupByUUID(r.device_uuid);
        if (found) {
          txLink = `<span class="av-sbt-badge" title="SBT Acuñado — Contrato UO: ${uoContract} (Token #${tokenId})" style="cursor:help; background:linear-gradient(135deg,#4f46e5,#4338ca); color:white; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:bold; display:inline-block; border:1px solid #6366f1;">
                      🏛️ SBT #${tokenId}
                    </span>`;
        }
      } catch (err) {
        console.warn(`Error lookupByUUID para ${r.device_uuid}:`, err);
      }
    }

    const detailBtn = infected > 0
      ? `<button class="av-detail-btn" onclick="window.showAvDetail(${i})">Ver ${infected} amenaza${infected > 1 ? 's' : ''}</button>`
      : '<span style="opacity:.4">—</span>';

    return `
      <tr class="${infectedCls}"
          data-av-hostname="${r.hostname?.toLowerCase() || ''}"
          data-av-uuid="${r.device_uuid?.toLowerCase() || ''}"
          data-av-status="${r.status?.toUpperCase() || 'PENDING'}"
          data-av-mode="${r.scan_mode || 'Daily'}">
        <td>${statusBadge(r.status)}</td>
        <td class="av-hostname">${r.hostname || '—'}</td>
        <td class="av-uuid" title="${r.device_uuid || ''}">${shortUUID(r.device_uuid)}</td>
        <td>${modeCellHtml(r)}</td>
        <td class="av-num">${(r.scanned_files || 0).toLocaleString()}</td>
        <td class="av-num ${infected > 0 ? 'av-infected-count' : ''}">${infected > 0 ? `🦠 ${infected}` : '0'}</td>
        <td class="av-ts">${fmtDate(r.timestamp)}</td>
        <td class="av-engine" style="text-align:center;">${(r.scanner || 'ClamAV').replace('ClamAV ', 'v')}</td>
        <td style="text-align:center;">${txLink}</td>
        <td>${detailBtn}</td>
      </tr>`;
  }));

  tbody.innerHTML = rows.join('');

  // ── 6. EXPONER displayList para showAvDetail ──────────────────────────────
  // showAvDetail usa el índice del array filtrado; actualizamos la referencia
  // para que el modal de amenazas funcione correctamente con los índices agrupados.
  window._avDisplayList = displayList;
}



/** Filtra la tabla por búsqueda y dropdowns de estado/modo */
window.filterAntivirusTable = async function(searchVal) {
  const search = (searchVal || document.getElementById('av-search')?.value || '').toLowerCase();
  const status = document.getElementById('av-filter-status')?.value || '';
  const mode   = document.getElementById('av-filter-mode')?.value   || '';

  const filtered = _avResultsCache.filter(r => {
    const matchSearch = !search ||
      (r.hostname || '').toLowerCase().includes(search) ||
      (r.device_uuid || '').toLowerCase().includes(search);
    const matchStatus = !status || (r.status || '').toUpperCase() === status.toUpperCase();
    const matchMode   = !mode   || (r.scan_mode || '') === mode;
    return matchSearch && matchStatus && matchMode;
  });

  await renderAntivirusTable(filtered);
};

/** Muestra el modal de detalle de amenazas para un dispositivo.
 *  Usa window._avDisplayList (lista agrupada por hostname) para
 *  mantener coherencia de índices con las filas renderizadas.
 */
window.showAvDetail = function(idx) {
  // Usar la lista agrupada expuesta por renderAntivirusTable
  const displayList = window._avDisplayList || [];
  const r = displayList[idx];
  if (!r) return;

  const modal = document.getElementById('av-detail-modal');
  const title = document.getElementById('av-modal-title');
  const body  = document.getElementById('av-modal-body');

  if (title) title.textContent = `🦠 Amenazas en ${r.hostname} — ${new Date(r.timestamp).toLocaleString('es-AR')}`;

  const files = r.infected_files || [];
  if (body) {
    body.innerHTML = `
      <div class="av-detail-meta">
        <div><strong>Dispositivo:</strong> ${r.hostname}</div>
        <div><strong>UUID:</strong> ${r.device_uuid || '—'}</div>
        <div><strong>Motor:</strong> ${r.scanner || 'ClamAV'}</div>
        <div><strong>Firmas:</strong> ${r.definitions_date || '—'}</div>
        <div><strong>Duración:</strong> ${r.scan_duration_s ? r.scan_duration_s + 's' : '—'}</div>
        <div><strong>Paths:</strong> ${(r.scan_paths || []).join(', ') || '—'}</div>
      </div>
      <div class="av-threats-list">
        <div class="av-threats-header">🔴 ${files.length} archivo${files.length !== 1 ? 's' : ''} infectado${files.length !== 1 ? 's' : ''}:</div>
        ${files.map(f => `<div class="av-threat-item">🦠 <code>${f}</code></div>`).join('')}
      </div>
      ${r.blockchain_tx ? `<div class="av-bc-info">⛓️ Registrado en Blockchain: <code>${r.blockchain_tx}</code></div>` : ''}
    `;
  }

  if (modal) modal.style.display = 'flex';
};

/** Descarga el instalador MSI (network o antivirus) desde el Gateway */
window.downloadAntivirusMsi = function(type) {
  const agentType = type === 'antivirus' ? 'antivirus' : 'network';
  const filename = type === 'antivirus' ? 'cybersec-antivirus-agent.msi' : 'cybersec-gateway-network.msi';
  
  const BASE = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';
  const url = `${BASE}/api/antivirus/download-installer?agent=${agentType}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast(`Iniciando descarga de ${filename}...`, 'success');
};

/** Muestra el modal de guía de instalación de ClamAV */
window.showClamavInstallGuide = function() {
  const modal = document.getElementById('av-install-modal');
  if (modal) modal.style.display = 'flex';
};

/** Copia el comando de instalación al portapapeles */
window.copyInstallCmd = function() {
  const cmd = document.getElementById('av-install-cmd')?.textContent || '';
  navigator.clipboard?.writeText(cmd).then(() => {
    toast('Comando copiado al portapapeles', 'success');
  });
};

/** Actualiza manualmente la vista antivirus */
window.refreshAntivirusView = function() {
  loadAntivirusView();
};

// Auto-polling antivirus cada 60 segundos si la vista está activa
setInterval(() => {
  const avView = document.getElementById('view-antivirus');
  if (avView?.classList.contains('active')) {
    loadAntivirusView();
  }
}, 60_000);


