/**
 * main.js — Punto de entrada del dashboard CyberSec DApp
 */
import { api } from './api.js';
import { toast } from './toast.js';
import { connectWallet, initWalletButton } from './wallet.js';
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
    $('svc-shodan-cfg').textContent  = apis.shodan ? '✅ Sí' : '⚠️ No';
    setBadge('svc-shodan-badge', apis.shodan, apis.shodan ? 'Configurado' : 'Sin config');
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
  $('svc-chain-network').textContent = chain.online ? 'Hardhat / Anvil — Chain 31337' : '—';
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

  // Wallet
  initWalletButton();
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

  // Contrato SecurityAudit — mostrar dirección dinámica real del gateway al iniciar
  try {
    const chain = await checkBlockchain();
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
