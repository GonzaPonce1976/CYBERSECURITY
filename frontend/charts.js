/**
 * charts.js — Chart.js wrappers para el dashboard
 */
import { Chart, registerables } from 'chart.js';
Chart.register(...registerables);

const COLORS = {
  CRITICAL: '#ff3a5c',
  HIGH:     '#ff7b00',
  MEDIUM:   '#ffd700',
  LOW:      '#00d4ff',
  INFO:     '#00ff9d',
};

let severityChart = null;
let timelineChart = null;

/**
 * Inicializa el gráfico de dona de severidades
 */
export function initSeverityChart() {
  const canvas = document.getElementById('severity-chart');
  if (!canvas) return;

  severityChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: Object.values(COLORS).map(c => c + '33'),
        borderColor: Object.values(COLORS),
        borderWidth: 2,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw} alertas`,
          },
        },
      },
      animation: { animateRotate: true, duration: 800 },
    },
  });
}

/**
 * Actualiza el gráfico de dona con nuevos datos
 */
export function updateSeverityChart(counts) {
  if (!severityChart) return;
  const vals = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => counts[s] || 0);
  severityChart.data.datasets[0].data = vals;
  severityChart.update('active');

  // Actualizar leyenda manual
  const legend = document.getElementById('chart-legend');
  if (!legend) return;
  legend.innerHTML = Object.entries(COLORS).map(([sev, color]) => `
    <div class="legend-item">
      <span class="legend-dot" style="background:${color}"></span>
      <span>${sev}</span>
      <span class="legend-value" style="color:${color}">${counts[sev] || 0}</span>
    </div>
  `).join('');
}

/**
 * Inicializa el gráfico de línea de alertas en el tiempo
 */
export function initTimelineChart() {
  const canvas = document.getElementById('timeline-chart');
  if (!canvas) return;

  const labels = Array.from({ length: 12 }, (_, i) => `${i * 5}m`);

  timelineChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Críticas',
          data: new Array(12).fill(0),
          borderColor: COLORS.CRITICAL,
          backgroundColor: COLORS.CRITICAL + '18',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
        },
        {
          label: 'Altas',
          data: new Array(12).fill(0),
          borderColor: COLORS.HIGH,
          backgroundColor: COLORS.HIGH + '18',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          display: true,
          labels: { color: '#8892a4', boxWidth: 12, font: { size: 11 } },
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#8892a4', font: { size: 11 } },
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#8892a4', font: { size: 11 }, precision: 0 },
        },
      },
      animation: { duration: 600 },
    },
  });
}

/**
 * Inserta un nuevo punto en el timeline (desplazando el array)
 */
export function pushTimelinePoint(criticalCount, highCount) {
  if (!timelineChart) return;
  const now = new Date().toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
  timelineChart.data.labels.push(now);
  timelineChart.data.labels.shift();
  timelineChart.data.datasets[0].data.push(criticalCount);
  timelineChart.data.datasets[0].data.shift();
  timelineChart.data.datasets[1].data.push(highCount);
  timelineChart.data.datasets[1].data.shift();
  timelineChart.update('none');
}
