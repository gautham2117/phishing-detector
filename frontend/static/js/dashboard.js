// dashboard.js
// Live data polling and Chart.js rendering for the Overview page.
"use strict";

let _distChart  = null;   // Chart.js doughnut instance
let _trendChart = null;   // Chart.js bar chart instance
let _pollTimer  = null;   // setInterval handle


// ─── Polling ─────────────────────────────────────────────────────────────────

function startDashboardPolling() {
  // Poll every 5 seconds
  _pollTimer = setInterval(refreshDashboard, 5000);
}

async function refreshDashboard() {
  try {
    const resp = await fetch("/dashboard/stats");
    if (!resp.ok) return;
    const data = await resp.json();

    _updateStatCards(data.stats);
    _updateThreatFeed(data.threat_feed || []);
    _updateTopDomains(data.top_domains || []);
    _updateAlerts(data.alerts || []);
    _updateHealthGrid(data.module_health || []);
    _updateDistChart(data.distribution || {});
    _updateTrendChart(data.trend || []);

    document.getElementById("update-time").textContent =
      new Date().toLocaleTimeString();

  } catch (err) {
    console.warn("Dashboard poll failed:", err.message);
  }
}


// ─── Stat cards ──────────────────────────────────────────────────────────────

function _updateStatCards(stats) {
  _setText("ov-total",   stats.total_scans_today ?? "—");
  _setText("ov-emails",  stats.emails_today      ?? "—");
  _setText("ov-urls",    stats.urls_today         ?? "—");
  _setText("ov-threats", stats.threats_today      ?? "—");
  _setText("ov-alerts",  stats.alerts_today       ?? "—");
}


// ─── Threat feed ─────────────────────────────────────────────────────────────

function _updateThreatFeed(items) {
  const container = document.getElementById("threat-feed");
  if (!container) return;

  if (!items.length) {
    container.innerHTML =
      '<p class="empty-state">No scans yet.</p>';
    return;
  }

  container.innerHTML = items.map(item => {
    const labelCls = (item.label || "unknown").toLowerCase();
    return `<div class="feed-row feed-${labelCls}">
      <span class="feed-type-pill">${_esc(item.type)}</span>
      <span class="feed-display" title="${_esc(item.detail || "")}">
        ${_esc(_trunc(item.display, 55))}
      </span>
      <span class="feed-score score-${labelCls}">${item.risk_score}</span>
      <span class="label-badge label-${labelCls}">${_esc(item.label)}</span>
      <a href="${_esc(item.link || '#')}" class="feed-link">→</a>
    </div>`;
  }).join("");
}


// ─── Top domains ─────────────────────────────────────────────────────────────

function _updateTopDomains(domains) {
  const tbody = document.getElementById("top-domains-body");
  if (!tbody) return;

  if (!domains.length) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="empty-state">No URL scans yet</td></tr>';
    return;
  }

  tbody.innerHTML = domains.map(d => {
    const score    = d.avg_score ?? 0;
    const fillCls  = score >= 70 ? "fill-malicious"
                   : score >= 30 ? "fill-suspicious" : "fill-safe";
    const labelCls = (d.label || "benign").toLowerCase();

    return `<tr>
      <td><code>${_esc(d.domain)}</code></td>
      <td>
        <div class="mini-bar-track">
          <div class="mini-bar-fill ${fillCls}"
               style="width:${score}%"></div>
        </div>
        ${score}
      </td>
      <td>${d.scan_count}</td>
      <td>
        <span class="label-badge label-${labelCls}">${_esc(d.label)}</span>
      </td>
    </tr>`;
  }).join("");
}


// ─── Recent alerts ────────────────────────────────────────────────────────────

function _updateAlerts(alerts) {
  const container = document.getElementById("recent-alerts");
  if (!container) return;

  if (!alerts.length) {
    container.innerHTML = '<p class="empty-state">No alerts yet.</p>';
    return;
  }

  container.innerHTML = alerts.map(a => {
    const sevCls    = (a.severity || "low").toLowerCase();
    const actionCls = (a.action   || "warn").toLowerCase();

    return `<div class="alert-row sev-${sevCls}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span class="sev-badge sev-${sevCls}">${_esc(a.severity)}</span>
        <span style="font-size:12px;color:var(--text-muted)">
          ${_esc(a.input_type)} · score ${a.risk_score}
        </span>
        <span class="action-pill action-${actionCls}"
              style="margin-left:auto;font-size:11px;padding:2px 8px;">
          ${_esc(a.action)}
        </span>
      </div>
      <p style="font-size:12px;color:var(--text-muted);margin:0;">
        ${_esc(a.summary)}
      </p>
    </div>`;
  }).join("");
}


// ─── Module health grid ───────────────────────────────────────────────────────

function _updateHealthGrid(modules) {
  const grid = document.getElementById("health-grid");
  if (!grid) return;

  grid.innerHTML = modules.map(m =>
    `<a href="${_esc(m.link)}"
        class="health-pill health-${m.status}"
        title="${_esc(m.name)}">
      <span class="health-dot"></span>
      ${_esc(m.name)}
    </a>`
  ).join("");
}


// ─── Distribution doughnut chart ─────────────────────────────────────────────

function initDistChart(safe, suspicious, malicious) {
  const ctx = document.getElementById("dist-chart");
  if (!ctx) return;

  _distChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels:   ["Safe", "Suspicious", "Malicious"],
      datasets: [{
        data:            [safe, suspicious, malicious],
        backgroundColor: ["#3fb950", "#d29922", "#f85149"],
        borderColor:     ["#3fb950", "#d29922", "#f85149"],
        borderWidth:     0,
        hoverOffset:     4
      }]
    },
    options: {
      responsive:  true,
      cutout:      "65%",
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`
          }
        }
      }
    }
  });
}

function _updateDistChart(dist) {
  if (!_distChart) return;
  _distChart.data.datasets[0].data = [
    dist.safe       || 0,
    dist.suspicious || 0,
    dist.malicious  || 0
  ];
  _distChart.update("none"); // "none" = no animation on refresh
}


// ─── 7-day trend bar chart ────────────────────────────────────────────────────

function initTrendChart(trendData) {
  const ctx = document.getElementById("trend-chart");
  if (!ctx) return;

  const labels = trendData.map(d => d.label || d.date);
  const totals = trendData.map(d => d.total || 0);

  _trendChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label:           "Total scans",
        data:            totals,
        backgroundColor: "rgba(56,139,253,0.45)",
        borderColor:     "#388bfd",
        borderWidth:     1,
        borderRadius:    3
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid:  { color: "rgba(255,255,255,0.04)" },
          ticks: { color: "#8b949e", font: { size: 11 } }
        },
        y: {
          beginAtZero: true,
          grid:  { color: "rgba(255,255,255,0.04)" },
          ticks: { color: "#8b949e", font: { size: 11 }, precision: 0 }
        }
      }
    }
  });
}

function _updateTrendChart(trendData) {
  if (!_trendChart || !trendData.length) return;
  _trendChart.data.labels                    = trendData.map(d => d.label || d.date);
  _trendChart.data.datasets[0].data          = trendData.map(d => d.total || 0);
  _trendChart.update("none");
}


// ─── Helpers ──────────────────────────────────────────────────────────────────

function _setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function _esc(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function _trunc(str, max) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}