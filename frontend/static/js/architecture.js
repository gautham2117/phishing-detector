"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd         = document.getElementById("page-data");
var HEALTH_URL  = _pd.dataset.healthUrl;
var METRICS_URL = _pd.dataset.metricsUrl;
var PLAN_URL    = _pd.dataset.planUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var arcOverallBanner  = document.getElementById("arcOverallBanner");
var arcOverallDot     = document.getElementById("arcOverallDot");
var arcOverallLabel   = document.getElementById("arcOverallLabel");
var arcOverallSummary = document.getElementById("arcOverallSummary");
var arcHealthGrid     = document.getElementById("arcHealthGrid");
var arcDbBody         = document.getElementById("arcDbBody");

var _rateChart  = null;
var _planLoaded = false;
var _pollTimer  = null;

// Table → phase mapping
var TABLE_PHASE_MAP = {
    "email_scans":            "Phase 1",
    "url_scans":              "Phase 2",
    "network_scans":          "Phase 3",
    "port_results":           "Phase 3",
    "attachment_scans":       "Phase 6",
    "ai_detection_scans":     "Phase 8",
    "image_analysis_scans":   "Phase 7",
    "monitored_targets":      "Phase 9",
    "monitor_scan_results":   "Phase 9",
    "aggregated_risk_scores": "Phase 10",
    "feedback_samples":       "Phase 12",
    "model_versions":         "Phase 12",
    "alerts":                 "Phase 13",
    "audit_logs":             "Phase 13",
    "extension_scans":        "Phase 14",
};


// ════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════

function loadHealth() {
    fetch(HEALTH_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderOverallStatus(data.overall, data.summary);
            renderHealthGrid(data.modules || []);
        })
        .catch(function () {
            arcOverallLabel.textContent = "Health check failed — is FastAPI running?";
            arcOverallDot.className     = "arc-overall-dot arc-dot-offline";
        });
}

function renderOverallStatus(overall, summary) {
    var configs = {
        online:   { cls: "arc-dot-online",   color: "var(--green)",
                    text: "All Systems Operational" },
        degraded: { cls: "arc-dot-degraded", color: "var(--amber)",
                    text: "System Degraded" },
        offline:  { cls: "arc-dot-offline",  color: "var(--red)",
                    text: "System Offline" },
    };
    var cfg = configs[overall] || configs.offline;

    arcOverallDot.className      = "arc-overall-dot " + cfg.cls;
    arcOverallLabel.textContent  = cfg.text;
    arcOverallLabel.style.color  = cfg.color;
    arcOverallBanner.style.borderColor = cfg.color;
    arcOverallSummary.textContent = (
        summary.online   + " online · " +
        summary.degraded + " degraded · " +
        summary.offline  + " offline"
    );
}

function renderHealthGrid(modules) {
    arcHealthGrid.innerHTML = "";
    modules.forEach(function (mod) {
        var statusCfg = {
            online:   { cls: "arc-status-online",   icon: "✅", color: "var(--green)" },
            degraded: { cls: "arc-status-degraded", icon: "⚠",  color: "var(--amber)" },
            offline:  { cls: "arc-status-offline",  icon: "✕",  color: "var(--red)"   },
        }[mod.status] || { cls: "", icon: "?", color: "var(--text-muted)" };

        var card = document.createElement("div");
        card.className = "arc-health-item " + statusCfg.cls;
        card.innerHTML =
            "<div class='arc-hi-icon'>" + statusCfg.icon + "</div>" +
            "<div class='arc-hi-name'>" + escapeHtml(mod.name) + "</div>" +
            "<div class='arc-hi-latency' style='color:" + statusCfg.color + "'>" +
                (mod.status !== "offline"
                    ? mod.latency_ms + " ms"
                    : "offline") +
            "</div>" +
            "<div class='arc-hi-path'>" + escapeHtml(mod.path) + "</div>";
        arcHealthGrid.appendChild(card);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// METRICS
// ════════════════════════════════════════════════════════════════════════════

function loadMetrics() {
    fetch(METRICS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderMetrics(data);
        })
        .catch(function () {/* silent */});
}

function renderMetrics(data) {
    var sys = data.system || {};
    var db  = data.database || {};

    // Metric cards
    setText("arcCpu",    sys.available !== false
        ? (sys.cpu_percent || 0).toFixed(1) + "%" : "N/A");
    setText("arcMemMb",  sys.available !== false
        ? (sys.memory_mb  || 0).toFixed(1) + " MB" : "N/A");
    setText("arcRpm",    (data.requests_per_min || 0).toFixed(1));
    setText("arcDbSize", db.available !== false
        ? (db.db_size_mb || 0).toFixed(3) + " MB" : "N/A");
    setText("arcDbRows", db.available !== false
        ? (db.total_rows || 0).toLocaleString() : "N/A");

    // Rate chart
    renderRateChart(data.rate_history || []);

    // DB table stats
    renderDbStats(db.tables || []);
}

function renderRateChart(history) {
    var labels = history.map(function (h) { return h.label; });
    var counts = history.map(function (h) { return h.count; });

    var ctx = document.getElementById("arcRateChart").getContext("2d");

    if (_rateChart) {
        _rateChart.data.labels         = labels;
        _rateChart.data.datasets[0].data = counts;
        _rateChart.update();
        return;
    }

    _rateChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels:   labels,
            datasets: [{
                label:           "Requests",
                data:            counts,
                backgroundColor: "rgba(56,139,253,0.4)",
                borderColor:     "#388bfd",
                borderWidth:     1,
                borderRadius:    3,
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks:  { color: "#8b949e", stepSize: 1 },
                    grid:   { color: "#21262d" },
                },
                x: {
                    ticks: { color: "#8b949e", maxRotation: 0 },
                    grid:  { display: false },
                },
            },
        },
    });
}

function renderDbStats(tables) {
    arcDbBody.innerHTML = "";
    if (tables.length === 0) {
        arcDbBody.innerHTML =
            '<tr><td colspan="3" class="att-empty-row">No table data.</td></tr>';
        return;
    }

    tables.forEach(function (t) {
        var phase = TABLE_PHASE_MAP[t.name] || "—";
        var rows  = t.rows !== null ? t.rows.toLocaleString() : "—";
        var rowClass = "";
        if (t.rows !== null && t.rows > 1000) { rowClass = "att-cell-amber"; }
        if (t.rows !== null && t.rows > 10000){ rowClass = "att-cell-red";   }

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td><code class='al-action-code'>" +
                escapeHtml(t.name) + "</code></td>" +
            "<td class='" + rowClass + "'>" + rows + "</td>" +
            "<td><span class='arc-phase-badge'>" + phase + "</span></td>";
        arcDbBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// MIGRATION PLAN
// ════════════════════════════════════════════════════════════════════════════

document.getElementById("arcPlanToggle").addEventListener("click", function () {
    var body = document.getElementById("arcPlanBody");
    if (body.style.display === "none") {
        body.style.display = "block";
        this.textContent   = "Hide Plan";
        if (!_planLoaded) {
            loadMigrationPlan();
            _planLoaded = true;
        }
    } else {
        body.style.display = "none";
        this.textContent   = "Show Plan";
    }
});

function loadMigrationPlan() {
    fetch(PLAN_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderMigrationPlan(data.plan || {});
        })
        .catch(function () {/* silent */});
}

function renderMigrationPlan(plan) {
    var container = document.getElementById("arcPlanSteps");
    container.innerHTML = "";

    var phases = plan.phases || [];
    phases.forEach(function (phase) {
        var step = document.createElement("div");
        step.className = "arc-plan-step";

        var cmdsHtml = "";
        if (phase.commands && phase.commands.length) {
            var cmdLines = phase.commands.map(function (c) {
                return escapeHtml(c);
            }).join("\n");
            cmdsHtml = "<pre class='mm-plan-code'>" + cmdLines + "</pre>";
        }

        step.innerHTML =
            "<div class='mm-plan-step-header'>" +
                "<span class='mm-plan-step-num'>Phase " + phase.phase + "</span>" +
                "<span class='mm-plan-step-name'>" +
                    escapeHtml(phase.name) + "</span>" +
                "<span class='arc-plan-status arc-status-ready'>✓ Ready</span>" +
            "</div>" +
            "<p class='mm-plan-desc'>" +
                escapeHtml(phase.description) + "</p>" +
            cmdsHtml +
            "<div class='arc-plan-note'>" +
                "💡 " + escapeHtml(phase.notes) +
            "</div>";
        container.appendChild(step);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function setText(id, val) {
    var el = document.getElementById(id);
    if (el) { el.textContent = val; }
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHealth();
loadMetrics();

// Health checks every 15s (expensive — pings all endpoints)
// Metrics every 5s (cheap — just reads memory/CPU/DB)
setInterval(loadHealth,  15000);
setInterval(loadMetrics, 5000);