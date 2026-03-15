"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd        = document.getElementById("page-data");
var LIST_URL   = _pd.dataset.listUrl;
var STATS_URL  = _pd.dataset.statsUrl;
var DETAIL_URL = _pd.dataset.detailUrl;
var CSV_URL    = _pd.dataset.csvUrl;
var PDF_URL    = _pd.dataset.pdfUrl;
var AUDIT_URL  = _pd.dataset.auditUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var alFeedBody  = document.getElementById("alFeedBody");
var alFeedCount = document.getElementById("alFeedCount");
var alAuditBody = document.getElementById("alAuditBody");
var _pollTimer  = null;

// ── Severity config ────────────────────────────────────────────────────────
var SEV_CONFIG = {
    Critical: { color: "var(--red)",   bg: "rgba(248,81,73,.12)",  icon: "🚨" },
    High:     { color: "var(--amber)", bg: "rgba(210,153,34,.10)", icon: "⚠"  },
    Medium:   { color: "var(--blue)",  bg: "rgba(56,139,253,.10)", icon: "🔶" },
    Low:      { color: "var(--green)", bg: "rgba(63,185,80,.08)",  icon: "🔷" },
};


// ════════════════════════════════════════════════════════════════════════════
// STATS
// ════════════════════════════════════════════════════════════════════════════

function loadStats() {
    fetch(STATS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            var s  = data.stats || {};
            var bs = s.by_severity || {};
            setText("alStatTotal",    s.total       || 0);
            setText("alStatOpen",     s.open        || 0);
            setText("alStatCritical", bs.Critical   || 0);
            setText("alStatHigh",     bs.High       || 0);
            setText("alStatMedium",   bs.Medium     || 0);
            setText("alStatLow",      bs.Low        || 0);
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// ALERT FEED
// ════════════════════════════════════════════════════════════════════════════

function buildFilterParams() {
    var params = [];
    var sev    = document.getElementById("alFiltSeverity").value;
    var mod    = document.getElementById("alFiltModule").value;
    var stat   = document.getElementById("alFiltStatus").value;
    var from   = document.getElementById("alFiltFrom").value;
    var to     = document.getElementById("alFiltTo").value;
    if (sev)  { params.push("severity="  + encodeURIComponent(sev));  }
    if (mod)  { params.push("module="    + encodeURIComponent(mod));  }
    if (stat) { params.push("status="    + encodeURIComponent(stat)); }
    if (from) { params.push("date_from=" + encodeURIComponent(from)); }
    if (to)   { params.push("date_to="   + encodeURIComponent(to));   }
    params.push("limit=200");
    return params.length ? "?" + params.join("&") : "?limit=200";
}

function loadAlerts() {
    fetch(LIST_URL + buildFilterParams())
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderAlerts(data.alerts || []);
        })
        .catch(function () {/* silent */});
}

function renderAlerts(alerts) {
    alFeedCount.textContent = alerts.length;
    alFeedBody.innerHTML    = "";

    if (alerts.length === 0) {
        alFeedBody.innerHTML =
            '<p class="att-empty-note" style="padding:20px">' +
            'No alerts match the current filters.</p>';
        return;
    }

    alerts.forEach(function (a) {
        var cfg  = SEV_CONFIG[a.severity] || SEV_CONFIG.Low;
        var card = document.createElement("div");
        card.className = "al-card";
        card.style.borderLeftColor = cfg.color;
        card.style.background      = cfg.bg;

        var statusBadge = {
            open:         "<span class='badge badge-malicious'>Open</span>",
            acknowledged: "<span class='badge badge-suspicious'>Acknowledged</span>",
            dismissed:    "<span class='badge'>Dismissed</span>",
        }[a.status] || "";

        var rules = (a.triggered_rules || []).slice(0, 4).join(", ") || "—";
        var ts    = (a.created_at || "").replace("T"," ").replace("Z","").slice(0,16);

        card.innerHTML =
            "<div class='al-card-header'>" +
                "<span class='al-sev-badge' style='color:" + cfg.color + "'>" +
                    cfg.icon + " " + a.severity +
                "</span>" +
                "<span class='al-module-tag'>" +
                    escapeHtml(a.module) + " · " +
                    escapeHtml(a.input_type) +
                "</span>" +
                "<span class='al-risk-score " + riskClass(a.risk_score) + "'>" +
                    (a.risk_score || 0).toFixed(1) + "/100" +
                "</span>" +
                statusBadge +
                "<span class='al-ts'>" + ts + "</span>" +
            "</div>" +
            "<div class='al-card-summary'>" +
                "🤖 " + escapeHtml(a.threat_summary || "No summary.") +
            "</div>" +
            "<div class='al-card-meta'>" +
                "<span>Rules: " + escapeHtml(rules) + "</span>" +
                "<span>Action: <strong>" +
                    escapeHtml(a.recommended_action) + "</strong></span>" +
                "<span>ID #" + a.id + "</span>" +
            "</div>" +
            "<div class='al-card-actions'>" +
                (a.status === "open"
                    ? "<button class='pm-btn pm-btn-history al-ack-btn' " +
                      "data-id='" + a.id + "'>✓ Acknowledge</button>"
                    : "") +
                (a.status !== "dismissed"
                    ? "<button class='pm-btn pm-btn-remove al-dis-btn' " +
                      "data-id='" + a.id + "'>✕ Dismiss</button>"
                    : "") +
                "<button class='pm-btn al-pdf-btn' " +
                "data-id='" + a.id + "'>⬇ PDF</button>" +
            "</div>";

        alFeedBody.appendChild(card);
    });
}

// Delegated button handlers
document.addEventListener("click", function (e) {
    var btn = e.target;

    // Acknowledge
    if (btn.classList.contains("al-ack-btn")) {
        var id = btn.dataset.id;
        btn.disabled    = true;
        btn.textContent = "⏳";
        fetch(DETAIL_URL + "/" + id + "/acknowledge", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body:    JSON.stringify({actor: "admin"}),
        })
        .then(function (r) { return r.json(); })
        .then(function () { loadAlerts(); loadStats(); loadAuditLog(); })
        .catch(function () { btn.disabled = false; });
        return;
    }

    // Dismiss
    if (btn.classList.contains("al-dis-btn")) {
        var id     = btn.dataset.id;
        var reason = prompt("Dismiss reason (optional):", "");
        if (reason === null) { return; }
        btn.disabled    = true;
        btn.textContent = "⏳";
        fetch(DETAIL_URL + "/" + id + "/dismiss", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body:    JSON.stringify({reason: reason, actor: "admin"}),
        })
        .then(function (r) { return r.json(); })
        .then(function () { loadAlerts(); loadStats(); loadAuditLog(); })
        .catch(function () { btn.disabled = false; });
        return;
    }

    // PDF export
    if (btn.classList.contains("al-pdf-btn")) {
        var id = btn.dataset.id;
        window.open(PDF_URL + "/" + id + "/export/pdf", "_blank");
    }
});

// Filter button
document.getElementById("alApplyFilter").addEventListener("click", function () {
    loadAlerts();
});

// CSV export
document.getElementById("alCsvBtn").addEventListener("click", function () {
    var params = buildFilterParams();
    window.open(CSV_URL + params, "_blank");
});


// ════════════════════════════════════════════════════════════════════════════
// AUDIT LOG
// ════════════════════════════════════════════════════════════════════════════

function loadAuditLog() {
    fetch(AUDIT_URL + "?limit=50")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderAuditLog(data.logs || []);
        })
        .catch(function () {/* silent */});
}

function renderAuditLog(logs) {
    alAuditBody.innerHTML = "";
    if (logs.length === 0) {
        alAuditBody.innerHTML =
            '<tr><td colspan="7" class="att-empty-row">No audit entries yet.</td></tr>';
        return;
    }
    logs.forEach(function (log) {
        var ts     = (log.created_at || "").replace("T"," ").replace("Z","").slice(0,19);
        var detail = "";
        try {
            var d  = JSON.parse(log.detail);
            detail = Object.entries(d)
                .map(function (kv) { return kv[0] + ": " + kv[1]; })
                .join(" | ")
                .slice(0, 100);
        } catch (e) {
            detail = (log.detail || "").slice(0, 100);
        }
        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + log.id + "</td>" +
            "<td><code class='al-action-code'>" +
                escapeHtml(log.action) + "</code></td>" +
            "<td>" + escapeHtml(log.actor)  + "</td>" +
            "<td>" + escapeHtml(log.module) + "</td>" +
            "<td>" + (log.object_id || "—") + "</td>" +
            "<td class='al-detail-cell'>" + escapeHtml(detail) + "</td>" +
            "<td class='att-ts'>" + ts + "</td>";
        alAuditBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function riskClass(score) {
    if (score >= 70) { return "att-cell-red"; }
    if (score >= 35) { return "att-cell-amber"; }
    return "";
}

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

loadStats();
loadAlerts();
loadAuditLog();

_pollTimer = setInterval(function () {
    loadStats();
    loadAlerts();
    loadAuditLog();
}, 5000);