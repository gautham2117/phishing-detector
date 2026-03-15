"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd        = document.getElementById("page-data");
var STATS_URL  = _pd ? _pd.dataset.statsUrl  : "/dashboard/stats";
var HEALTH_URL = _pd ? _pd.dataset.healthUrl : "/dashboard/health";

// ── DOM ────────────────────────────────────────────────────────────────────
var dbFeedBody    = document.getElementById("dbFeedBody");
var dbDomainsBody = document.getElementById("dbDomainsBody");
var dbAlertsBody  = document.getElementById("dbAlertsBody");
var dbHealthRow   = document.getElementById("dbHealthRow");

var _pieChart     = null;
var _pollTimer    = null;
var _healthTimer  = null;


// ════════════════════════════════════════════════════════════════════════════
// MAIN STATS POLL
// ════════════════════════════════════════════════════════════════════════════

function loadStats() {
    fetch(STATS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderCounts(data.counts    || {});
            renderPieChart(data.distribution || {});
            renderFeed(data.live_feed   || []);
            renderDomains(data.top_domains || []);
            renderAlerts(data.alerts    || []);
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// SCAN COUNTS
// ════════════════════════════════════════════════════════════════════════════

function renderCounts(counts) {
    setText("dbCountTotal",      counts.total      || 0);
    setText("dbCountEmail",      counts.email      || 0);
    setText("dbCountUrl",        counts.url        || 0);
    setText("dbCountNetwork",    counts.network    || 0);
    setText("dbCountAttachment", counts.attachment || 0);
    setText("dbCountAi",         counts.ai         || 0);
    setText("dbCountImage",      counts.image      || 0);
}


// ════════════════════════════════════════════════════════════════════════════
// PIE CHART
// ════════════════════════════════════════════════════════════════════════════

function renderPieChart(dist) {
    var safe       = dist.safe       || 0;
    var suspicious = dist.suspicious || 0;
    var malicious  = dist.malicious  || 0;
    var total      = dist.total      || 1;

    // Legend
    var legendEl = document.getElementById("dbPieLegend");
    if (legendEl) {
        legendEl.innerHTML =
            "<div class='db-pie-item'>" +
                "<span class='db-pie-dot' style='background:#3fb950'></span>" +
                "<span>Safe</span>" +
                "<strong>" + safe + "</strong>" +
            "</div>" +
            "<div class='db-pie-item'>" +
                "<span class='db-pie-dot' style='background:#d29922'></span>" +
                "<span>Suspicious</span>" +
                "<strong>" + suspicious + "</strong>" +
            "</div>" +
            "<div class='db-pie-item'>" +
                "<span class='db-pie-dot' style='background:#f85149'></span>" +
                "<span>Malicious</span>" +
                "<strong>" + malicious + "</strong>" +
            "</div>" +
            "<div class='db-pie-item db-pie-total'>" +
                "<span>Total</span>" +
                "<strong>" + total + "</strong>" +
            "</div>";
    }

    var ctx = document.getElementById("dbPieChart");
    if (!ctx) { return; }

    var data = {
        labels:   ["Safe", "Suspicious", "Malicious"],
        datasets: [{
            data:            [safe, suspicious, malicious],
            backgroundColor: ["#3fb950", "#d29922", "#f85149"],
            borderColor:     "#0f1117",
            borderWidth:     3,
        }],
    };

    if (_pieChart) {
        _pieChart.data = data;
        _pieChart.update();
        return;
    }

    _pieChart = new Chart(ctx.getContext("2d"), {
        type: "doughnut",
        data: data,
        options: {
            responsive:  false,
            cutout:      "65%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function (ctx) {
                            var pct = total > 0
                                ? Math.round((ctx.parsed / total) * 100)
                                : 0;
                            return " " + ctx.label + ": " +
                                ctx.parsed + " (" + pct + "%)";
                        },
                    },
                },
            },
        },
    });
}


// ════════════════════════════════════════════════════════════════════════════
// LIVE FEED
// ════════════════════════════════════════════════════════════════════════════

function renderFeed(feed) {
    dbFeedBody.innerHTML = "";
    if (feed.length === 0) {
        dbFeedBody.innerHTML =
            '<tr><td colspan="5" class="att-empty-row">' +
            'No scans recorded yet.</td></tr>';
        return;
    }
    feed.forEach(function (item) {
        var verdictClass = {
            SAFE:       "badge-safe",
            CLEAN:      "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
        }[item.verdict] || "";

        var scoreClass = "";
        if (item.risk_score >= 70)      { scoreClass = "att-cell-red";   }
        else if (item.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var ts = (item.scanned_at || "")
            .replace("T", " ").replace("Z", "").slice(0, 16);

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + escapeHtml(item.icon) + " " +
                escapeHtml(item.module) + "</td>" +
            "<td class='lm-ref-cell'>" +
                escapeHtml(item.ref || "—") + "</td>" +
            "<td class='" + scoreClass + "'>" +
                (item.risk_score || 0).toFixed(1) + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                escapeHtml(item.verdict || "—") + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        dbFeedBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// TOP RISKY DOMAINS
// ════════════════════════════════════════════════════════════════════════════

function renderDomains(domains) {
    dbDomainsBody.innerHTML = "";
    if (domains.length === 0) {
        dbDomainsBody.innerHTML =
            '<tr><td colspan="3" class="att-empty-row">' +
            'No URL scans today.</td></tr>';
        return;
    }
    domains.forEach(function (d) {
        var verdictClass = {
            MALICIOUS:  "badge-malicious",
            SUSPICIOUS: "badge-suspicious",
            SAFE:       "badge-safe",
        }[d.verdict] || "";

        var scoreClass = "";
        if (d.risk_score >= 70)      { scoreClass = "att-cell-red";   }
        else if (d.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td class='ext-domain-cell'>" +
                escapeHtml(d.domain) + "</td>" +
            "<td class='" + scoreClass + "'>" +
                d.risk_score.toFixed(1) + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                escapeHtml(d.verdict || "—") + "</span></td>";
        dbDomainsBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// RECENT ALERTS PANEL
// ════════════════════════════════════════════════════════════════════════════

function renderAlerts(alerts) {
    dbAlertsBody.innerHTML = "";
    if (alerts.length === 0) {
        dbAlertsBody.innerHTML =
            '<p class="att-empty-note" style="padding:8px">No open alerts.</p>';
        return;
    }

    var sevColors = {
        Critical: "#f85149",
        High:     "#d29922",
        Medium:   "#388bfd",
        Low:      "#3fb950",
    };

    alerts.forEach(function (a) {
        var color  = sevColors[a.severity] || "#8b949e";
        var ts     = (a.created_at || "")
            .replace("T", " ").replace("Z", "").slice(0, 16);

        var div = document.createElement("div");
        div.className = "db-alert-item";
        div.style.borderLeftColor = color;
        div.innerHTML =
            "<div class='db-alert-header'>" +
                "<span class='db-alert-sev' style='color:" + color + "'>" +
                    escapeHtml(a.severity) +
                "</span>" +
                "<span class='db-alert-module'>" +
                    escapeHtml(a.module) +
                "</span>" +
                "<span class='db-alert-score " +
                    (a.risk_score >= 70 ? "att-cell-red" :
                     a.risk_score >= 35 ? "att-cell-amber" : "") + "'>" +
                    (a.risk_score || 0).toFixed(1) +
                "</span>" +
                "<span class='db-alert-ts'>" + ts + "</span>" +
            "</div>" +
            "<div class='db-alert-summary'>" +
                escapeHtml((a.summary || "—").slice(0, 100)) +
            "</div>";
        dbAlertsBody.appendChild(div);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// MODULE HEALTH ROW
// ════════════════════════════════════════════════════════════════════════════

function loadHealth() {
    fetch(HEALTH_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHealthRow(data.modules || []);
        })
        .catch(function () {/* silent */});
}

function renderHealthRow(modules) {
    dbHealthRow.innerHTML = "";
    if (modules.length === 0) {
        dbHealthRow.innerHTML =
            '<p class="att-empty-note">No health data available.</p>';
        return;
    }

    modules.forEach(function (mod) {
        var cfg = {
            online:   { color: "var(--green)", icon: "●", cls: "db-health-online"   },
            degraded: { color: "var(--amber)", icon: "◐", cls: "db-health-degraded" },
            offline:  { color: "var(--red)",   icon: "○", cls: "db-health-offline"  },
        }[mod.status] || { color: "#8b949e", icon: "?", cls: "" };

        var pill = document.createElement("div");
        pill.className = "db-health-pill " + cfg.cls;
        pill.title     = mod.name + " — " + mod.latency_ms + "ms";
        pill.innerHTML =
            "<span class='db-health-dot' " +
                "style='color:" + cfg.color + "'>" +
                cfg.icon +
            "</span>" +
            "<span class='db-health-name'>" +
                escapeHtml(mod.name) +
            "</span>";
        dbHealthRow.appendChild(pill);
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

loadStats();
loadHealth();

// Stats every 5s, health every 15s
_pollTimer   = setInterval(loadStats,  5000);
_healthTimer = setInterval(loadHealth, 15000);