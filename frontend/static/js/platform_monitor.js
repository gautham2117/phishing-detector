"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd          = document.getElementById("page-data");
var ADD_URL      = _pd.dataset.addUrl;
var REMOVE_URL   = _pd.dataset.removeUrl;
var SCAN_URL     = _pd.dataset.scanUrl;
var LIST_URL     = _pd.dataset.listUrl;
var FEED_URL     = _pd.dataset.feedUrl;
var POLL_URL     = _pd.dataset.pollUrl;
var HISTORY_URL  = _pd.dataset.historyUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var pmAddBtn      = document.getElementById("pmAddBtn");
var pmAddError    = document.getElementById("pmAddError");
var pmWatchBody   = document.getElementById("pmWatchBody");
var pmWatchCount  = document.getElementById("pmWatchCount");
var pmFeedBody    = document.getElementById("pmFeedBody");
var pmAlertBanner = document.getElementById("pmAlertBanner");
var pmAlertText   = document.getElementById("pmAlertText");
var pmHistoryCard = document.getElementById("pmHistoryCard");

var _historyChart = null;
var _pollTimer    = null;
var _feedTimer    = null;
var _watchTimer   = null;


// ════════════════════════════════════════════════════════════════════════════
// ADD TARGET
// ════════════════════════════════════════════════════════════════════════════

pmAddBtn.addEventListener("click", function () {
    var url       = document.getElementById("pmUrl").value.trim();
    var label     = document.getElementById("pmLabel").value.trim();
    var interval  = parseInt(document.getElementById("pmInterval").value, 10) || 60;
    var threshold = parseFloat(document.getElementById("pmThreshold").value) || 50.0;

    if (!url) {
        showAddError("Please enter a URL or domain.");
        return;
    }

    pmAddBtn.disabled = true;
    pmAddBtn.textContent = "Adding…";
    hideAddError();

    fetch(ADD_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            url:              url,
            label:            label || url,
            interval_minutes: interval,
            alert_threshold:  threshold,
        }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        pmAddBtn.disabled    = false;
        pmAddBtn.textContent = "Add to Watchlist";
        if (data.status !== "success") {
            showAddError(data.message || "Failed to add target.");
            return;
        }
        document.getElementById("pmUrl").value   = "";
        document.getElementById("pmLabel").value = "";
        loadWatchlist();
    })
    .catch(function (err) {
        pmAddBtn.disabled    = false;
        pmAddBtn.textContent = "Add to Watchlist";
        showAddError("Request failed: " + err.message);
    });
});


// ════════════════════════════════════════════════════════════════════════════
// WATCHLIST
// ════════════════════════════════════════════════════════════════════════════

function loadWatchlist() {
    fetch(LIST_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderWatchlist(data.targets || []);
        })
        .catch(function () {/* silent */});
}

function renderWatchlist(targets) {
    pmWatchCount.textContent = targets.length;
    pmWatchBody.innerHTML    = "";

    if (targets.length === 0) {
        pmWatchBody.innerHTML =
            '<tr><td colspan="8" class="att-empty-row">No targets yet.</td></tr>';
        return;
    }

    targets.forEach(function (t) {
        var verdictClass = {
            CLEAN:     "badge-safe",
            SUSPICIOUS:"badge-suspicious",
            MALICIOUS: "badge-malicious",
            UNKNOWN:   "",
        }[t.last_verdict] || "";

        var lastScan = t.last_scanned
            ? t.last_scanned.replace("T"," ").replace("Z","").slice(0,16)
            : "Never";

        var scoreClass = "";
        if (t.last_risk_score >= 70)      { scoreClass = "att-cell-red"; }
        else if (t.last_risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td class='pm-label'>" + escapeHtml(t.label) + "</td>" +
            "<td class='pm-domain'>" + escapeHtml(t.domain) + "</td>" +
            "<td>" + t.interval_minutes + " min</td>" +
            "<td>" + t.alert_threshold.toFixed(0) + "</td>" +
            "<td class='att-ts'>" + lastScan + "</td>" +
            "<td class='" + scoreClass + "'>" +
                (t.last_risk_score || 0).toFixed(1) +
            "</td>" +
            "<td>" +
                (t.last_verdict
                    ? "<span class='badge " + verdictClass + "'>" +
                      escapeHtml(t.last_verdict) + "</span>"
                    : "—") +
            "</td>" +
            "<td class='pm-actions'>" +
                "<button class='pm-btn pm-btn-scan' data-id='" + t.id + "'" +
                " data-label='" + escapeHtml(t.label) + "'>▶ Scan</button>" +
                "<button class='pm-btn pm-btn-history' data-id='" + t.id + "'" +
                " data-label='" + escapeHtml(t.label) + "'>📈 History</button>" +
                "<button class='pm-btn pm-btn-remove' data-id='" + t.id + "'>✕</button>" +
            "</td>";
        pmWatchBody.appendChild(tr);
    });
}

// Delegated click handlers for watchlist buttons
document.addEventListener("click", function (e) {
    var btn = e.target;

    if (btn.classList.contains("pm-btn-scan")) {
        var id    = btn.dataset.id;
        var label = btn.dataset.label;
        btn.disabled    = true;
        btn.textContent = "⏳";
        fetch(SCAN_URL + "/" + id + "/scan", { method: "POST" })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                btn.disabled    = false;
                btn.textContent = "▶ Scan";
                if (data.alert_fired) {
                    showAlert("⚠ Alert fired for '" + label +
                        "' — risk score: " + data.risk_score.toFixed(1));
                }
                loadWatchlist();
            })
            .catch(function () {
                btn.disabled    = false;
                btn.textContent = "▶ Scan";
            });
    }

    if (btn.classList.contains("pm-btn-remove")) {
        var id = btn.dataset.id;
        if (!confirm("Remove this target from the watchlist?")) { return; }
        fetch(REMOVE_URL + "/" + id + "/remove", { method: "DELETE" })
            .then(function (r) { return r.json(); })
            .then(function () { loadWatchlist(); })
            .catch(function () {/* silent */});
    }

    if (btn.classList.contains("pm-btn-history")) {
        var id    = btn.dataset.id;
        var label = btn.dataset.label;
        loadHistory(id, label);
    }
});


// ════════════════════════════════════════════════════════════════════════════
// RISK SCORE HISTORY CHART
// ════════════════════════════════════════════════════════════════════════════

function loadHistory(targetId, label) {
    fetch(HISTORY_URL + "/" + targetId + "/history?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistoryChart(data.history || [], label);
            pmHistoryCard.style.display = "block";
            pmHistoryCard.scrollIntoView({ behavior: "smooth" });
        })
        .catch(function () {/* silent */});
}

function renderHistoryChart(history, label) {
    document.getElementById("pmHistoryLabel").textContent = label;

    var reversed = history.slice().reverse();
    var labels   = reversed.map(function (h) {
        return (h.scanned_at || "").slice(11, 16);
    });
    var scores = reversed.map(function (h) {
        return h.risk_score || 0;
    });

    var total   = history.length;
    var avg     = total ? (scores.reduce(function (a, b) { return a + b; }, 0) / total).toFixed(1) : "—";
    var alerts  = history.filter(function (h) { return h.alert_fired; }).length;
    var verdict = history[0] ? history[0].verdict : "—";

    document.getElementById("pmHistTotal").textContent   = total;
    document.getElementById("pmHistAvg").textContent     = avg;
    document.getElementById("pmHistAlerts").textContent  = alerts;
    document.getElementById("pmHistVerdict").textContent = verdict;

    var ctx = document.getElementById("pmHistoryChart").getContext("2d");
    if (_historyChart) { _historyChart.destroy(); }

    _historyChart = new Chart(ctx, {
        type: "line",
        data: {
            labels:   labels,
            datasets: [{
                label:           "Risk Score",
                data:            scores,
                borderColor:     "#388bfd",
                backgroundColor: "rgba(56,139,253,0.1)",
                pointBackgroundColor: scores.map(function (s) {
                    if (s >= 70) { return "#f85149"; }
                    if (s >= 35) { return "#d29922"; }
                    return "#3fb950";
                }),
                pointRadius:  5,
                tension:      0.3,
                fill:         true,
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    min: 0, max: 100,
                    ticks: { color: "#8b949e" },
                    grid:  { color: "#21262d" },
                },
                x: {
                    ticks: { color: "#8b949e" },
                    grid:  { color: "#21262d" },
                },
            },
        },
    });
}

document.getElementById("pmHistoryClose").addEventListener("click", function () {
    pmHistoryCard.style.display = "none";
    if (_historyChart) { _historyChart.destroy(); _historyChart = null; }
});


// ════════════════════════════════════════════════════════════════════════════
// UNIFIED FEED
// ════════════════════════════════════════════════════════════════════════════

function loadFeed() {
    fetch(FEED_URL + "?limit=50")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderFeed(data.feed || []);
        })
        .catch(function () {/* silent */});
}

function renderFeed(feed) {
    pmFeedBody.innerHTML = "";
    if (feed.length === 0) {
        pmFeedBody.innerHTML =
            '<tr><td colspan="5" class="att-empty-row">No scans recorded yet.</td></tr>';
        return;
    }

    feed.forEach(function (item) {
        var verdictClass = verdictBadgeClass(item.verdict);
        var scoreClass   = "";
        if (item.risk_score >= 70)      { scoreClass = "att-cell-red"; }
        else if (item.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var ts = (item.scanned_at || "").replace("T"," ").replace("Z","").slice(0,16);

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td class='pm-module'>" +
                item.icon + " " + escapeHtml(item.module) +
            "</td>" +
            "<td class='pm-ref'>" + escapeHtml(item.ref || "—") + "</td>" +
            "<td class='" + scoreClass + "'>" +
                (item.risk_score || 0).toFixed(1) +
            "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                escapeHtml(item.verdict || "—") +
            "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        pmFeedBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// POLLING — check due targets every 30 seconds
// ════════════════════════════════════════════════════════════════════════════

function pollDueTargets() {
    fetch(POLL_URL, { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (!data || data.status !== "success") { return; }
            if (data.scanned_count > 0) {
                loadWatchlist();
                loadFeed();
            }
            if (data.alert_count > 0) {
                var names = (data.alerts || [])
                    .map(function (a) { return a.label + " (" + a.risk_score.toFixed(1) + ")"; })
                    .join(", ");
                showAlert(
                    data.alert_count + " alert(s) fired: " + names
                );
            }
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// ALERT BANNER
// ════════════════════════════════════════════════════════════════════════════

function showAlert(msg) {
    pmAlertText.textContent    = msg;
    pmAlertBanner.style.display = "flex";
}

document.getElementById("pmAlertClose").addEventListener("click", function () {
    pmAlertBanner.style.display = "none";
});


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function verdictBadgeClass(verdict) {
    var map = {
        CLEAN:     "badge-safe",
        SAFE:      "badge-safe",
        SUSPICIOUS:"badge-suspicious",
        MALICIOUS: "badge-malicious",
        LOW:       "badge-safe",
        MEDIUM:    "badge-suspicious",
        HIGH:      "badge-malicious",
        CRITICAL:  "badge-malicious",
    };
    return map[verdict] || "";
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function showAddError(msg) {
    pmAddError.textContent   = "⚠ " + msg;
    pmAddError.style.display = "block";
}
function hideAddError() {
    pmAddError.style.display = "none";
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadWatchlist();
loadFeed();
pollDueTargets();

// Watchlist + feed refresh every 10 seconds
_watchTimer = setInterval(loadWatchlist, 10000);
_feedTimer  = setInterval(loadFeed,      10000);

// Poll for due targets every 30 seconds
_pollTimer  = setInterval(pollDueTargets, 30000);