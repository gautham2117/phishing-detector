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
var pmAddBtn       = document.getElementById("pmAddBtn");
var pmAddError     = document.getElementById("pmAddError");
var pmWatchBody    = document.getElementById("pmWatchBody");
var pmWatchCount   = document.getElementById("pmWatchCount");
var pmFeedBody     = document.getElementById("pmFeedBody");
var pmFeedMeta     = document.getElementById("pmFeedMeta");
var pmAlertBanner  = document.getElementById("pmAlertBanner");
var pmAlertText    = document.getElementById("pmAlertText");
var pmHistoryTitle = document.getElementById("pmHistoryTitle");
var pmHistoryClose = document.getElementById("pmHistoryClose");
var pmChartEmpty   = document.getElementById("pmChartEmpty");

var _historyChart  = null;
var _pollTimer     = null;
var _feedTimer     = null;
var _watchTimer    = null;

// Cached watchlist targets — used to rebuild overview chart after
// a per-target history view is closed.
var _cachedTargets = [];


// ════════════════════════════════════════════════════════════════════════════
// ADD TARGET
// ════════════════════════════════════════════════════════════════════════════

pmAddBtn.addEventListener("click", function () {
    var url       = document.getElementById("pmUrl").value.trim();
    var label     = document.getElementById("pmLabel").value.trim();
    var interval  = parseInt(document.getElementById("pmInterval").value, 10) || 60;
    var threshold = parseFloat(document.getElementById("pmThreshold").value) || 50.0;

    if (!url) { showAddError("Please enter a URL or domain."); return; }

    pmAddBtn.disabled    = true;
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
            _cachedTargets = data.targets || [];
            renderWatchlist(_cachedTargets);
            // Refresh overview chart only if we're not already viewing a
            // specific target's history (close button is hidden = overview mode)
            if (pmHistoryClose.style.display === "none") {
                renderOverviewChart(_cachedTargets);
            }
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
            CLEAN:      "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
            UNKNOWN:    "",
        }[t.last_verdict] || "";

        var lastScan = t.last_scanned
            ? t.last_scanned.replace("T", " ").replace("Z", "").slice(0, 16)
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
            "<td class='" + scoreClass + "'>" + (t.last_risk_score || 0).toFixed(1) + "</td>" +
            "<td>" +
                (t.last_verdict
                    ? "<span class='badge " + verdictClass + "'>" +
                      escapeHtml(t.last_verdict) + "</span>"
                    : "—") +
            "</td>" +
            "<td class='pm-actions'>" +
                "<button class='pm-btn pm-btn-scan' data-id='" + t.id +
                "' data-label='" + escapeHtml(t.label) + "'>▶ Scan</button>" +
                "<button class='pm-btn pm-btn-history' data-id='" + t.id +
                "' data-label='" + escapeHtml(t.label) + "'>📈 History</button>" +
                "<button class='pm-btn pm-btn-remove' data-id='" + t.id + "'>✕</button>" +
            "</td>";
        pmWatchBody.appendChild(tr);
    });
}

// Delegated click handlers
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
        // Find this target's index in _cachedTargets so colour matches overview
        var idx = _cachedTargets.findIndex(function (t) {
            return String(t.id) === String(btn.dataset.id);
        });
        loadHistory(btn.dataset.id, btn.dataset.label, idx < 0 ? 0 : idx);
    }
});


// Distinct colour palette — one per watchlist target
var PLOT_COLOURS = [
    "#388bfd", "#3fb950", "#f85149", "#d29922", "#a371f7",
    "#39d353", "#ff7b72", "#ffa657", "#79c0ff", "#f2cc60",
    "#56d364", "#ff6e96", "#b392f0", "#4fc1ff", "#e6c07b",
];

function colourForIndex(i) {
    return PLOT_COLOURS[i % PLOT_COLOURS.length];
}

// ════════════════════════════════════════════════════════════════════════════
// OVERVIEW PLOT — multi-line, one line per target, fetches each target's
// last 10 history points in parallel then plots them all together.
// ════════════════════════════════════════════════════════════════════════════

function renderOverviewChart(targets) {
    var canvas = document.getElementById("pmHistoryChart");

    if (!targets || targets.length === 0) {
        canvas.style.display       = "none";
        pmChartEmpty.style.display = "block";
        document.getElementById("pmHistoryStats").style.display = "none";
        pmHistoryTitle.textContent   = "Risk Score — All Targets";
        pmHistoryClose.style.display = "none";
        return;
    }

    canvas.style.display       = "block";
    pmChartEmpty.style.display = "none";
    document.getElementById("pmHistoryStats").style.display = "flex";
    pmHistoryTitle.textContent   = "Risk Score — All Targets";
    pmHistoryClose.style.display = "none";

    // ── Stats (from cached target snapshots, no extra fetch needed) ─────────
    var scores  = targets.map(function (t) { return t.last_risk_score || 0; });
    var total   = targets.length;
    var avg     = (scores.reduce(function (a, b) { return a + b; }, 0) / total).toFixed(1);
    var alerts  = targets.filter(function (t) {
        return (t.last_risk_score || 0) >= t.alert_threshold;
    }).length;
    var peak    = Math.max.apply(null, scores).toFixed(1);

    document.getElementById("pmHistTotal").textContent  = total;
    document.getElementById("pmHistAvg").textContent    = avg;
    document.getElementById("pmHistAlerts").textContent = alerts;
    document.getElementById("pmHistVerdict").textContent = peak;

    // ── Fetch history for every target in parallel ───────────────────────────
    var fetches = targets.map(function (t) {
        return fetch(HISTORY_URL + "/" + t.id + "/history?limit=10")
            .then(function (r) { return r.json(); })
            .catch(function () { return { status: "error", history: [] }; });
    });

    Promise.all(fetches).then(function (results) {
        // Build a unified sorted label set (HH:MM timestamps)
        var labelSet = {};
        results.forEach(function (res) {
            (res.history || []).forEach(function (h) {
                var ts = (h.scanned_at || "").slice(0, 16).replace("T", " ");
                if (ts) { labelSet[ts] = true; }
            });
        });
        var allLabels = Object.keys(labelSet).sort();

        // Trim to last 15 ticks max to keep chart readable
        if (allLabels.length > 15) {
            allLabels = allLabels.slice(allLabels.length - 15);
        }

        // Build one dataset per target
        var datasets = targets.map(function (t, i) {
            var colour  = colourForIndex(i);
            var histMap = {};
            var res     = results[i];
            (res.history || []).forEach(function (h) {
                var ts = (h.scanned_at || "").slice(0, 16).replace("T", " ");
                histMap[ts] = h.risk_score || 0;
            });

            var data = allLabels.map(function (ts) {
                return histMap.hasOwnProperty(ts) ? histMap[ts] : null;
            });

            var shortLabel = (t.label || t.domain || "—");
            if (shortLabel.length > 20) { shortLabel = shortLabel.slice(0, 18) + "…"; }

            return {
                label:                shortLabel,
                data:                 data,
                borderColor:          colour,
                backgroundColor:      colour + "22",   // 13% opacity fill
                pointBackgroundColor: colour,
                pointRadius:          4,
                pointHoverRadius:     6,
                tension:              0.35,
                fill:                 false,
                spanGaps:             true,             // connect across nulls
            };
        });

        var ctx = canvas.getContext("2d");
        if (_historyChart) { _historyChart.destroy(); }

        _historyChart = new Chart(ctx, {
            type: "line",
            data: {
                labels:   allLabels.map(function (l) { return l.slice(11, 16); }),
                datasets: datasets,
            },
            options: {
                responsive:          true,
                maintainAspectRatio: true,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        display:  true,
                        position: "bottom",
                        labels: {
                            color:    "#8b949e",
                            boxWidth: 12,
                            padding:  10,
                            font:     { size: 11 },
                        },
                    },
                    tooltip: { mode: "index", intersect: false },
                },
                scales: {
                    y: {
                        min: 0, max: 100,
                        ticks: { color: "#8b949e", font: { size: 11 } },
                        grid:  { color: "#21262d" },
                        title: {
                            display: true, text: "Risk Score",
                            color: "#8b949e", font: { size: 11 },
                        },
                    },
                    x: {
                        ticks: { color: "#8b949e", font: { size: 11 } },
                        grid:  { color: "#21262d" },
                    },
                },
            },
        });
    });
}


// ════════════════════════════════════════════════════════════════════════════
// PER-TARGET HISTORY CHART — switched to when "📈 History" is clicked
// ════════════════════════════════════════════════════════════════════════════

function loadHistory(targetId, label, targetIndex) {
    fetch(HISTORY_URL + "/" + targetId + "/history?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistoryChart(data.history || [], label, targetIndex);
        })
        .catch(function () {/* silent */});
}

function renderHistoryChart(history, label, targetIndex) {
    var canvas = document.getElementById("pmHistoryChart");
    canvas.style.display       = "block";
    pmChartEmpty.style.display = "none";
    document.getElementById("pmHistoryStats").style.display = "flex";

    pmHistoryClose.style.display = "inline-flex";
    pmHistoryTitle.textContent   = "Risk Score History — " + label;

    // Use the same colour this target has in the overview chart
    var colour = colourForIndex(typeof targetIndex === "number" ? targetIndex : 0);

    var reversed = history.slice().reverse();
    var labels   = reversed.map(function (h) {
        return (h.scanned_at || "").slice(11, 16);
    });
    var scores = reversed.map(function (h) { return h.risk_score || 0; });

    var total   = history.length;
    var avg     = total
        ? (scores.reduce(function (a, b) { return a + b; }, 0) / total).toFixed(1)
        : "—";
    var alerts  = history.filter(function (h) { return h.alert_fired; }).length;
    var verdict = history[0] ? history[0].verdict : "—";

    document.getElementById("pmHistTotal").textContent  = total;
    document.getElementById("pmHistAvg").textContent    = avg;
    document.getElementById("pmHistAlerts").textContent = alerts;
    document.getElementById("pmHistVerdict").textContent = verdict;

    var ctx = canvas.getContext("2d");
    if (_historyChart) { _historyChart.destroy(); }

    _historyChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label:           label,
                data:            scores,
                borderColor:     colour,
                backgroundColor: colour + "22",
                pointBackgroundColor: scores.map(function (s) {
                    if (s >= 70) { return "#f85149"; }
                    if (s >= 35) { return "#d29922"; }
                    return "#3fb950";
                }),
                pointRadius:      5,
                pointHoverRadius: 7,
                tension:          0.35,
                fill:             true,
            }],
        },
        options: {
            responsive:          true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: { mode: "index", intersect: false },
            },
            scales: {
                y: {
                    min: 0, max: 100,
                    ticks: { color: "#8b949e", font: { size: 11 } },
                    grid:  { color: "#21262d" },
                },
                x: {
                    ticks: { color: "#8b949e", font: { size: 11 } },
                    grid:  { color: "#21262d" },
                },
            },
        },
    });
}

// "← Overview" button — restore overview chart
pmHistoryClose.addEventListener("click", function () {
    pmHistoryClose.style.display = "none";
    renderOverviewChart(_cachedTargets);
});


// ════════════════════════════════════════════════════════════════════════════
// UNIFIED FEED — compact, limit 10, scrollable
// ════════════════════════════════════════════════════════════════════════════

function loadFeed() {
    // Request 10 items instead of 50
    fetch(FEED_URL + "?limit=10")
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
        pmFeedMeta.textContent = "";
        return;
    }

    pmFeedMeta.textContent = "showing " + feed.length + " most recent";

    feed.forEach(function (item) {
        var verdictClass = verdictBadgeClass(item.verdict);
        var scoreClass   = "";
        if (item.risk_score >= 70)      { scoreClass = "att-cell-red"; }
        else if (item.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var ts = (item.scanned_at || "").replace("T", " ").replace("Z", "").slice(0, 16);

        // Truncate long ref strings to keep rows compact
        var ref = item.ref || "—";
        if (ref.length > 42) { ref = ref.slice(0, 40) + "…"; }

        var tr = document.createElement("tr");
        tr.style.lineHeight = "1.3";   // compact row height
        tr.innerHTML =
            "<td class='pm-module' style='white-space:nowrap'>" +
                item.icon + " " + escapeHtml(item.module) +
            "</td>" +
            "<td class='pm-ref' style='max-width:220px;overflow:hidden;" +
                "text-overflow:ellipsis;white-space:nowrap' title='" +
                escapeHtml(item.ref || "") + "'>" +
                escapeHtml(ref) +
            "</td>" +
            "<td class='" + scoreClass + "'>" +
                (item.risk_score || 0).toFixed(1) +
            "</td>" +
            "<td><span class='badge " + verdictClass + "' style='font-size:10px;padding:2px 6px'>" +
                escapeHtml(item.verdict || "—") +
            "</span></td>" +
            "<td class='att-ts' style='white-space:nowrap'>" + ts + "</td>";
        pmFeedBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// POLLING
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
                    .map(function (a) {
                        return a.label + " (" + a.risk_score.toFixed(1) + ")";
                    })
                    .join(", ");
                showAlert(data.alert_count + " alert(s) fired: " + names);
            }
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// ALERT BANNER
// ════════════════════════════════════════════════════════════════════════════

function showAlert(msg) {
    pmAlertText.textContent     = msg;
    pmAlertBanner.style.display = "flex";
}

document.getElementById("pmAlertClose").addEventListener("click", function () {
    pmAlertBanner.style.display = "none";
});


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function verdictBadgeClass(verdict) {
    return ({
        CLEAN:     "badge-safe",
        SAFE:      "badge-safe",
        SUSPICIOUS:"badge-suspicious",
        MALICIOUS: "badge-malicious",
        LOW:       "badge-safe",
        MEDIUM:    "badge-suspicious",
        HIGH:      "badge-malicious",
        CRITICAL:  "badge-malicious",
    })[verdict] || "";
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

// Draw empty-state chart immediately so the card isn't blank on load
renderOverviewChart([]);

// Then load real data
loadWatchlist();
loadFeed();
pollDueTargets();

_watchTimer = setInterval(loadWatchlist,    10000);
_feedTimer  = setInterval(loadFeed,         10000);
_pollTimer  = setInterval(pollDueTargets,   30000);