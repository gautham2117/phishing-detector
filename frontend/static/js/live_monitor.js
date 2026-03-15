"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd        = document.getElementById("page-data");
var FEED_URL   = _pd.dataset.feedUrl;
var STATS_URL  = _pd.dataset.statsUrl;
var ALERTS_URL = _pd.dataset.alertsUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var lmFeedBody    = document.getElementById("lmFeedBody");
var lmFeedCount   = document.getElementById("lmFeedCount");
var lmAlertBanner = document.getElementById("lmAlertBanner");
var lmAlertText   = document.getElementById("lmAlertText");
var lmLastUpdate  = document.getElementById("lmLastUpdate");
var thresholdSlider = document.getElementById("lmThresholdSlider");
var thresholdVal    = document.getElementById("lmThresholdVal");

var _threshold    = 70;
var _knownIds     = {};   // module+id → true — tracks seen entries for flash effect
var _pollTimer    = null;


// ════════════════════════════════════════════════════════════════════════════
// THRESHOLD SLIDER
// ════════════════════════════════════════════════════════════════════════════

thresholdSlider.addEventListener("input", function () {
    _threshold             = parseInt(this.value, 10);
    thresholdVal.textContent = _threshold;
});


// ════════════════════════════════════════════════════════════════════════════
// STATS
// ════════════════════════════════════════════════════════════════════════════

function loadStats() {
    fetch(STATS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            var s = data.stats || {};
            document.getElementById("statTotal").textContent     =
                (s.total      || 0).toLocaleString();
            document.getElementById("statMalicious").textContent =
                (s.malicious  || 0).toLocaleString();
            document.getElementById("statSuspicious").textContent=
                (s.suspicious || 0).toLocaleString();
            document.getElementById("statSafe").textContent      =
                (s.safe       || 0).toLocaleString();
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// FEED
// ════════════════════════════════════════════════════════════════════════════

function loadFeed() {
    fetch(FEED_URL + "?limit=100")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderFeed(data.feed || []);
            lmLastUpdate.textContent =
                "Last updated: " + new Date().toLocaleTimeString();
        })
        .catch(function () {/* silent */});
}

function renderFeed(feed) {
    lmFeedCount.textContent = feed.length;
    lmFeedBody.innerHTML    = "";

    if (feed.length === 0) {
        lmFeedBody.innerHTML =
            '<tr><td colspan="5" class="att-empty-row">' +
            'No scans recorded yet.</td></tr>';
        return;
    }

    feed.forEach(function (item) {
        var key         = item.module + "-" + item.id;
        var isNew       = !_knownIds[key];
        _knownIds[key]  = true;

        var verdictClass = {
            SAFE:       "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
        }[item.verdict] || "";

        var scoreClass = "";
        if (item.risk_score >= 70)      { scoreClass = "att-cell-red"; }
        else if (item.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var ts = (item.scanned_at || "")
            .replace("T", " ").replace("Z", "").slice(0, 19);

        var tr = document.createElement("tr");
        if (isNew) { tr.className = "lm-row-new"; }

        tr.innerHTML =
            "<td class='lm-module-cell'>" +
                escapeHtml(item.icon) + " " +
                escapeHtml(item.module) +
            "</td>" +
            "<td class='lm-ref-cell'>" +
                escapeHtml(item.ref || "—") +
            "</td>" +
            "<td class='" + scoreClass + "'>" +
                (item.risk_score || 0).toFixed(1) +
            "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                escapeHtml(item.verdict || "—") +
            "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";

        lmFeedBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// ALERTS
// ════════════════════════════════════════════════════════════════════════════

function loadAlerts() {
    fetch(ALERTS_URL + "?threshold=" + _threshold + "&limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            var count = data.count || 0;
            if (count > 0) {
                var top  = data.alerts[0];
                lmAlertText.textContent =
                    count + " scan(s) above threshold (" + _threshold + ") — " +
                    "Latest: " + escapeHtml(top.module) + " · " +
                    escapeHtml(top.ref) + " · score " +
                    top.risk_score.toFixed(1);
                lmAlertBanner.style.display = "flex";
            } else {
                lmAlertBanner.style.display = "none";
            }
        })
        .catch(function () {/* silent */});
}


// ════════════════════════════════════════════════════════════════════════════
// ALERT CLOSE BUTTON
// ════════════════════════════════════════════════════════════════════════════

document.getElementById("lmAlertClose").addEventListener("click", function () {
    lmAlertBanner.style.display = "none";
});


// ════════════════════════════════════════════════════════════════════════════
// POLL LOOP — every 5 seconds
// ════════════════════════════════════════════════════════════════════════════

function poll() {
    loadStats();
    loadFeed();
    loadAlerts();
}

poll();
_pollTimer = setInterval(poll, 5000);


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}