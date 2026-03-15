"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd          = document.getElementById("page-data");
var AGG_URL      = _pd.dataset.aggregateUrl;
var HISTORY_URL  = _pd.dataset.historyUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var aggBtn       = document.getElementById("rsAggBtn");
var aggBtnText   = document.getElementById("rsAggBtnText");
var aggSpinner   = document.getElementById("rsAggSpinner");
var rsError      = document.getElementById("rsError");
var resultsPanel = document.getElementById("rsResultsPanel");
var historyBody  = document.getElementById("rsHistoryBody");

// Phase icon map
var PHASE_ICONS = {
    email:      "✉",
    url:        "🔗",
    network:    "🌐",
    attachment: "📎",
    ai:         "🤖",
    image:      "🖼",
};


// ════════════════════════════════════════════════════════════════════════════
// FORM SUBMISSION
// ════════════════════════════════════════════════════════════════════════════

aggBtn.addEventListener("click", function () {
    var payload = buildPayload();
    if (!payload) {
        showError("Enter at least one scan ID.");
        return;
    }
    hideError();
    setLoading(true);
    resultsPanel.style.display = "none";

    fetch(AGG_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body:    JSON.stringify(payload),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        setLoading(false);
        if (data.status === "error") {
            showError(data.message || "Aggregation failed.");
            return;
        }
        renderResults(data);
        resultsPanel.style.display = "block";
        resultsPanel.scrollIntoView({ behavior: "smooth" });
        loadHistory();
    })
    .catch(function (err) {
        setLoading(false);
        showError("Request failed: " + err.message);
    });
});

function buildPayload() {
    var fields = {
        email_scan_id:   document.getElementById("rsEmailId").value,
        url_scan_id:     document.getElementById("rsUrlId").value,
        network_scan_id: document.getElementById("rsNetworkId").value,
        attachment_id:   document.getElementById("rsAttachId").value,
        ai_detection_id: document.getElementById("rsAiId").value,
        image_scan_id:   document.getElementById("rsImageId").value,
    };
    var payload = {};
    var hasAny  = false;
    Object.keys(fields).forEach(function (k) {
        var v = parseInt(fields[k], 10);
        if (!isNaN(v) && v > 0) {
            payload[k] = v;
            hasAny = true;
        }
    });
    return hasAny ? payload : null;
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var mod = (data.module_results || {}).risk_aggregator || {};
    renderGauge(mod, data);
    renderVerdict(mod, data);
    renderBreakdown(mod);
}

// ── Gauge ──
function renderGauge(mod, data) {
    var score    = mod.final_score || 0;
    var phases   = mod.phases_used || [];

    document.getElementById("rsGaugeValue").textContent = score.toFixed(1);

    // SVG arc — total arc length ~283 for a 180° semicircle
    var arcLen  = 283;
    var offset  = arcLen - (score / 100) * arcLen;
    var arc     = document.getElementById("rsGaugeArc");
    arc.setAttribute("stroke-dashoffset", offset.toFixed(1));

    var color = "#3fb950";
    if (score >= 70)      { color = "#f85149"; }
    else if (score >= 35) { color = "#d29922"; }
    arc.setAttribute("stroke", color);

    // Phase pills
    var phasesEl = document.getElementById("rsGaugePhases");
    phasesEl.innerHTML = "";
    phases.forEach(function (p) {
        var span = document.createElement("span");
        span.className   = "rs-phase-pill";
        span.textContent = (PHASE_ICONS[p] || "•") + " " + p;
        phasesEl.appendChild(span);
    });
}

// ── Verdict ──
function renderVerdict(mod, data) {
    var verdict = mod.verdict || "UNKNOWN";
    var badge   = document.getElementById("rsVerdictBadge");
    badge.textContent = verdict;
    badge.className   = "ai-verdict-badge ai-verdict-" +
        verdict.toLowerCase().replace("_", "-");

    document.getElementById("rsVerdictScore").textContent =
        "Final score: " + (mod.final_score || 0).toFixed(2) + " / 100";

    var actionMap = {
        ALLOW: "✅ Allow",
        WARN:  "⚠ Review carefully",
        BLOCK: "🚫 Block",
    };
    document.getElementById("rsVerdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");

    document.getElementById("rsExplanation").textContent =
        data.explanation || mod.explanation || "";
}

// ── Per-phase breakdown ──
function renderBreakdown(mod) {
    var breakdown = mod.breakdown || {};
    var container = document.getElementById("rsBreakdown");
    container.innerHTML = "";

    var phases = Object.keys(breakdown);
    if (phases.length === 0) {
        container.innerHTML = '<p class="att-empty-note">No breakdown available.</p>';
        return;
    }

    phases.forEach(function (phase) {
        var data     = breakdown[phase];
        var raw      = data.raw      || 0;
        var weighted = data.weighted || 0;
        var pct      = data.pct_of_total || 0;

        var barColor = "#3fb950";
        if (raw >= 70)      { barColor = "#f85149"; }
        else if (raw >= 35) { barColor = "#d29922"; }

        var row = document.createElement("div");
        row.className = "rs-breakdown-row";
        row.innerHTML =
            "<div class='rs-bd-label'>" +
                "<span class='rs-bd-icon'>" + (PHASE_ICONS[phase] || "•") + "</span>" +
                "<span class='rs-bd-name'>" + phase.charAt(0).toUpperCase() +
                    phase.slice(1) + "</span>" +
                "<span class='rs-bd-scanid'>ID: " + (data.scan_id || "—") + "</span>" +
            "</div>" +
            "<div class='rs-bd-bar-wrap'>" +
                "<div class='rs-bd-bar-bg'>" +
                    "<div class='rs-bd-bar-fill' style='width:" +
                        raw.toFixed(1) + "%; background:" + barColor + "'></div>" +
                "</div>" +
                "<span class='rs-bd-raw'>" + raw.toFixed(1) + "</span>" +
            "</div>" +
            "<div class='rs-bd-meta'>" +
                "<span class='rs-bd-weight'>Weight: " +
                    (data.norm_weight * 100).toFixed(1) + "%</span>" +
                "<span class='rs-bd-weighted'>Contribution: " +
                    weighted.toFixed(2) + "</span>" +
            "</div>";
        container.appendChild(row);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistory(data.records || []);
        })
        .catch(function () {/* silent */});
}

function renderHistory(records) {
    historyBody.innerHTML = "";
    if (records.length === 0) {
        historyBody.innerHTML =
            '<tr><td colspan="11" class="att-empty-row">No aggregations yet.</td></tr>';
        return;
    }

    records.forEach(function (r) {
        var verdictClass = {
            CLEAN:     "badge-safe",
            SUSPICIOUS:"badge-suspicious",
            MALICIOUS: "badge-malicious",
        }[r.verdict] || "";

        var scoreClass = "";
        if (r.final_score >= 70)      { scoreClass = "att-cell-red"; }
        else if (r.final_score >= 35) { scoreClass = "att-cell-amber"; }

        var phases = (r.phases_used || []).map(function (p) {
            return PHASE_ICONS[p] || p;
        }).join(" ");

        var ts = (r.created_at || "").replace("T"," ").replace("Z","").slice(0,16);

        var fmtScore = function (v) {
            return v !== null && v !== undefined ? v.toFixed(1) : "—";
        };

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + r.id + "</td>" +
            "<td class='rs-phases-cell'>" + phases + "</td>" +
            "<td>" + fmtScore(r.email_score)      + "</td>" +
            "<td>" + fmtScore(r.url_score)         + "</td>" +
            "<td>" + fmtScore(r.network_score)     + "</td>" +
            "<td>" + fmtScore(r.attachment_score)  + "</td>" +
            "<td>" + fmtScore(r.ai_score)          + "</td>" +
            "<td>" + fmtScore(r.image_score)       + "</td>" +
            "<td class='" + scoreClass + "'>" +
                (r.final_score || 0).toFixed(1) +
            "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                (r.verdict || "—") +
            "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function setLoading(on) {
    aggBtn.disabled         = on;
    aggBtnText.style.display= on ? "none"   : "inline";
    aggSpinner.style.display= on ? "inline" : "none";
}

function showError(msg) {
    rsError.textContent   = "⚠ " + msg;
    rsError.style.display = "block";
}
function hideError() {
    rsError.style.display = "none";
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
setInterval(loadHistory, 5000);