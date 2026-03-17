"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd         = document.getElementById("page-data");
var AGG_URL     = _pd.dataset.aggregateUrl;
var AUTO_URL    = _pd.dataset.autoUrl;
var STATUS_URL  = _pd.dataset.statusUrl;
var HISTORY_URL = _pd.dataset.historyUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var aggBtn       = document.getElementById("rsAggBtn");
var aggBtnText   = document.getElementById("rsAggBtnText");
var aggSpinner   = document.getElementById("rsAggSpinner");
var rsError      = document.getElementById("rsError");
var resultsPanel = document.getElementById("rsResultsPanel");
var historyBody  = document.getElementById("rsHistoryBody");
var rsManualPanel = document.getElementById("rsManualPanel");
var rsAutoPanel   = document.getElementById("rsAutoPanel");
var rsStatusGrid  = document.getElementById("rsStatusGrid");
var rsModeBadge   = document.getElementById("rsModeBadge");
var rsCardTitle   = document.getElementById("rsCardTitle");

var PHASE_ICONS = {
    email: "✉", url: "🔗", network: "🌐",
    attachment: "📎", ai: "🤖", image: "🖼",
};
var PHASE_LABELS = {
    email: "Email Scan", url: "URL Scan", network: "Network Scan",
    attachment: "Attachment", ai: "AI Detection", image: "Image Analysis",
};

// Current mode — "manual" | "auto"
var _currentMode   = "manual";
// Cached status from last probe (used when Calculate is clicked in auto mode)
var _cachedStatus  = {};
var _statusTimer   = null;


// ════════════════════════════════════════════════════════════════════════════
// MODE TOGGLE
// ════════════════════════════════════════════════════════════════════════════

document.getElementById("rsBtnManual").addEventListener("click", function () {
    setMode("manual");
});
document.getElementById("rsBtnAuto").addEventListener("click", function () {
    setMode("auto");
});

function setMode(mode) {
    _currentMode = mode;

    // Toggle active pill style
    document.getElementById("rsBtnManual").classList.toggle("rs-mode-active", mode === "manual");
    document.getElementById("rsBtnAuto").classList.toggle("rs-mode-active",   mode === "auto");

    // Show/hide panels
    rsManualPanel.style.display = mode === "manual" ? "block" : "none";
    rsAutoPanel.style.display   = mode === "auto"   ? "block" : "none";

    rsCardTitle.textContent = mode === "manual"
        ? "Enter Scan IDs to Aggregate"
        : "Automatic — Most Recent Scan Per Module";

    aggBtnText.textContent = mode === "manual"
        ? "Calculate Aggregate Score"
        : "Calculate Automatic Score";

    if (mode === "auto") {
        probeStatus();
        // Re-probe every 10 s while auto panel is visible
        if (!_statusTimer) {
            _statusTimer = setInterval(probeStatus, 10000);
        }
    } else {
        if (_statusTimer) { clearInterval(_statusTimer); _statusTimer = null; }
    }
}


// ════════════════════════════════════════════════════════════════════════════
// AUTO MODE — MODULE STATUS PROBE
// ════════════════════════════════════════════════════════════════════════════

function probeStatus() {
    fetch(STATUS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status === "error") { return; }
            _cachedStatus = data.modules || data;
            renderStatusGrid(_cachedStatus);
            var ts = new Date().toLocaleTimeString();
            document.getElementById("rsAutoRefreshNote").textContent =
                "Last probed: " + ts;
        })
        .catch(function () {
            document.getElementById("rsAutoRefreshNote").textContent =
                "Could not reach module status endpoint.";
        });
}

function renderStatusGrid(modules) {
    rsStatusGrid.innerHTML = "";

    var phaseOrder = ["email", "url", "network", "attachment", "ai", "image"];
    phaseOrder.forEach(function (phase) {
        var info    = modules[phase] || { online: false };
        var online  = info.online === true;
        var score   = (info.score !== null && info.score !== undefined)
                        ? info.score.toFixed(1) : "—";

        // Score colour when online
        var scoreColour = "#c9d1d9";
        if (online && info.score !== null) {
            if (info.score >= 70)      { scoreColour = "#f85149"; }
            else if (info.score >= 35) { scoreColour = "#d29922"; }
            else                       { scoreColour = "#3fb950"; }
        }

        // Truncate long refs
        var ref = (info.ref || "—");
        if (ref.length > 28) { ref = ref.slice(0, 26) + "…"; }

        var ts = "";
        if (info.scanned_at) {
            ts = info.scanned_at.replace("T", " ").replace("Z", "").slice(0, 16);
        }

        var tile = document.createElement("div");
        tile.className = "rs-status-tile " + (online ? "tile-online" : "tile-offline");
        tile.innerHTML =
            "<div class='rs-tile-header'>" +
                "<span class='rs-tile-dot'></span>" +
                PHASE_ICONS[phase] + " " + PHASE_LABELS[phase] +
            "</div>" +
            "<div class='rs-tile-score' style='color:" + scoreColour + "'>" +
                (online ? score : "—") +
            "</div>" +
            "<div class='rs-tile-meta'>" +
                (online
                    ? "ID " + info.scan_id + " · " + ref
                    : "No scans recorded") +
            "</div>" +
            (ts ? "<div class='rs-tile-meta'>" + ts + "</div>" : "");
        rsStatusGrid.appendChild(tile);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// CALCULATE BUTTON
// ════════════════════════════════════════════════════════════════════════════

aggBtn.addEventListener("click", function () {
    hideError();
    setLoading(true);
    resultsPanel.style.display = "none";

    if (_currentMode === "manual") {
        runManual();
    } else {
        runAuto();
    }
});

// ── Manual ────────────────────────────────────────────────────────────────
function runManual() {
    var payload = buildPayload();
    if (!payload) {
        setLoading(false);
        showError("Enter at least one scan ID.");
        return;
    }
    fetch(AGG_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body:    JSON.stringify(payload),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        setLoading(false);
        if (data.status === "error") { showError(data.message || "Aggregation failed."); return; }
        renderResults(data, "manual");
        loadHistory();
    })
    .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
}

// ── Auto ──────────────────────────────────────────────────────────────────
function runAuto() {
    // Check at least one module is online
    var anyOnline = Object.values(_cachedStatus).some(function (m) { return m.online; });
    if (!anyOnline) {
        setLoading(false);
        showError("No module data available yet. Run at least one scan first.");
        return;
    }
    fetch(AUTO_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body:    JSON.stringify({}),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        setLoading(false);
        if (data.status === "error") { showError(data.message || "Auto aggregation failed."); return; }
        renderResults(data, "auto");
        loadHistory();
    })
    .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
}

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
        if (!isNaN(v) && v > 0) { payload[k] = v; hasAny = true; }
    });
    return hasAny ? payload : null;
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data, mode) {
    var mod = (data.module_results || {}).risk_aggregator || data;

    // Mode badge
    rsModeBadge.textContent = (mode === "auto" ? "AUTOMATIC" : "MANUAL") + " MODE";
    rsModeBadge.className   = "rs-mode-result-badge " +
        (mode === "auto" ? "badge-auto" : "badge-manual");

    renderGauge(mod);
    renderVerdict(mod, data);
    renderBreakdown(mod, mode);

    resultsPanel.style.display = "block";
    resultsPanel.scrollIntoView({ behavior: "smooth" });
}

function renderGauge(mod) {
    var score  = mod.final_score || 0;
    var phases = mod.phases_used || [];

    document.getElementById("rsGaugeValue").textContent = score.toFixed(1);

    var arcLen = 283;
    var arc    = document.getElementById("rsGaugeArc");
    arc.setAttribute("stroke-dashoffset", (arcLen - (score / 100) * arcLen).toFixed(1));

    var color = score >= 70 ? "#f85149" : score >= 35 ? "#d29922" : "#3fb950";
    arc.setAttribute("stroke", color);

    var phasesEl = document.getElementById("rsGaugePhases");
    phasesEl.innerHTML = "";
    phases.forEach(function (p) {
        var span = document.createElement("span");
        span.className   = "rs-phase-pill";
        span.textContent = (PHASE_ICONS[p] || "•") + " " + p;
        phasesEl.appendChild(span);
    });
}

function renderVerdict(mod, data) {
    var verdict = mod.verdict || "UNKNOWN";
    var badge   = document.getElementById("rsVerdictBadge");
    badge.textContent = verdict;
    badge.className   = "ai-verdict-badge ai-verdict-" +
        verdict.toLowerCase().replace("_", "-");

    document.getElementById("rsVerdictScore").textContent =
        "Final score: " + (mod.final_score || 0).toFixed(2) + " / 100";

    var actionMap = { ALLOW: "✅ Allow", WARN: "⚠ Review carefully", BLOCK: "🚫 Block" };
    document.getElementById("rsVerdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action ||
                      actionMap[mod.action] || mod.action || "—");

    document.getElementById("rsExplanation").textContent =
        data.explanation || mod.explanation || "";
}

function renderBreakdown(mod, mode) {
    var breakdown = mod.breakdown || {};
    var container = document.getElementById("rsBreakdown");
    container.innerHTML = "";

    // In auto mode, show ALL six phases — offline ones greyed out
    var allPhases    = ["email", "url", "network", "attachment", "ai", "image"];
    var phasesToShow = mode === "auto" ? allPhases : Object.keys(breakdown);

    if (phasesToShow.length === 0) {
        container.innerHTML = '<p class="att-empty-note">No breakdown available.</p>';
        return;
    }

    phasesToShow.forEach(function (phase) {
        var data    = breakdown[phase];
        var isUsed  = !!data;

        var raw      = isUsed ? (data.raw      || 0) : null;
        var weighted = isUsed ? (data.weighted || 0) : null;
        var scanId   = isUsed ? data.scan_id          : null;

        var barColor = "#3fb950";
        if (raw !== null) {
            if (raw >= 70)      { barColor = "#f85149"; }
            else if (raw >= 35) { barColor = "#d29922"; }
        }

        var row = document.createElement("div");
        row.className = "rs-breakdown-row" + (isUsed ? "" : " rs-bd-offline");

        // Offline row styling — muted, dashed border
        if (!isUsed) {
            row.style.cssText = "opacity:.45;filter:grayscale(.6)";
        }

        row.innerHTML =
            "<div class='rs-bd-label'>" +
                "<span class='rs-bd-icon'>" + (PHASE_ICONS[phase] || "•") + "</span>" +
                "<span class='rs-bd-name'>" +
                    phase.charAt(0).toUpperCase() + phase.slice(1) +
                "</span>" +
                (isUsed
                    ? "<span class='rs-bd-scanid'>ID: " + (scanId || "—") + "</span>"
                    : "<span class='rs-bd-offline-label' style='" +
                      "font-size:10px;color:#484f58;margin-left:6px'" +
                      ">● not used</span>") +
            "</div>" +
            "<div class='rs-bd-bar-wrap'>" +
                "<div class='rs-bd-bar-bg'>" +
                    (isUsed
                        ? "<div class='rs-bd-bar-fill' style='width:" +
                          raw.toFixed(1) + "%;background:" + barColor + "'></div>"
                        : "<div style='width:0%'></div>") +
                "</div>" +
                "<span class='rs-bd-raw'>" +
                    (isUsed ? raw.toFixed(1) : "—") +
                "</span>" +
            "</div>" +
            "<div class='rs-bd-meta'>" +
                (isUsed
                    ? "<span class='rs-bd-weight'>Weight: " +
                      (data.norm_weight * 100).toFixed(1) + "%</span>" +
                      "<span class='rs-bd-weighted'>Contribution: " +
                      weighted.toFixed(2) + "</span>"
                    : "<span style='color:#484f58;font-size:11px'>No scan data</span>") +
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
        .catch(function () {});
}

function renderHistory(records) {
    historyBody.innerHTML = "";
    if (records.length === 0) {
        historyBody.innerHTML =
            '<tr><td colspan="12" class="att-empty-row">No aggregations yet.</td></tr>';
        return;
    }

    records.forEach(function (r) {
        var verdictClass = {
            CLEAN: "badge-safe", SUSPICIOUS: "badge-suspicious",
            MALICIOUS: "badge-malicious",
        }[r.verdict] || "";

        var scoreClass = r.final_score >= 70 ? "att-cell-red"
                       : r.final_score >= 35 ? "att-cell-amber" : "";

        var phases = (r.phases_used || []).map(function (p) {
            return PHASE_ICONS[p] || p;
        }).join(" ");

        var ts = (r.created_at || "").replace("T", " ").replace("Z", "").slice(0, 16);

        var fmt = function (v) {
            return (v !== null && v !== undefined) ? v.toFixed(1) : "—";
        };

        // Mode badge for history row
        var modeCell = r.mode === "auto"
            ? "<span style='font-size:10px;color:#3fb950;font-weight:600'>AUTO</span>"
            : "<span style='font-size:10px;color:#79c0ff;font-weight:600'>MANUAL</span>";

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + r.id + "</td>" +
            "<td>" + modeCell + "</td>" +
            "<td class='rs-phases-cell'>" + phases + "</td>" +
            "<td>" + fmt(r.email_score)      + "</td>" +
            "<td>" + fmt(r.url_score)         + "</td>" +
            "<td>" + fmt(r.network_score)     + "</td>" +
            "<td>" + fmt(r.attachment_score)  + "</td>" +
            "<td>" + fmt(r.ai_score)          + "</td>" +
            "<td>" + fmt(r.image_score)       + "</td>" +
            "<td class='" + scoreClass + "'>" + (r.final_score || 0).toFixed(1) + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" + (r.verdict || "—") + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function setLoading(on) {
    aggBtn.disabled          = on;
    aggBtnText.style.display = on ? "none"   : "inline";
    aggSpinner.style.display = on ? "inline" : "none";
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