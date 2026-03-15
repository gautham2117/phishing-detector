"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd         = document.getElementById("page-data");
var SCAN_URL    = _pd.dataset.scanUrl;
var HISTORY_URL = _pd.dataset.historyUrl;
var STATUS_URL  = _pd.dataset.statusUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var extStatusDot   = document.getElementById("extStatusDot");
var extStatusLabel = document.getElementById("extStatusLabel");
var extScanBtn     = document.getElementById("extScanBtn");
var extScanInput   = document.getElementById("extScanInput");
var extScanError   = document.getElementById("extScanError");
var extResultPanel = document.getElementById("extResultPanel");
var extHistBody    = document.getElementById("extHistBody");
var extHistCount   = document.getElementById("extHistCount");

var _pollTimer = null;


// ════════════════════════════════════════════════════════════════════════════
// BACKEND STATUS
// ════════════════════════════════════════════════════════════════════════════

function checkStatus() {
    fetch(STATUS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status === "online" || data.status === "success") {
                extStatusDot.className   = "ext-status-dot ext-dot-online";
                extStatusLabel.textContent = "Backend online — extension scanning active";
                extStatusLabel.style.color = "var(--green)";
            } else {
                setOffline();
            }
        })
        .catch(function () { setOffline(); });
}

function setOffline() {
    extStatusDot.className     = "ext-status-dot ext-dot-offline";
    extStatusLabel.textContent = "Backend offline — start FastAPI on port 8001";
    extStatusLabel.style.color = "var(--red)";
}


// ════════════════════════════════════════════════════════════════════════════
// MANUAL SCAN
// ════════════════════════════════════════════════════════════════════════════

extScanBtn.addEventListener("click", function () {
    var url = extScanInput.value.trim();
    if (!url) {
        showError("Please enter a URL.");
        return;
    }
    if (!url.startsWith("http")) {
        url = "https://" + url;
        extScanInput.value = url;
    }

    hideError();
    extScanBtn.disabled    = true;
    extScanBtn.textContent = "⏳ Scanning…";
    extResultPanel.style.display = "none";

    fetch(SCAN_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body:    JSON.stringify({url: url}),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        extScanBtn.disabled    = false;
        extScanBtn.textContent = "Scan URL";
        if (data.status !== "success") {
            showError(data.message || "Scan failed.");
            return;
        }
        renderInlineResult(data);
        extResultPanel.style.display = "block";
        loadHistory();
    })
    .catch(function (err) {
        extScanBtn.disabled    = false;
        extScanBtn.textContent = "Scan URL";
        showError("Request failed: " + err.message);
    });
});

function renderInlineResult(data) {
    var label    = data.label    || "SAFE";
    var score    = data.risk_score || 0;
    var labelLow = label.toLowerCase();

    var badge = document.getElementById("extResultBadge");
    badge.textContent = label;
    badge.className   = "ext-result-badge ext-badge-" + labelLow;

    document.getElementById("extResultScore").textContent =
        "Risk: " + score.toFixed(1) + " / 100";

    var actionMap = {
        ALLOW:      "✅ Allow",
        WARN:       "⚠ Review carefully",
        QUARANTINE: "🔒 Quarantine",
        BLOCK:      "🚫 Block",
    };
    var actionEl = document.getElementById("extResultAction");
    actionEl.textContent = actionMap[data.recommended_action] || data.recommended_action || "—";

    var bar = document.getElementById("extResultBar");
    bar.style.width = Math.min(score, 100) + "%";
    bar.className   = "ext-result-bar-fill ext-bar-" + labelLow;

    document.getElementById("extResultSummary").textContent =
        data.threat_summary || "No threat information available.";

    var details = data.details || {};
    var detailParts = [];
    if (details.domain)     { detailParts.push("Domain: " + details.domain); }
    if (details.ssl_valid !== undefined) {
        detailParts.push("SSL: " + (details.ssl_valid ? "Valid" : "Invalid"));
    }
    if (details.domain_age !== null && details.domain_age !== undefined) {
        detailParts.push("Domain age: " + details.domain_age + " days");
    }
    if (details.flags && details.flags.length) {
        detailParts.push("Flags: " + details.flags.join(", "));
    }
    document.getElementById("extResultDetails").textContent =
        detailParts.join(" · ") || "";
}


// ════════════════════════════════════════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=50")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistory(data.scans || []);
        })
        .catch(function () {/* silent */});
}

function renderHistory(scans) {
    extHistCount.textContent = scans.length;
    extHistBody.innerHTML    = "";

    if (scans.length === 0) {
        extHistBody.innerHTML =
            '<tr><td colspan="8" class="att-empty-row">' +
            'No scans yet — browse with the extension installed.</td></tr>';
        return;
    }

    scans.forEach(function (s) {
        var verdictClass = {
            SAFE:       "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
        }[s.label] || "";

        var scoreClass = "";
        if (s.risk_score >= 70)      { scoreClass = "att-cell-red";   }
        else if (s.risk_score >= 35) { scoreClass = "att-cell-amber"; }

        var summary = (s.threat_summary || "").slice(0, 80);
        if (s.threat_summary && s.threat_summary.length > 80) {
            summary += "…";
        }
        var ts = (s.scanned_at || "").replace("T"," ").replace("Z","").slice(0,16);
        var sourceIcon = s.source === "extension" ? "🧩" : "🖥";

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>" +
            "<td class='ext-domain-cell'>" + escapeHtml(s.domain || s.url) + "</td>" +
            "<td class='" + scoreClass + "'>" + (s.risk_score || 0).toFixed(1) + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                escapeHtml(s.label) + "</span></td>" +
            "<td class='ext-summary-cell'>" + escapeHtml(summary) + "</td>" +
            "<td>" + escapeHtml(s.recommended_action || "—") + "</td>" +
            "<td>" + sourceIcon + " " + escapeHtml(s.source || "—") + "</td>" +
            "<td class='att-ts'>" + ts + "</td>";
        extHistBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function showError(msg) {
    extScanError.textContent   = "⚠ " + msg;
    extScanError.style.display = "block";
}
function hideError() {
    extScanError.style.display = "none";
}
function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

checkStatus();
loadHistory();
_pollTimer = setInterval(function () {
    checkStatus();
    loadHistory();
}, 5000);