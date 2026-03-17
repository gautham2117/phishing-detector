"use strict";

var DASHBOARD_URL = "http://127.0.0.1:5000/extension/";

// ════════════════════════════════════════════════════════════════════════════
// GAUGE GEOMETRY  (SVG viewBox="0 0 260 150")
//   Pivot  : CX=130, CY=138
//   Radius : R=100
//   Arc    : 210° (score=0) → clockwise → -30° (score=100)  = 240° sweep
//   SVG clockwise = sweep-flag 1
// ════════════════════════════════════════════════════════════════════════════

var CX        = 130;
var CY        = 138;
var R         = 100;
var ARC_START = 210;
var ARC_SPAN  = 240;

function deg2rad(d) { return d * Math.PI / 180; }

function scoreToXY(score, radius) {
    var ang = deg2rad(ARC_START - (score / 100) * ARC_SPAN);
    return { x: CX + radius * Math.cos(ang), y: CY - radius * Math.sin(ang) };
}

function arcPath(sA, sB, radius) {
    var p1   = scoreToXY(sA, radius);
    var p2   = scoreToXY(sB, radius);
    var span = (sB - sA) / 100 * ARC_SPAN;
    return ["M", p1.x, p1.y, "A", radius, radius, 0, span > 180 ? 1 : 0, 1, p2.x, p2.y].join(" ");
}

function buildTracks() {
    document.getElementById("trackSafe")  .setAttribute("d", arcPath(0,  35,  R));
    document.getElementById("trackWarn")  .setAttribute("d", arcPath(35, 70,  R));
    document.getElementById("trackDanger").setAttribute("d", arcPath(70, 100, R));
}

function buildTicks() {
    var gT = document.getElementById("ticks");
    var gL = document.getElementById("tickLabels");
    [0, 25, 50, 75, 100].forEach(function (v) {
        var outer = scoreToXY(v, R + 4);
        var inner = scoreToXY(v, R - 10);
        var lp    = scoreToXY(v, R - 23);

        var ln = document.createElementNS("http://www.w3.org/2000/svg", "line");
        ln.setAttribute("x1", outer.x); ln.setAttribute("y1", outer.y);
        ln.setAttribute("x2", inner.x); ln.setAttribute("y2", inner.y);
        gT.appendChild(ln);

        var tx = document.createElementNS("http://www.w3.org/2000/svg", "text");
        tx.setAttribute("x", lp.x); tx.setAttribute("y", lp.y);
        tx.textContent = String(v);
        gL.appendChild(tx);
    });
}

// ── Animated needle ───────────────────────────────────────────────────────
var _cur = 0, _tgt = 0, _rafId = null;

function setScore(s) {
    _tgt = Math.max(0, Math.min(100, s));
    if (!_rafId) _animTick();
}

function _animTick() {
    var diff = _tgt - _cur;
    if (Math.abs(diff) < 0.2) { _cur = _tgt; _drawAt(_cur); _rafId = null; return; }
    _cur += diff * 0.11;
    _drawAt(_cur);
    _rafId = requestAnimationFrame(_animTick);
}

function _drawAt(score) {
    var arc = document.getElementById("arcProgress");
    if (score < 0.3) {
        arc.setAttribute("d", "");
    } else {
        arc.setAttribute("d", arcPath(0, score, R));
        arc.setAttribute("stroke", score >= 70 ? "#ff3d3d" : score >= 35 ? "#ffab00" : "#00e676");
    }
    var tip  = scoreToXY(score, R - 10);
    var tail = scoreToXY(score, -16);
    var nd = document.getElementById("needle");
    nd.setAttribute("x1", CX); nd.setAttribute("y1", CY);
    nd.setAttribute("x2", tip.x); nd.setAttribute("y2", tip.y);
    var tl = document.getElementById("needleTail");
    tl.setAttribute("x1", CX); tl.setAttribute("y1", CY);
    tl.setAttribute("x2", tail.x); tl.setAttribute("y2", tail.y);
}


// ════════════════════════════════════════════════════════════════════════════
// DOM REFS
// ════════════════════════════════════════════════════════════════════════════

var pgStatusDot    = document.getElementById("pgStatusDot");
var pgStatusText   = document.getElementById("pgStatusText");
var pgScore        = document.getElementById("pgScore");
var pgVerdict      = document.getElementById("pgVerdict");
var pgUrl          = document.getElementById("pgUrl");
var pgSummary      = document.getElementById("pgSummary");
var pgActionIcon   = document.getElementById("pgActionIcon");
var pgAction       = document.getElementById("pgAction");
var pgScanBtn      = document.getElementById("pgScanBtn");
var pgResetBtn     = document.getElementById("pgResetBtn");
var pgDashBtn      = document.getElementById("pgDashBtn");
var autoScanToggle = document.getElementById("autoScanToggle");
var toggleLbl      = document.getElementById("toggleLbl");
var scanOverlay    = document.getElementById("scanOverlay");
var scanLog        = document.getElementById("scanLog");
var scanProgFill   = document.getElementById("scanProgFill");
var overlayTitle   = document.getElementById("overlayTitle");

var ACTION_CFG = {
    ALLOW:      { icon: "✔", text: "SAFE TO VISIT",                 color: "#00e676" },
    WARN:       { icon: "⚠", text: "REVIEW BEFORE PROCEEDING",     color: "#ffab00" },
    QUARANTINE: { icon: "⛔", text: "DO NOT INTERACT — QUARANTINE",  color: "#ff3d3d" },
    BLOCK:      { icon: "✖", text: "BLOCKED — KNOWN MALICIOUS",    color: "#ff3d3d" },
};


// ════════════════════════════════════════════════════════════════════════════
// SCANNING OVERLAY
// ════════════════════════════════════════════════════════════════════════════

var _logTimer     = null;
var _pollTimer    = null;
var _scanActive   = false;
var _scanStartUrl = "";

var LOG_LINES = [
    "RESOLVING DNS...",
    "FETCHING SSL CERTIFICATE...",
    "CHECKING DOMAIN AGE...",
    "RUNNING URL CLASSIFIER...",
    "SCANNING FOR REDIRECTS...",
    "QUERYING THREAT FEEDS...",
    "RUNNING ML MODELS...",
    "COMPUTING RISK SCORE...",
    "FINALIZING REPORT...",
];

function showOverlay(url) {
    if (_scanActive) return;
    _scanActive   = true;
    _scanStartUrl = url;

    // Reset log
    scanLog.innerHTML = '<div class="log-line">INITIALIZING MODULES...</div>';

    // Reset progress bar (re-apply animation by removing and re-adding the class)
    scanProgFill.style.transition   = "none";
    scanProgFill.style.width        = "0%";
    scanProgFill.style.background   = "";
    scanProgFill.style.boxShadow    = "";
    scanProgFill.classList.remove("indeterminate");
    // Force reflow so the browser registers the reset before we re-add
    void scanProgFill.offsetWidth;
    scanProgFill.classList.add("indeterminate");

    overlayTitle.textContent = "SCANNING TARGET";
    try {
        var host = new URL(url).hostname;
        overlayTitle.textContent = "SCANNING · " + host.toUpperCase();
    } catch (e) {}

    scanOverlay.classList.add("active");
    pgScanBtn.disabled    = true;
    pgScanBtn.textContent = "⏳ SCANNING...";
    pgResetBtn.disabled   = true;

    var idx = 0;
    _logTimer = setInterval(function () {
        if (idx >= LOG_LINES.length) { clearInterval(_logTimer); return; }
        var div = document.createElement("div");
        div.className   = "log-line";
        div.textContent = LOG_LINES[idx++];
        while (scanLog.children.length >= 3) scanLog.removeChild(scanLog.firstChild);
        scanLog.appendChild(div);
    }, 800);
}

function hideOverlay(success) {
    if (!_scanActive) return;
    _scanActive = false;

    clearInterval(_logTimer);
    clearInterval(_pollTimer);
    _logTimer  = null;
    _pollTimer = null;

    // Snap progress to 100%
    scanProgFill.classList.remove("indeterminate");
    scanProgFill.style.transition = "width .3s ease";
    scanProgFill.style.width      = "100%";

    if (success) {
        scanProgFill.style.background = "#00e676";
        scanProgFill.style.boxShadow  = "0 0 8px #00e676";
        _appendLog("SCAN COMPLETE ✔", "#00e676");
    } else {
        scanProgFill.style.background = "#ff3d3d";
        scanProgFill.style.boxShadow  = "0 0 8px #ff3d3d";
        _appendLog("SCAN FAILED — BACKEND OFFLINE?", "#ff3d3d");
    }

    setTimeout(function () {
        scanOverlay.classList.remove("active");
        pgScanBtn.disabled    = false;
        pgScanBtn.textContent = "⬡ Scan";
        pgResetBtn.disabled   = false;
    }, 700);
}

function _appendLog(text, color) {
    var div = document.createElement("div");
    div.className   = "log-line";
    div.style.color = color || "";
    div.textContent = text;
    while (scanLog.children.length >= 3) scanLog.removeChild(scanLog.firstChild);
    scanLog.appendChild(div);
}


// ════════════════════════════════════════════════════════════════════════════
// STORAGE POLL — called after SCAN_CURRENT_TAB to wait for the result
// Background writes to lastScan when done; we detect it here.
// We stamp a scan_id timestamp before starting so we can tell a new result
// from a stale one that was in storage before we started.
// ════════════════════════════════════════════════════════════════════════════

var _scanRequestTs = 0;   // set at scan start; we only accept results after this

function startPolling() {
    clearInterval(_pollTimer);
    var attempts = 0;
    var maxAttempts = 30;   // 30 × 500ms = 15 seconds

    _pollTimer = setInterval(function () {
        attempts++;

        chrome.storage.local.get(["lastScan"], function (data) {
            if (data && data.lastScan) {
                var r = data.lastScan;
                // Only accept if the result was written AFTER we started this scan
                var resultTs = r.ts || 0;
                if (resultTs >= _scanRequestTs) {
                    clearInterval(_pollTimer);
                    _pollTimer = null;
                    hideOverlay(true);
                    renderResult(r);
                    return;
                }
            }

            if (attempts >= maxAttempts) {
                clearInterval(_pollTimer);
                _pollTimer = null;
                hideOverlay(false);
            }
        });
    }, 500);
}


// ════════════════════════════════════════════════════════════════════════════
// RENDER SCAN RESULT
// ════════════════════════════════════════════════════════════════════════════

function renderResult(result) {
    var score = Number(result.risk_score) || 0;
    var label = (result.label || "SAFE").toUpperCase();

    setScore(score);

    var col = score >= 70 ? "#ff3d3d" : score >= 35 ? "#ffab00" : "#00e676";
    pgScore.textContent = Math.round(score);
    pgScore.style.color = col;

    var vClass = { SAFE: "v-safe", SUSPICIOUS: "v-suspicious", MALICIOUS: "v-malicious" }[label] || "v-unknown";
    pgVerdict.textContent = label;
    pgVerdict.className   = "verdict-pill " + vClass;

    pgUrl.textContent = result.url || "—";

    pgSummary.textContent =
        result.threat_summary || result.explanation || "No threat detail available.";

    var act  = (result.action || result.recommended_action || "ALLOW").toUpperCase();
    var acfg = ACTION_CFG[act] || ACTION_CFG.ALLOW;
    pgActionIcon.textContent = acfg.icon;
    pgAction.textContent     = acfg.text;
    pgAction.style.color     = acfg.color;
}


// ════════════════════════════════════════════════════════════════════════════
// RESET
// ════════════════════════════════════════════════════════════════════════════

function doReset() {
    if (_scanActive) return;   // don't reset mid-scan

    setScore(0);
    pgScore.textContent   = "—";
    pgScore.style.color   = "var(--muted)";
    pgVerdict.textContent = "NO SCAN";
    pgVerdict.className   = "verdict-pill v-unknown";
    pgUrl.textContent     = "awaiting scan target...";
    pgSummary.textContent = "Navigate to a page or click SCAN to begin threat assessment.";
    pgActionIcon.textContent = "◈";
    pgAction.textContent  = "—";
    pgAction.style.color  = "var(--muted)";
    chrome.storage.local.remove("lastScan");

    pgResetBtn.classList.add("confirming");
    pgResetBtn.addEventListener("animationend", function h() {
        pgResetBtn.classList.remove("confirming");
        pgResetBtn.removeEventListener("animationend", h);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// AUTO-SCAN TOGGLE
// ════════════════════════════════════════════════════════════════════════════

function applyToggleUI(enabled) {
    autoScanToggle.checked = enabled;
    toggleLbl.textContent  = enabled ? "ON"  : "OFF";
    toggleLbl.style.color  = enabled ? "#00e676" : "var(--muted)";
}

chrome.storage.local.get(["autoScanEnabled"], function (data) {
    applyToggleUI(data.autoScanEnabled !== false);
});

autoScanToggle.addEventListener("change", function () {
    var enabled = autoScanToggle.checked;
    applyToggleUI(enabled);
    chrome.storage.local.set({ autoScanEnabled: enabled });
    chrome.runtime.sendMessage({ type: "SET_AUTO_SCAN", enabled: enabled });
});


// ════════════════════════════════════════════════════════════════════════════
// BACKEND STATUS
// ════════════════════════════════════════════════════════════════════════════

function checkBackend() {
    chrome.runtime.sendMessage({ type: "PING_BACKEND" }, function (resp) {
        if (resp && resp.online) {
            pgStatusDot.className    = "s-dot online";
            pgStatusText.textContent = "BACKEND ONLINE  ·  SCANNING ACTIVE";
        } else {
            pgStatusDot.className    = "s-dot offline";
            pgStatusText.textContent = "BACKEND OFFLINE  ·  START :8001";
        }
    });
}


// ════════════════════════════════════════════════════════════════════════════
// SCAN BUTTON
// ════════════════════════════════════════════════════════════════════════════

pgScanBtn.addEventListener("click", function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        var url = (tabs && tabs[0] && tabs[0].url) || "";

        if (!url.startsWith("http")) {
            pgStatusText.textContent = "CANNOT SCAN THIS PAGE TYPE";
            return;
        }

        // Mark when this scan started so poll ignores stale storage
        _scanRequestTs = Date.now();

        // Clear any old result from storage so the poll doesn't
        // pick it up as a new result
        chrome.storage.local.remove("lastScan", function () {
            showOverlay(url);

            chrome.runtime.sendMessage({ type: "SCAN_CURRENT_TAB" }, function (resp) {
                if (!resp || resp.ok === false) {
                    // Background couldn't even start the scan
                    hideOverlay(false);
                    return;
                }
                // Background is scanning — poll storage for the result
                startPolling();
            });
        });
    });
});


// ════════════════════════════════════════════════════════════════════════════
// RESET + DASHBOARD BUTTONS
// ════════════════════════════════════════════════════════════════════════════

pgResetBtn.addEventListener("click", doReset);
pgDashBtn.addEventListener("click",  function () { chrome.tabs.create({ url: DASHBOARD_URL }); });


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

buildTracks();
buildTicks();
_drawAt(0);

checkBackend();

chrome.storage.local.get(["lastScan"], function (data) {
    if (data && data.lastScan) renderResult(data.lastScan);
});

setInterval(checkBackend, 30000);