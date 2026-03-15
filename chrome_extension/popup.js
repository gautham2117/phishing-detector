"use strict";

var DASHBOARD_URL = "http://127.0.0.1:5000/extension/";

// ── DOM ───────────────────────────────────────────────────────────────────────
var pgStatusDot   = document.getElementById("pgStatusDot");
var pgStatusText  = document.getElementById("pgStatusText");
var pgVerdictBadge= document.getElementById("pgVerdictBadge");
var pgScore       = document.getElementById("pgScore");
var pgBarFill     = document.getElementById("pgBarFill");
var pgUrl         = document.getElementById("pgUrl");
var pgSummary     = document.getElementById("pgSummary");
var pgAction      = document.getElementById("pgAction");
var pgScanBtn     = document.getElementById("pgScanBtn");
var pgDashBtn     = document.getElementById("pgDashBtn");

var ACTION_LABELS = {
  ALLOW:      "✅ Allow",
  WARN:       "⚠ Review carefully",
  QUARANTINE: "🔒 Quarantine",
  BLOCK:      "🚫 Block",
};


// ── Check backend status ──────────────────────────────────────────────────────
chrome.runtime.sendMessage({ type: "PING_BACKEND" }, function (resp) {
  if (resp && resp.online) {
    pgStatusDot.className  = "pg-status-dot online";
    pgStatusText.textContent = "Backend online — scanning active";
  } else {
    pgStatusDot.className  = "pg-status-dot offline";
    pgStatusText.textContent = "Backend offline — start FastAPI on :8001";
  }
});


// ── Load last scan result from storage ────────────────────────────────────────
chrome.storage.local.get(["lastScan"], function (data) {
  if (data && data.lastScan) {
    renderResult(data.lastScan);
  } else {
    pgUrl.textContent     = "No scans yet on this session.";
    pgSummary.textContent = "Browse to any page to trigger an automatic scan.";
  }
});


// ── Scan current tab ──────────────────────────────────────────────────────────
pgScanBtn.addEventListener("click", function () {
  pgScanBtn.disabled    = true;
  pgScanBtn.textContent = "⏳ Scanning…";

  chrome.runtime.sendMessage({ type: "SCAN_CURRENT_TAB" }, function () {
    // Poll storage for result (background will update it)
    var attempts = 0;
    var poll = setInterval(function () {
      attempts++;
      chrome.storage.local.get(["lastScan"], function (data) {
        if (data && data.lastScan) {
          renderResult(data.lastScan);
          pgScanBtn.disabled    = false;
          pgScanBtn.textContent = "🔍 Scan This Page";
          clearInterval(poll);
        }
        if (attempts >= 15) {
          pgScanBtn.disabled    = false;
          pgScanBtn.textContent = "🔍 Scan This Page";
          clearInterval(poll);
        }
      });
    }, 500);
  });
});


// ── Open dashboard ────────────────────────────────────────────────────────────
pgDashBtn.addEventListener("click", function () {
  chrome.tabs.create({ url: DASHBOARD_URL });
});


// ── Render result ─────────────────────────────────────────────────────────────
function renderResult(result) {
  var label     = result.label  || "SAFE";
  var score     = result.risk_score || 0;
  var labelLow  = label.toLowerCase();

  // Badge
  pgVerdictBadge.textContent = label;
  pgVerdictBadge.className   = "pg-verdict-badge " + labelLow;

  // Score
  pgScore.textContent = score.toFixed(1) + " / 100";

  // Bar
  pgBarFill.style.width = Math.min(score, 100) + "%";
  pgBarFill.className   = "pg-bar-fill " + labelLow;

  // URL
  pgUrl.textContent = result.url || "—";

  // Summary
  pgSummary.textContent = result.threat_summary || "No threat information.";

  // Action
  var action = result.action || result.recommended_action || "ALLOW";
  pgAction.textContent  = ACTION_LABELS[action] || action;
  pgAction.style.color  = {
    ALLOW:      "#3fb950",
    WARN:       "#d29922",
    QUARANTINE: "#f85149",
    BLOCK:      "#f85149",
  }[action] || "#8b949e";
}