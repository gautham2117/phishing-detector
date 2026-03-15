/**
 * background.js — PhishGuard Extension Service Worker
 * Intercepts navigation events, scans URLs, stores results,
 * sends verdict to content script via tab messaging.
 */

"use strict";

var FASTAPI_BASE   = "http://127.0.0.1:8001";
var SCAN_ENDPOINT  = FASTAPI_BASE + "/api/extension/scan";
var PING_ENDPOINT  = FASTAPI_BASE + "/api/extension/status";
var SCAN_CACHE     = {};       // url → result cache (session)
var CACHE_TTL_MS   = 5 * 60 * 1000;  // 5 minutes
var SKIP_SCHEMES   = ["chrome://", "chrome-extension://", "about:", "data:",
                      "file://", "moz-extension://"];

// ── Intercept completed navigations ──────────────────────────────────────────
chrome.webNavigation.onCompleted.addListener(function (details) {
  if (details.frameId !== 0) { return; }  // main frame only

  var url = details.url || "";
  if (!url.startsWith("http")) { return; }
  if (SKIP_SCHEMES.some(function (s) { return url.startsWith(s); })) { return; }

  scanUrl(url, details.tabId);
});

// ── Scan a URL ────────────────────────────────────────────────────────────────
function scanUrl(url, tabId) {
  // Check cache first
  var now    = Date.now();
  var cached = SCAN_CACHE[url];
  if (cached && (now - cached.ts) < CACHE_TTL_MS) {
    sendToTab(tabId, cached.result);
    return;
  }

  fetch(SCAN_ENDPOINT, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ url: url, source: "extension" }),
  })
  .then(function (r) { return r.json(); })
  .then(function (data) {
    if (data.status !== "success") { return; }

    var result = {
      url:            url,
      risk_score:     data.risk_score      || 0,
      label:          data.label           || "SAFE",
      verdict:        data.verdict         || "SAFE",
      threat_summary: data.threat_summary  || "No threats detected.",
      action:         data.recommended_action || "ALLOW",
      details:        data.details         || {},
    };

    // Cache it
    SCAN_CACHE[url] = { result: result, ts: Date.now() };

    // Save last result to storage for popup
    chrome.storage.local.set({ lastScan: result });

    // Send to content script
    sendToTab(tabId, result);

    // Update extension icon badge
    updateBadge(tabId, result.label);
  })
  .catch(function (err) {
    console.warn("[PhishGuard] Scan failed for:", url, err.message);
  });
}

// ── Send result to content script ─────────────────────────────────────────────
function sendToTab(tabId, result) {
  chrome.tabs.sendMessage(tabId, {
    type:   "PHISHGUARD_RESULT",
    result: result,
  }).catch(function () {
    // Content script not ready yet — retry once after 500ms
    setTimeout(function () {
      chrome.tabs.sendMessage(tabId, {
        type:   "PHISHGUARD_RESULT",
        result: result,
      }).catch(function () {/* silent */});
    }, 500);
  });
}

// ── Update icon badge ─────────────────────────────────────────────────────────
function updateBadge(tabId, label) {
  var config = {
    "SAFE":       { text: "✓",  color: "#3fb950" },
    "SUSPICIOUS": { text: "!",  color: "#d29922" },
    "MALICIOUS":  { text: "✕",  color: "#f85149" },
  };
  var cfg = config[label] || config["SAFE"];
  chrome.action.setBadgeText({
    text:  cfg.text,
    tabId: tabId,
  });
  chrome.action.setBadgeBackgroundColor({
    color: cfg.color,
    tabId: tabId,
  });
}

// ── Message handler (from popup requesting a fresh scan) ──────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (msg.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs || !tabs[0]) {
        sendResponse({ error: "No active tab." });
        return;
      }
      var url   = tabs[0].url || "";
      var tabId = tabs[0].id;
      if (!url.startsWith("http")) {
        sendResponse({ error: "Cannot scan this page." });
        return;
      }
      // Clear cache to force fresh scan
      delete SCAN_CACHE[url];
      scanUrl(url, tabId);
      sendResponse({ status: "scanning" });
    });
    return true;  // keep channel open for async
  }

  if (msg.type === "PING_BACKEND") {
    fetch(PING_ENDPOINT)
      .then(function (r) { return r.json(); })
      .then(function (d) { sendResponse({ online: d.status === "online" }); })
      .catch(function ()  { sendResponse({ online: false }); });
    return true;
  }
});