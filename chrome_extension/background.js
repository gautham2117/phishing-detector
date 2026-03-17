/**
 * background.js — Mahoraga Sentinel Extension Service Worker
 * KEY FIX: Popup closes mid-poll killing the interval.
 * Solution: background owns the entire scan lifecycle.
 * Popup only (1) triggers scan, (2) reads storage on open.
 * No polling in popup — storage read is instant on popup open.
 */

"use strict";

var FASTAPI_BASE   = "http://127.0.0.1:8001";
var SCAN_ENDPOINT  = FASTAPI_BASE + "/api/extension/scan";
var EMAIL_ENDPOINT = FASTAPI_BASE + "/api/scan/email";
var PING_ENDPOINT  = FASTAPI_BASE + "/api/extension/status";
var SCAN_CACHE     = {};
var CACHE_TTL_MS   = 5 * 60 * 1000;
var SKIP_SCHEMES   = [
  "chrome://", "chrome-extension://", "about:",
  "data:", "file://", "moz-extension://"
];

// ── Intercept completed navigations ──────────────────────────────────────────
chrome.webNavigation.onCompleted.addListener(function (details) {
  if (details.frameId !== 0) { return; }
  var url = details.url || "";
  if (!url.startsWith("http")) { return; }
  if (SKIP_SCHEMES.some(function (s) { return url.startsWith(s); })) { return; }

  chrome.storage.local.get(["autoScanEnabled"], function (data) {
    if (data.autoScanEnabled !== true) { return; }
    scanUrl(url, details.tabId);
  });
});

// ── URL Scan ──────────────────────────────────────────────────────────────────
function scanUrl(url, tabId) {
  var now    = Date.now();
  var cached = SCAN_CACHE[url];
  if (cached && (now - cached.ts) < CACHE_TTL_MS) {
    var c = cached.result;
    c.ts  = cached.ts;
    chrome.storage.local.set({ lastScan: c });
    sendToTab(tabId, c);
    return;
  }

  var req = new Request(SCAN_ENDPOINT, {
    method:  "POST",
    headers: new Headers({ "Content-Type": "application/json" }),
    body:    JSON.stringify({ url: url, source: "extension" }),
    mode:    "cors",
  });

  fetch(req)
    .then(function (r) {
      if (!r.ok) {
        return r.text().then(function (t) {
          throw new Error("HTTP " + r.status + ": " + t.slice(0, 200));
        });
      }
      return r.json();
    })
    .then(function (data) {
      if (data.status !== "success") {
        console.warn("[Mahoraga Sentinel] Non-success response:", data);
        // Write failure state so popup can show it
        chrome.storage.local.set({
          lastScan: {
            mode: "url", url: url,
            risk_score: 0, label: "UNKNOWN", verdict: "UNKNOWN",
            threat_summary: "Scan returned non-success status.",
            action: "WARN", details: {}, ts: Date.now(), failed: true,
          }
        });
        return;
      }

      var ts     = Date.now();
      var result = {
        mode:           "url",
        url:            url,
        risk_score:     data.risk_score         || 0,
        label:          data.label              || "SAFE",
        verdict:        data.verdict            || "SAFE",
        threat_summary: data.threat_summary     || "No threats detected.",
        action:         data.recommended_action || "ALLOW",
        details:        data.details            || {},
        ts:             ts,
        failed:         false,
      };

      SCAN_CACHE[url] = { result: result, ts: ts };

      // Write to storage — popup reads this on open
      chrome.storage.local.set({ lastScan: result });

      sendToTab(tabId, result);
      updateBadge(tabId, result.label);
    })
    .catch(function (err) {
      console.warn("[Mahoraga Sentinel] URL scan failed:", err.message);
      // Write failure so popup knows scan is done (failed)
      chrome.storage.local.set({
        lastScan: {
          mode: "url", url: url,
          risk_score: 0, label: "UNKNOWN", verdict: "UNKNOWN",
          threat_summary: "Scan failed: " + err.message,
          action: "WARN", details: {}, ts: Date.now(), failed: true,
        }
      });
    });
}

// ── Email Scan ────────────────────────────────────────────────────────────────
function scanEmail(rawEmail, tabId, sendResponse) {
  var req = new Request(EMAIL_ENDPOINT, {
    method:  "POST",
    headers: new Headers({ "Content-Type": "application/json" }),
    body:    JSON.stringify({ raw_email: rawEmail, submitter: "extension" }),
    mode:    "cors",
  });

  fetch(req)
    .then(function (r) {
      if (!r.ok) {
        return r.text().then(function (t) {
          throw new Error("HTTP " + r.status + ": " + t.slice(0, 200));
        });
      }
      return r.json();
    })
    .then(function (data) {
      if (data.status !== "success") {
        sendResponse({ ok: false, error: "Backend error" });
        return;
      }
      var ep  = (data.module_results || {}).email_parser || {};
      var ts  = Date.now();
      var result = {
        mode:           "email",
        risk_score:     data.risk_score         || 0,
        label:          data.label              || "SAFE",
        verdict:        data.label              || "SAFE",
        threat_summary: data.explanation        || "No threats detected.",
        action:         data.recommended_action || "ALLOW",
        sender:         ep.sender               || "",
        subject:        ep.subject              || "",
        anomalies:      ep.anomalies            || [],
        ts:             ts,
        failed:         false,
      };
      chrome.storage.local.set({ lastEmailScan: result });
      if (tabId) { updateBadge(tabId, result.label); }
      sendResponse({ ok: true, result: result });
    })
    .catch(function (err) {
      console.warn("[Mahoraga Sentinel] Email scan failed:", err.message);
      sendResponse({ ok: false, error: err.message });
    });
}

// ── Send result to content script ─────────────────────────────────────────────
function sendToTab(tabId, result) {
  if (!tabId) { return; }
  chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_RESULT", result: result })
    .catch(function () {
      setTimeout(function () {
        chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_RESULT", result: result })
          .catch(function () {});
      }, 500);
    });
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(tabId, label) {
  var cfg = {
    SAFE:       { text: "✓", color: "#3fb950" },
    SUSPICIOUS: { text: "!", color: "#d29922" },
    MALICIOUS:  { text: "✕", color: "#f85149" },
  };
  var c = cfg[label] || cfg.SAFE;
  chrome.action.setBadgeText({ text: c.text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: c.color, tabId: tabId });
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {

  // Popup triggers scan — background does the fetch and writes storage.
  // Popup does NOT poll. It reads storage when it reopens.
  if (msg.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs || !tabs[0]) {
        sendResponse({ ok: false, error: "No active tab." });
        return;
      }
      var url   = tabs[0].url || "";
      var tabId = tabs[0].id;
      if (!url.startsWith("http")) {
        sendResponse({ ok: false, error: "Cannot scan this page." });
        return;
      }
      delete SCAN_CACHE[url];

      // Write a "scanning" sentinel so popup knows a scan is in flight
      // if it reopens before the result arrives
      chrome.storage.local.set({
        scanInFlight: { url: url, startedAt: Date.now() }
      });

      // Respond immediately so popup can show overlay
      sendResponse({ ok: true, status: "scanning" });

      // Do the actual fetch — result written to storage when done
      scanUrl(url, tabId);
    });
    return true;
  }

  // Popup polls once on open to check if an in-flight scan finished
  if (msg.type === "GET_LAST_SCAN") {
    chrome.storage.local.get(["lastScan", "scanInFlight"], function (data) {
      sendResponse({
        lastScan:    data.lastScan    || null,
        scanInFlight: data.scanInFlight || null,
      });
    });
    return true;
  }

  if (msg.type === "SCAN_EMAIL_CONTENT") {
    if (!msg.raw_email || !msg.raw_email.trim()) {
      sendResponse({ ok: false, error: "Empty email content." });
      return true;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tabId = tabs && tabs[0] ? tabs[0].id : null;
      scanEmail(msg.raw_email, tabId, sendResponse);
    });
    return true;
  }

  if (msg.type === "PING_BACKEND") {
    fetch(PING_ENDPOINT)
      .then(function (r) { return r.json(); })
      .then(function (d) { sendResponse({ online: d.status === "online" }); })
      .catch(function ()  { sendResponse({ online: false }); });
    return true;
  }

  if (msg.type === "SET_AUTO_SCAN") {
    chrome.storage.local.set({ autoScanEnabled: !!msg.enabled });
    sendResponse({ ok: true });
    return true;
  }
});