/**
 * background.js — Mahoraga Sentinel Extension Service Worker
 * FIX 1: Trusted domain whitelist — skips backend scan for known-safe
 *         domains and writes SAFE result directly to storage.
 * FIX 2: Stores ts on every result for popup polling.
 * FIX 3: Uses explicit Request + Headers to preserve Content-Type.
 * FIX 4: Handles SET_AUTO_SCAN, respects autoScanEnabled (default OFF).
 * FIX 5: Writes failed:true sentinel so popup never hangs.
 */

"use strict";

var FASTAPI_BASE   = "http://127.0.0.1:8001";
var SCAN_ENDPOINT  = FASTAPI_BASE + "/api/extension/scan";
var EMAIL_ENDPOINT = FASTAPI_BASE + "/api/scan/email";
var PING_ENDPOINT  = FASTAPI_BASE + "/api/extension/status";
var SCAN_CACHE     = {};
var CACHE_TTL_MS   = 5 * 60 * 1000;

var SKIP_SCHEMES = [
  "chrome://", "chrome-extension://", "about:",
  "data:", "file://", "moz-extension://"
];

// Trusted domains — never scanned, always returned as SAFE.
// These are major platforms where a malicious score is always a false positive.
var TRUSTED_DOMAINS = [
  "mail.google.com",
  "google.com",
  "gmail.com",
  "accounts.google.com",
  "github.com",
  "microsoft.com",
  "live.com",
  "outlook.com",
  "office.com",
  "office365.com",
  "linkedin.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "aws.amazon.com",
  "twitter.com",
  "x.com",
  "facebook.com",
  "instagram.com",
  "youtube.com",
  "wikipedia.org",
  "stackoverflow.com",
  "npmjs.com",
  "pypi.org",
  "cloudflare.com",
];

function isTrustedDomain(url) {
  try {
    var hostname = new URL(url).hostname.toLowerCase();
    return TRUSTED_DOMAINS.some(function (d) {
      // exact match or subdomain match (e.g. mail.google.com matches google.com)
      return hostname === d || hostname.endsWith("." + d);
    });
  } catch (e) {
    return false;
  }
}

function makeSafeResult(url) {
  try {
    var hostname = new URL(url).hostname;
  } catch (e) {
    var hostname = url;
  }
  return {
    mode:           "url",
    url:            url,
    risk_score:     0,
    label:          "SAFE",
    verdict:        "SAFE",
    threat_summary: hostname + " is a trusted domain — scan skipped.",
    action:         "ALLOW",
    details:        { domain: hostname, ssl_valid: true, domain_age: null, flags: [] },
    ts:             Date.now(),
    failed:         false,
    trusted:        true,
  };
}

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
  // Trusted domain — return SAFE immediately without hitting backend
  if (isTrustedDomain(url)) {
    var result = makeSafeResult(url);
    SCAN_CACHE[url] = { result: result, ts: result.ts };
    chrome.storage.local.set({ lastScan: result });
    sendToTab(tabId, result);
    updateBadge(tabId, "SAFE");
    return;
  }

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
        chrome.storage.local.set({
          lastScan: {
            mode:"url", url:url, risk_score:0, label:"UNKNOWN", verdict:"UNKNOWN",
            threat_summary:"Scan returned non-success status.",
            action:"WARN", details:{}, ts:Date.now(), failed:true,
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
      chrome.storage.local.set({ lastScan: result });
      sendToTab(tabId, result);
      updateBadge(tabId, result.label);
    })
    .catch(function (err) {
      console.warn("[Mahoraga Sentinel] URL scan failed:", err.message);
      chrome.storage.local.set({
        lastScan: {
          mode:"url", url:url, risk_score:0, label:"UNKNOWN", verdict:"UNKNOWN",
          threat_summary:"Scan failed: " + err.message,
          action:"WARN", details:{}, ts:Date.now(), failed:true,
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
        sendResponse({ ok:false, error:"Backend error" });
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
      sendResponse({ ok:true, result:result });
    })
    .catch(function (err) {
      console.warn("[Mahoraga Sentinel] Email scan failed:", err.message);
      sendResponse({ ok:false, error:err.message });
    });
}

// ── Send result to content script ─────────────────────────────────────────────
function sendToTab(tabId, result) {
  if (!tabId) { return; }
  chrome.tabs.sendMessage(tabId, { type:"PHISHGUARD_RESULT", result:result })
    .catch(function () {
      setTimeout(function () {
        chrome.tabs.sendMessage(tabId, { type:"PHISHGUARD_RESULT", result:result })
          .catch(function () {});
      }, 500);
    });
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(tabId, label) {
  var cfg = {
    SAFE:       { text:"✓", color:"#3fb950" },
    SUSPICIOUS: { text:"!", color:"#d29922" },
    MALICIOUS:  { text:"✕", color:"#f85149" },
  };
  var c = cfg[label] || cfg.SAFE;
  chrome.action.setBadgeText({ text:c.text, tabId:tabId });
  chrome.action.setBadgeBackgroundColor({ color:c.color, tabId:tabId });
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {

  if (msg.type === "SCAN_CURRENT_TAB") {
    chrome.tabs.query({ active:true, currentWindow:true }, function (tabs) {
      if (!tabs||!tabs[0]) { sendResponse({ok:false,error:"No active tab."}); return; }
      var url=tabs[0].url||"";
      if (!url.startsWith("http")) { sendResponse({ok:false,error:"Cannot scan this page."}); return; }
      delete SCAN_CACHE[url];
      chrome.storage.local.set({
        scanInFlight: { url:url, startedAt:Date.now() }
      });
      sendResponse({ ok:true, status:"scanning" });
      scanUrl(url, tabs[0].id);
    });
    return true;
  }

  if (msg.type === "SCAN_EMAIL_CONTENT") {
    if (!msg.raw_email||!msg.raw_email.trim()) {
      sendResponse({ok:false,error:"Empty email content."}); return true;
    }
    chrome.tabs.query({active:true,currentWindow:true},function(tabs){
      var tabId = tabs&&tabs[0] ? tabs[0].id : null;
      scanEmail(msg.raw_email, tabId, sendResponse);
    });
    return true;
  }

  if (msg.type === "PING_BACKEND") {
    fetch(PING_ENDPOINT)
      .then(function(r){ return r.json(); })
      .then(function(d){ sendResponse({online: d.status==="online"}); })
      .catch(function(){ sendResponse({online:false}); });
    return true;
  }

  if (msg.type === "SET_AUTO_SCAN") {
    chrome.storage.local.set({ autoScanEnabled: !!msg.enabled });
    sendResponse({ok:true});
    return true;
  }
});