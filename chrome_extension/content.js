/**
 * content.js — Mahoraga Page Banner, Tooltip & Gmail Email Extractor
 *
 * Existing behaviour preserved exactly:
 *   - Injects colour-coded banner on scan result
 *   - Hoverable threat summary tooltip
 *
 * New behaviour added:
 *   - Responds to GET_EMAIL_CONTENT message from popup
 *   - Detects open Gmail thread and extracts sender, subject, body
 *   - Returns { found, sender, subject, body, raw_email } to popup
 */

"use strict";

var _banner  = null;
var _tooltip = null;

// ── Listen for scan results from background service worker ────────────────────
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {

  if (msg.type === "PHISHGUARD_RESULT") {
    var result = msg.result;
    if (!result) { return; }
    removeBanner();
    injectBanner(result);
    return;
  }

  // ── Gmail email extraction ─────────────────────────────────────────────────
  if (msg.type === "GET_EMAIL_CONTENT") {
    var extracted = extractGmailEmail();
    sendResponse(extracted);
    return true;
  }
});

// ════════════════════════════════════════════════════════════════════════════
// GMAIL EMAIL EXTRACTOR
// Gmail renders the open thread in the DOM. We look for the visible email
// body using Gmail's own data attributes and aria roles.
// ════════════════════════════════════════════════════════════════════════════

function extractGmailEmail() {
  // Must be on Gmail
  if (!window.location.hostname.includes("mail.google.com")) {
    return { found: false, reason: "not_gmail" };
  }

  // Must have a thread open — URL contains /#inbox/, /#all/, /#sent/ etc
  // or a message ID (long hex string after the hash)
  var hash = window.location.hash || "";
  var hasThread = (
    hash.includes("/") &&
    !hash.match(/^#(inbox|all|sent|drafts|spam|trash|starred|imp)$/)
  ) || hash.match(/#[a-z0-9]{16}/i);

  if (!hasThread) {
    return { found: false, reason: "no_thread_open" };
  }

  // ── Extract sender ─────────────────────────────────────────────────────────
  var sender = "";
  // Gmail puts sender email in [email] attribute or span.go inside .gD
  var senderEl = document.querySelector(".gD");
  if (senderEl) {
    sender = senderEl.getAttribute("email") || senderEl.textContent || "";
  }
  if (!sender) {
    // Fallback: look for From: in the message header area
    var fromSpan = document.querySelector("[data-hovercard-id]");
    if (fromSpan) { sender = fromSpan.getAttribute("data-hovercard-id") || ""; }
  }

  // ── Extract subject ────────────────────────────────────────────────────────
  var subject = "";
  // Gmail renders subject in h2.hP
  var subjEl = document.querySelector("h2.hP");
  if (subjEl) { subject = subjEl.textContent.trim(); }
  if (!subject) {
    // Fallback: page title minus " - Gmail"
    subject = document.title.replace(/\s*-\s*Gmail\s*$/, "").trim();
  }

  // ── Extract body ───────────────────────────────────────────────────────────
  // Gmail wraps the visible message body in div.a3s (class "a3s aiL" or similar)
  // There may be multiple (thread). We take the last visible one (most recent).
  var bodyEls = document.querySelectorAll("div.a3s");
  var bodyText = "";
  if (bodyEls.length > 0) {
    // Take last one (most recent message in thread)
    var lastBody = bodyEls[bodyEls.length - 1];
    bodyText = (lastBody.innerText || lastBody.textContent || "").trim();
  }

  // Fallback: any div with role="listitem" containing email content
  if (!bodyText) {
    var listItems = document.querySelectorAll('[role="listitem"]');
    for (var i = listItems.length - 1; i >= 0; i--) {
      var t = (listItems[i].innerText || "").trim();
      if (t.length > 40) { bodyText = t; break; }
    }
  }

  if (!sender && !subject && !bodyText) {
    return { found: false, reason: "content_not_found" };
  }

  // ── Build a minimal raw_email string for /api/scan/email ──────────────────
  var raw_email = [
    "From: " + (sender  || "unknown@gmail.com"),
    "Subject: " + (subject || "(no subject)"),
    "",
    bodyText || "(no body)",
  ].join("\n");

  return {
    found:     true,
    sender:    sender  || "",
    subject:   subject || "",
    body:      bodyText || "",
    raw_email: raw_email,
  };
}


// ════════════════════════════════════════════════════════════════════════════
// BANNER INJECTION  (unchanged from original)
// ════════════════════════════════════════════════════════════════════════════

function injectBanner(result) {
  var colors = {
    SAFE:       { bg: "#0d1117", border: "#3fb950", text: "#3fb950", icon: "✅" },
    SUSPICIOUS: { bg: "#0d1117", border: "#d29922", text: "#d29922", icon: "⚠"  },
    MALICIOUS:  { bg: "#0d1117", border: "#f85149", text: "#f85149", icon: "🚫" },
  };
  var cfg = colors[result.label] || colors.SAFE;

  _banner = document.createElement("div");
  _banner.id = "__phishguard_banner__";

  Object.assign(_banner.style, {
    position:     "fixed",
    top:          "0",
    left:         "0",
    right:        "0",
    zIndex:       "2147483647",
    background:   cfg.bg,
    borderBottom: "3px solid " + cfg.border,
    color:        cfg.text,
    fontFamily:   "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    fontSize:     "13px",
    padding:      "8px 16px",
    display:      "flex",
    alignItems:   "center",
    gap:          "10px",
    boxShadow:    "0 2px 8px rgba(0,0,0,.5)",
    transition:   "opacity .3s ease",
  });

  var barColor    = cfg.border;
  var scoreBarHTML = (
    "<div style='flex:1;background:#21262d;border-radius:4px;height:6px;" +
    "overflow:hidden;max-width:120px'>" +
      "<div style='width:" + result.risk_score + "%;height:100%;" +
      "background:" + barColor + ";border-radius:4px'></div>" +
    "</div>"
  );

  _banner.innerHTML = (
    "<span style='font-size:16px'>" + cfg.icon + "</span>" +
    "<span style='font-weight:700;letter-spacing:.03em'>Mahoraga: " + result.label + "</span>" +
    "<span style='color:#8b949e'>|</span>" +
    "<span>Risk: <strong style='color:" + cfg.border + "'>" +
      result.risk_score.toFixed(1) + "/100</strong></span>" +
    scoreBarHTML +
    "<span id='__pg_tooltip_trigger__' style='color:#388bfd;" +
      "cursor:pointer;text-decoration:underline;font-size:12px'>" +
      "ℹ Threat Summary" +
    "</span>" +
    "<button id='__pg_close__' style='margin-left:auto;background:transparent;" +
      "border:none;color:#8b949e;cursor:pointer;font-size:16px;" +
      "line-height:1;padding:0 4px'>✕</button>"
  );

  document.body.insertBefore(_banner, document.body.firstChild);

  document.body.style.paddingTop =
    (parseInt(document.body.style.paddingTop || "0") + 44) + "px";

  var closeBtn = _banner.querySelector("#__pg_close__");
  if (closeBtn) {
    closeBtn.addEventListener("click", function () { removeBanner(); });
  }

  var tooltipTrigger = _banner.querySelector("#__pg_tooltip_trigger__");
  if (tooltipTrigger) {
    tooltipTrigger.addEventListener("mouseenter", function (e) {
      showTooltip(result.threat_summary, e.target);
    });
    tooltipTrigger.addEventListener("mouseleave", hideTooltip);
    tooltipTrigger.addEventListener("click", function (e) {
      showTooltip(result.threat_summary, e.target);
    });
  }
}

// ── Tooltip ───────────────────────────────────────────────────────────────────

function showTooltip(text, anchor) {
  hideTooltip();

  _tooltip = document.createElement("div");
  _tooltip.id = "__phishguard_tooltip__";

  Object.assign(_tooltip.style, {
    position:     "fixed",
    zIndex:       "2147483647",
    background:   "#161b22",
    border:       "1px solid #30363d",
    borderRadius: "8px",
    color:        "#e6edf3",
    fontFamily:   "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    fontSize:     "12px",
    lineHeight:   "1.5",
    padding:      "10px 14px",
    maxWidth:     "360px",
    boxShadow:    "0 4px 16px rgba(0,0,0,.6)",
    pointerEvents:"none",
  });

  _tooltip.innerHTML = (
    "<strong style='color:#388bfd;display:block;margin-bottom:4px'>" +
      "🤖 Mahoraga Sentinel - AI Threat Summary" +
    "</strong>" +
    escapeHtml(text || "No threat information available.")
  );

  document.body.appendChild(_tooltip);

  var rect = anchor.getBoundingClientRect();
  _tooltip.style.top  = (rect.bottom + 6) + "px";
  _tooltip.style.left = Math.min(rect.left, window.innerWidth - 380) + "px";
}

function hideTooltip() {
  if (_tooltip && _tooltip.parentNode) {
    _tooltip.parentNode.removeChild(_tooltip);
  }
  _tooltip = null;
}

// ── Remove banner ─────────────────────────────────────────────────────────────

function removeBanner() {
  if (_banner && _banner.parentNode) {
    document.body.style.paddingTop =
      Math.max(0, parseInt(document.body.style.paddingTop || "0") - 44) + "px";
    _banner.parentNode.removeChild(_banner);
  }
  _banner = null;
  hideTooltip();
}

// ── Escape HTML ───────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}