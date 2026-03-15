/**
 * content.js — PhishGuard Page Banner & Tooltip Injector
 * Injects a color-coded banner at the top of the page
 * and a hoverable threat summary tooltip.
 */

"use strict";

var _banner  = null;
var _tooltip = null;

// ── Listen for scan results from background service worker ────────────────────
chrome.runtime.onMessage.addListener(function (msg) {
  if (msg.type !== "PHISHGUARD_RESULT") { return; }
  var result = msg.result;
  if (!result) { return; }

  removeBanner();
  injectBanner(result);
});

// ── Banner injection ──────────────────────────────────────────────────────────
function injectBanner(result) {
  var colors = {
    SAFE:       { bg: "#0d1117", border: "#3fb950", text: "#3fb950", icon: "✅" },
    SUSPICIOUS: { bg: "#0d1117", border: "#d29922", text: "#d29922", icon: "⚠" },
    MALICIOUS:  { bg: "#0d1117", border: "#f85149", text: "#f85149", icon: "🚫" },
  };
  var cfg = colors[result.label] || colors.SAFE;

  _banner = document.createElement("div");
  _banner.id = "__phishguard_banner__";

  // ── Banner styles ──────────────────────────────────────────────────────────
  Object.assign(_banner.style, {
    position:       "fixed",
    top:            "0",
    left:           "0",
    right:          "0",
    zIndex:         "2147483647",
    background:     cfg.bg,
    borderBottom:   "3px solid " + cfg.border,
    color:          cfg.text,
    fontFamily:     "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    fontSize:       "13px",
    padding:        "8px 16px",
    display:        "flex",
    alignItems:     "center",
    gap:            "10px",
    boxShadow:      "0 2px 8px rgba(0,0,0,.5)",
    transition:     "opacity .3s ease",
  });

  // ── Score bar ──────────────────────────────────────────────────────────────
  var barColor = cfg.border;
  var scoreBarHTML = (
    "<div style='flex:1;background:#21262d;border-radius:4px;height:6px;" +
    "overflow:hidden;max-width:120px'>" +
      "<div style='width:" + result.risk_score + "%;height:100%;" +
      "background:" + barColor + ";border-radius:4px'></div>" +
    "</div>"
  );

  // ── Banner content ─────────────────────────────────────────────────────────
  _banner.innerHTML = (
    "<span style='font-size:16px'>" + cfg.icon + "</span>" +
    "<span style='font-weight:700;letter-spacing:.03em'>" +
      "PhishGuard: " + result.label +
    "</span>" +
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

  // Nudge page content down
  document.body.style.paddingTop =
    (parseInt(document.body.style.paddingTop || "0") + 44) + "px";

  // ── Close button ──────────────────────────────────────────────────────────
  var closeBtn = _banner.querySelector("#__pg_close__");
  if (closeBtn) {
    closeBtn.addEventListener("click", function () {
      removeBanner();
    });
  }

  // ── Tooltip ───────────────────────────────────────────────────────────────
  var tooltipTrigger = _banner.querySelector("#__pg_tooltip_trigger__");
  if (tooltipTrigger) {
    tooltipTrigger.addEventListener("mouseenter", function (e) {
      showTooltip(result.threat_summary, e.target);
    });
    tooltipTrigger.addEventListener("mouseleave", function () {
      hideTooltip();
    });
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
      "🤖 AI Threat Summary" +
    "</strong>" +
    escapeHtml(text || "No threat information available.")
  );

  document.body.appendChild(_tooltip);

  // Position below anchor
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