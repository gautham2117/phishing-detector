// url_intel.js
// Client-side logic for the URL Intelligence dashboard page.

"use strict";

// ─── Submit a single URL ─────────────────────────────────────────────────────

async function submitUrl() {
  const urlInput = document.getElementById("url-input");
  const url      = urlInput.value.trim();

  if (!url) {
    alert("Please enter a URL to analyze.");
    return;
  }

  // Basic URL sanity check before sending to the server
  if (!url.match(/^https?:\/\/.+/i) && !url.includes(".")) {
    alert("Please enter a valid URL (e.g. https://example.com)");
    return;
  }

  showSpinner(true, "Running WHOIS, SSL, DNS, and ML checks...");
  hideResultCard();

  try {
    const response = await fetch("/url/submit", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok) {
      alert(`Error: ${data.error || response.statusText}`);
      return;
    }

    renderUrlResult(data);
    refreshHistory();

  } catch (err) {
    alert(`Network error: ${err.message}`);
  } finally {
    showSpinner(false);
  }
}


// ─── Render full result card ──────────────────────────────────────────────────

function renderUrlResult(data) {
  /*
   * data.module_results.url_intelligence contains the full result dict:
   * {
   *   original_url, normalized_url, domain,
   *   whois: {registrar, creation_date, domain_age_days, is_young_domain, ...},
   *   ssl:   {has_ssl, valid, issuer, expiry_date, is_self_signed, is_free_cert},
   *   ip:    {ip_address, country, city, org, asn, is_cdn},
   *   dns:   {A, MX, NS, has_spf_record, has_dmarc_record, uses_free_dns},
   *   redirects: {chain, final_url, hop_count, crosses_domain, has_open_redirect},
   *   ml_result: {label, score, model},
   *   risk_score, label, flags
   * }
   */
  const ui = data.module_results?.url_intelligence || {};

  // ── URL header ──
  document.getElementById("result-url").textContent    = ui.original_url || "—";
  document.getElementById("result-domain").textContent = ui.domain || "";

  // ── Risk badge + score bar ──
  const label   = data.label || "UNKNOWN";
  const score   = data.risk_score || 0;
  const badge   = document.getElementById("risk-badge");
  badge.textContent = label;
  badge.className   = `risk-badge badge-${label.toLowerCase()}`;

  const bar = document.getElementById("score-bar");
  bar.style.width = `${score}%`;
  bar.className   = `score-bar-fill ${
    score < 30 ? "fill-safe" : score < 70 ? "fill-suspicious" : "fill-malicious"
  }`;
  document.getElementById("score-number").textContent = score.toFixed(1);

  // ── Action pill ──
  const action = data.recommended_action || "WARN";
  const pill   = document.getElementById("action-pill");
  pill.textContent = `Recommended: ${action}`;
  pill.className   = `action-pill action-${action.toLowerCase()}`;

  // ── Risk flags row ──
  const flagsRow = document.getElementById("flags-row");
  flagsRow.innerHTML = (ui.flags || [])
    .map(f => `<span class="flag-pill">${escapeHtml(f)}</span>`)
    .join(" ");

  // ── WHOIS ──
  const w = ui.whois || {};
  setText("w-registrar", w.registrar || "—");
  setText("w-created",   w.creation_date   ? formatDate(w.creation_date)   : "—");
  setText("w-expires",   w.expiration_date  ? formatDate(w.expiration_date)  : "—");
  setText("w-age",       w.domain_age_days != null ? `${w.domain_age_days} days` : "—");

  const youngEl = document.getElementById("w-young");
  if (w.is_young_domain) {
    youngEl.innerHTML = '<span class="auth-pill auth-fail">Yes — under 6 months</span>';
  } else if (w.domain_age_days != null) {
    youngEl.innerHTML = '<span class="auth-pill auth-pass">No</span>';
  } else {
    youngEl.textContent = "—";
  }

  // ── SSL ──
  const s = ui.ssl || {};
  setBoolPill("s-https",  s.has_ssl,       "HTTPS",       "HTTP only");
  setBoolPill("s-valid",  s.valid,          "Valid",        "Invalid");
  setText("s-issuer",     s.issuer || "—");
  setText("s-expiry",     s.expiry_date    ? `${formatDate(s.expiry_date)} (${s.days_until_expiry ?? "?"} days)` : "—");
  setBoolPill("s-self",   s.is_self_signed, "Yes (⚠ risk)", "No", true);
  setBoolPill("s-free",   s.is_free_cert,   "Yes",          "No",  false, true);

  // ── IP / Geo ──
  const g = ui.ip || {};
  setText("g-ip",      g.ip_address || "—");
  setText("g-country", g.country    || "—");
  setText("g-city",    g.city       || "—");
  setText("g-org",     g.org        || "—");
  setText("g-asn",     g.asn        || "—");
  setBoolPill("g-cdn", g.is_cdn,    "Yes (CDN)", "No", false, true);

  // ── DNS ──
  const d = ui.dns || {};
  setText("d-a",    (d.A  || []).join(", ") || "—");
  setText("d-mx",   (d.MX || []).slice(0,3).join("; ") || "—");
  setText("d-ns",   (d.NS || []).slice(0,2).join(", ") || "—");
  setBoolPill("d-spf",     d.has_spf_record,   "Present",   "Missing", false, false);
  setBoolPill("d-dmarc",   d.has_dmarc_record, "Present",   "Missing", false, false);
  setBoolPill("d-freedns", d.uses_free_dns,    "Yes (note)","No",      false, true);

  // ── Redirect chain ──
  const r       = ui.redirects || {};
  const chain   = r.chain || [];
  const hopBadge = document.getElementById("hop-count");
  hopBadge.textContent = `${r.hop_count || 0} hop${r.hop_count !== 1 ? "s" : ""}`;

  const chainDiv = document.getElementById("redirect-chain-display");
  if (chain.length === 0) {
    chainDiv.innerHTML = '<p class="empty-state">No redirects — URL resolves directly</p>';
  } else {
    chainDiv.innerHTML = `<div class="redirect-chain">
      ${chain.map((hop, i) => {
        const statusClass =
          hop.status_code >= 200 && hop.status_code < 300 ? "status-2xx" :
          hop.status_code >= 300 && hop.status_code < 400 ? "status-3xx" : "status-err";
        return `<div class="redirect-hop">
          <div class="hop-num">${i + 1}</div>
          <div class="hop-url">${escapeHtml(truncate(hop.url, 80))}</div>
          <div class="hop-status ${statusClass}">
            ${hop.status_code || "err"}
          </div>
        </div>`;
      }).join("")}
      ${r.crosses_domain
        ? `<div class="anomaly-item severity-high" style="margin-top:8px">
             Cross-domain redirect detected — final destination domain differs from original
           </div>`
        : ""}
      ${r.has_open_redirect
        ? `<div class="anomaly-item severity-high" style="margin-top:4px">
             Open redirect detected — trusted domain redirects to external URL
           </div>`
        : ""}
    </div>`;
  }

  // ── ML result ──
  const ml = ui.ml_result || {};
  const verdict   = document.getElementById("ml-verdict");
  verdict.textContent = ml.label || "—";
  verdict.style.color =
    ml.label === "MALICIOUS" ? "var(--red)" :
    ml.label === "BENIGN"    ? "var(--green)" : "var(--text-muted)";

  const mlConf = Math.round((ml.score || 0) * 100);
  const mlBar  = document.getElementById("ml-conf-bar");
  mlBar.style.width = `${mlConf}%`;
  mlBar.className   = `confidence-bar-fill ${
    ml.label === "MALICIOUS" ? "fill-malicious" : "fill-safe"
  }`;
  document.getElementById("ml-conf-label").textContent = `${mlConf}% confidence`;
  document.getElementById("ml-model-name").textContent = ml.model || "";

  // ── Explanation ──
  document.getElementById("explanation-text").textContent =
    data.explanation || "—";

  // ── Show the card ──
  document.getElementById("result-card").style.display = "block";
  document.getElementById("result-card").scrollIntoView({ behavior: "smooth" });
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
}


// ─── Live history polling ─────────────────────────────────────────────────────

async function refreshHistory() {
  try {
    const resp  = await fetch("/url/history");
    if (!resp.ok) return;
    const scans = await resp.json();

    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    if (!scans.length) {
      tbody.innerHTML =
        '<tr><td colspan="8" class="empty-state">No URL scans yet</td></tr>';
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const labelClass  = (s.final_label || "unknown").toLowerCase();
      const sslBadge    = s.ssl_valid
        ? '<span class="auth-pill auth-pass">valid</span>'
        : '<span class="auth-pill auth-fail">invalid</span>';
      const ageBadge    = s.domain_age_days != null
        ? `<span class="${s.domain_age_days < 180 ? "text-danger" : ""}">${s.domain_age_days}</span>`
        : "—";

      return `<tr>
        <td class="truncate" title="${escapeHtml(s.raw_url || "")}">
          <code>${escapeHtml(s.domain || "—")}</code>
        </td>
        <td>${escapeHtml(s.ip_address || "—")}</td>
        <td>${escapeHtml(s.country || "—")}</td>
        <td>${ageBadge}</td>
        <td>${sslBadge}</td>
        <td>
          <span class="score-pill score-${labelClass}">
            ${(s.ml_score || 0).toFixed(2)}
          </span>
        </td>
        <td>
          <span class="label-badge label-${labelClass}">
            ${s.final_label || "—"}
          </span>
        </td>
        <td>${s.scanned_at ? new Date(s.scanned_at).toLocaleString() : "—"}</td>
      </tr>`;
    }).join("");

    document.getElementById("update-time").textContent =
      new Date().toLocaleTimeString();

  } catch (err) {
    console.warn("URL history refresh failed:", err.message);
  }
}

// Poll every 5 seconds when on this page
if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── Helpers ─────────────────────────────────────────────────────────────────

function showSpinner(show, msg = "") {
  const el = document.getElementById("spinner");
  if (!el) return;
  el.style.display = show ? "flex" : "none";
  if (msg) document.getElementById("spinner-msg").textContent = msg;
}

function hideResultCard() {
  const el = document.getElementById("result-card");
  if (el) el.style.display = "none";
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

/**
 * Set a cell to a colored pass/fail pill based on a boolean.
 * @param {boolean} warningOnTrue  — if true, a "true" value shows amber not green
 * @param {boolean} neutralOnTrue  — if true, a "true" value shows neutral gray
 */
function setBoolPill(id, bool, trueLabel, falseLabel,
                     warningOnTrue = false, neutralOnTrue = false) {
  const el = document.getElementById(id);
  if (!el) return;

  if (bool === null || bool === undefined) {
    el.textContent = "—";
    return;
  }

  if (bool) {
    const cls = neutralOnTrue ? "auth-none"
              : warningOnTrue ? "auth-fail" : "auth-pass";
    el.innerHTML = `<span class="auth-pill ${cls}">${trueLabel}</span>`;
  } else {
    el.innerHTML = `<span class="auth-pill auth-fail">${falseLabel}</span>`;
  }
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  try {
    return new Date(isoStr).toLocaleDateString("en-GB", {
      year: "numeric", month: "short", day: "numeric"
    });
  } catch { return isoStr; }
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, max) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}