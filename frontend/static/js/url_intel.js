// url_intel.js
// Client-side logic for the URL Intelligence dashboard page.
//
// FIXES IN THIS VERSION:
//   1. SSL "Valid?" — reads s.is_valid (not s.valid; "valid" key does not
//      exist in _ssl_check() return dict). Previous code was correct but
//      setBoolPill was passed undefined when is_valid=False because the
//      fallback ssl_data dict only had "has_ssl" and "is_valid" keys.
//      Confirmed: ssl_data always has is_valid as an explicit bool now.
//
//   2. domain_age_days / domain_age_flag — these are TOP-LEVEL keys in the
//      analyze_url() result, not nested inside the whois sub-dict.
//      renderUrlResult reads ui.domain_age_days and ui.domain_age_flag
//      (ui = module_results.url_intelligence), which is correct.
//
//   3. Organisation row (g-org) — was reading ui.asn as fallback because
//      "org" was never in the analyze_url() return dict. Now ui.org is
//      surfaced as a separate top-level key containing the full org string
//      (e.g. "AS13335 Cloudflare, Inc."), while ui.asn = "AS13335".
//
//   4. CDN detection — now reads ui.org (full string) for keyword matching
//      instead of ui.asn (prefix only).
//
// NEW IN THIS VERSION:
//   5. renderSubdomains() — renders the subdomain enumeration card.
//      Reads ui.subdomains (list of subdomain result objects).
//      Shows risk summary pills + full sortable table with per-subdomain
//      risk score, label, SSL validity, ML score, and flag names.
//      Card is hidden when no subdomains are returned.

"use strict";

// ─── Submit a single URL ─────────────────────────────────────────────────────

async function submitUrl() {
  const urlInput = document.getElementById("url-input");
  const url      = urlInput.value.trim();

  if (!url) {
    alert("Please enter a URL to analyze.");
    return;
  }

  if (!url.match(/^https?:\/\/.+/i) && !url.includes(".")) {
    alert("Please enter a valid URL (e.g. https://example.com)");
    return;
  }

  showSpinner(true, "Running WHOIS, SSL, DNS, ML checks, and subdomain enumeration...");
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
//
// analyze_url() response shape (wrapped in scan_router response):
// {
//   status, risk_score, label, recommended_action, explanation,
//   module_results: {
//     url_intelligence: {
//       raw_url, final_url, domain,
//       ip:      str,    country: str,   city: str,
//       org:     str,    asn:     str,   ← org is now a separate top-level key
//       whois:   { registrar, creation_date, expiry_date, ... },
//       dns:     { a_records, mx_records, ns_records, spf_policy, txt_records, ... },
//       ssl:     { has_ssl, is_valid, issuer, expires, days_to_expiry,
//                  is_expired, is_self_signed, san_mismatch, ... },
//       redirect_chain: [str],   redirect_count: int,
//       domain_age_days: int|null,   domain_age_flag: bool,
//       ml_result: { label, score, model },
//       flags: [{ flag, description, severity }],
//       subdomains: [{ subdomain, source, ip, resolves, risk_score,
//                      label, ml_score, ssl_valid, flags }],
//       risk_contribution: float
//     }
//   }
// }

function renderUrlResult(data) {
  const ui = (data.module_results || {}).url_intelligence || {};

  // ── URL header ──
  document.getElementById("result-url").textContent    = ui.raw_url || ui.final_url || "—";
  document.getElementById("result-domain").textContent = ui.domain  || "";

  // ── Risk badge + score bar ──
  const label = data.label || "UNKNOWN";
  const score = data.risk_score || 0;
  const badge = document.getElementById("risk-badge");
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
  flagsRow.innerHTML = (ui.flags || []).map(f => {
    const name = f.flag || f.description || "";
    const sev  = (f.severity || "low").toLowerCase();
    const cls  = sev === "high" ? "flag-pill flag-high"
               : sev === "medium" ? "flag-pill flag-medium"
               : "flag-pill flag-low";
    return `<span class="${cls}" title="${escapeHtml(f.description || "")}">${escapeHtml(name)}</span>`;
  }).join(" ");

  // ── WHOIS ──
  // creation_date and expiry_date are ISO strings stored inside the whois sub-dict.
  // domain_age_days and domain_age_flag are TOP-LEVEL keys (not inside whois).
  const w = ui.whois || {};
  setText("w-registrar", w.registrar || "—");
  setText("w-created",   w.creation_date  ? formatDate(w.creation_date)  : "—");
  setText("w-expires",   w.expiry_date    ? formatDate(w.expiry_date)    : "—");

  // FIX: domain_age_days is at ui (top-level of url_intelligence), not ui.whois
  const ageDays = ui.domain_age_days;
  setText("w-age", ageDays != null ? `${ageDays} days` : "—");

  const youngEl = document.getElementById("w-young");
  if (ui.domain_age_flag) {
    youngEl.innerHTML = '<span class="auth-pill auth-fail">Yes — under 6 months</span>';
  } else if (ageDays != null) {
    youngEl.innerHTML = '<span class="auth-pill auth-pass">No</span>';
  } else {
    youngEl.textContent = "—";
  }

  // ── SSL ──
  // _ssl_check() always returns "is_valid" (never "valid").
  // setBoolPill reads s.is_valid — will render pill correctly for both
  // true and false; previously rendered "—" when is_valid was falsy
  // because the old fallback ssl_data dict was missing the is_valid key.
  const s = ui.ssl || {};
  setBoolPill("s-https", s.has_ssl,         "HTTPS",         "HTTP only");
  setBoolPill("s-valid", s.is_valid,         "Valid",          "Invalid");
  setText("s-issuer",    s.issuer || "—");

  if (s.expires) {
    const daysLeft = s.days_to_expiry != null ? ` (${s.days_to_expiry} days)` : "";
    setText("s-expiry", formatDate(s.expires) + daysLeft);
  } else {
    setText("s-expiry", "—");
  }

  setBoolPill("s-self", s.is_self_signed, "Yes (⚠ risk)", "No", true);

  // Free cert = Let's Encrypt / ZeroSSL / Buypass
  const isFree = !!(s.issuer && (
    s.issuer.toLowerCase().includes("let's encrypt") ||
    s.issuer.toLowerCase().includes("letsencrypt")   ||
    s.issuer.toLowerCase().includes("zerossl")       ||
    s.issuer.toLowerCase().includes("buypass")       ||
    s.issuer.toLowerCase().includes("r3")            ||
    s.issuer.toLowerCase().includes("e1")
  ));
  setBoolPill("s-free", isFree, "Yes", "No", false, true);

  // ── IP / Geo ──
  // ip, country, city, org, asn are all flat top-level strings in ui.
  // FIX: g-org now reads ui.org (full org string like "AS13335 Cloudflare, Inc.")
  //      g-asn reads ui.asn ("AS13335" only)
  //      Previously both were reading ui.asn → Organisation showed "AS13335".
  setText("g-ip",      ui.ip      || "—");
  setText("g-country", ui.country || "—");
  setText("g-city",    ui.city    || "—");
  setText("g-org",     ui.org     || "—");   // FIX: was ui.asn
  setText("g-asn",     ui.asn     || "—");

  // CDN detection — FIX: now reads ui.org (full string) for keyword matching
  const cdnSource = (ui.org || ui.asn || "").toLowerCase();
  const isCdn = !!(cdnSource && (
    cdnSource.includes("cloudflare") ||
    cdnSource.includes("fastly")     ||
    cdnSource.includes("akamai")     ||
    cdnSource.includes("amazon")     ||
    cdnSource.includes("google")     ||
    cdnSource.includes("microsoft")  ||
    cdnSource.includes("cdn")
  ));
  setBoolPill("g-cdn", isCdn, "Yes (CDN)", "No", false, true);

  // ── DNS ──
  const d = ui.dns || {};

  const aRecs  = (d.a_records  || []).map(r => r.address || r).join(", ") || "—";
  const mxRecs = (d.mx_records || []).slice(0, 3)
                   .map(r => r.host || r).join("; ") || "—";
  const nsRecs = (d.ns_records || []).slice(0, 2).join(", ") || "—";

  setText("d-a",  aRecs);
  setText("d-mx", mxRecs);
  setText("d-ns", nsRecs);

  const hasSpf   = !!(d.spf_policy || (d.txt_records || []).some(t => t.startsWith("v=spf1")));
  const hasDmarc = (d.txt_records  || []).some(t => t.includes("v=DMARC1"));
  const freeNs   = (d.ns_records   || []).some(n =>
    ["freedns", "namecheap", "afraid", "cloudns", "1984"].some(f => n.includes(f))
  );

  setBoolPill("d-spf",     hasSpf,   "Present",    "Missing",    false, false);
  setBoolPill("d-dmarc",   hasDmarc, "Present",    "Missing",    false, false);
  setBoolPill("d-freedns", freeNs,   "Yes (note)", "No",         false, true);

  // ── Redirect chain ──
  // redirect_chain = flat list of URL strings; redirect_count = int (both top-level)
  const chain    = ui.redirect_chain || [];
  const hopCount = ui.redirect_count || chain.length || 0;

  const hopBadge = document.getElementById("hop-count");
  hopBadge.textContent = `${hopCount} hop${hopCount !== 1 ? "s" : ""}`;

  const chainDiv = document.getElementById("redirect-chain-display");
  if (chain.length === 0) {
    chainDiv.innerHTML = '<p class="empty-state">No redirects — URL resolves directly</p>';
  } else {
    chainDiv.innerHTML = `<div class="redirect-chain">
      ${chain.map((hopUrl, i) => `
        <div class="redirect-hop">
          <div class="hop-num">${i + 1}</div>
          <div class="hop-url">${escapeHtml(truncate(String(hopUrl), 80))}</div>
          <div class="hop-status status-3xx">→</div>
        </div>`).join("")}
    </div>`;
  }

  // ── ML result ──
  const ml = ui.ml_result || {};
  const verdictEl = document.getElementById("ml-verdict");
  verdictEl.textContent = ml.label || "—";
  verdictEl.style.color =
    ml.label === "MALICIOUS" ? "var(--red)"         :
    ml.label === "BENIGN"    ? "var(--green)"        :
    ml.label === "UNKNOWN"   ? "var(--text-muted)"   :
                               "var(--text-muted)";

  // ml.score is the phishing probability (0-1).
  // For BENIGN results this is near 0 (e.g. 0.03 for github.com).
  // Show it as phishing confidence — not as general confidence.
  const mlConf = Math.round((ml.score || 0) * 100);
  const mlBar  = document.getElementById("ml-conf-bar");
  mlBar.style.width = `${mlConf}%`;
  mlBar.className   = `confidence-bar-fill ${
    ml.label === "MALICIOUS" ? "fill-malicious" : "fill-safe"
  }`;
  // Show raw phishing % for clarity
  document.getElementById("ml-conf-label").textContent =
    ml.label === "BENIGN"
      ? `${100 - mlConf}% confidence (benign)`
      : `${mlConf}% confidence`;
  document.getElementById("ml-model-name").textContent = ml.model || "";

  // ── Subdomains (NEW) ──
  renderSubdomains(ui.subdomains || []);

  // ── Explanation ──
  document.getElementById("explanation-text").textContent =
    data.explanation || "—";

  // ── Show the card ──
  document.getElementById("result-card").style.display = "block";
  document.getElementById("result-card").scrollIntoView({ behavior: "smooth" });
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
}


// ─── Subdomain card renderer (NEW) ───────────────────────────────────────────
//
// Reads ui.subdomains which is a list of objects:
//   { subdomain, source, ip, resolves, risk_score, label, ml_score,
//     ssl_valid, flags }
//
// Shows:
//   - Count badges (total found / total resolving)
//   - Risk summary pills (how many SAFE / SUSPICIOUS / MALICIOUS)
//   - Full sortable table with one row per subdomain

function renderSubdomains(subdomains) {
  const card = document.getElementById("subdomain-card");

  if (!subdomains || subdomains.length === 0) {
    card.style.display = "none";
    return;
  }

  card.style.display = "block";

  const total    = subdomains.length;
  const resolves = subdomains.filter(s => s.resolves).length;
  const safe     = subdomains.filter(s => s.label === "SAFE").length;
  const susp     = subdomains.filter(s => s.label === "SUSPICIOUS").length;
  const mali     = subdomains.filter(s => s.label === "MALICIOUS").length;
  const unscored = subdomains.filter(s => s.label == null).length;

  // Count badges
  document.getElementById("subdomain-total-badge").textContent = `${total} found`;

  const resolvesBadge = document.getElementById("subdomain-resolve-badge");
  resolvesBadge.textContent = `${resolves} resolve`;
  resolvesBadge.style.display = "inline";

  // Risk summary pills
  const summaryDiv = document.getElementById("subdomain-risk-summary");
  const pills = [];
  if (mali   > 0) pills.push(`<span class="label-badge label-malicious">${mali} malicious</span>`);
  if (susp   > 0) pills.push(`<span class="label-badge label-suspicious">${susp} suspicious</span>`);
  if (safe   > 0) pills.push(`<span class="label-badge label-safe">${safe} safe</span>`);
  if (unscored > 0) pills.push(`<span class="label-badge label-unknown">${unscored} unresolved/unscored</span>`);
  summaryDiv.innerHTML = pills.join(" ");

  // Source note
  const sources = [...new Set(subdomains.map(s => s.source))];
  const sourceMap = { crtsh: "crt.sh (CT logs)", bruteforce: "DNS brute-force", both: "crt.sh + DNS" };
  const sourceNote = sources.map(src => sourceMap[src] || src).join(" · ");
  document.getElementById("subdomain-source-note").textContent =
    `Sources: ${sourceNote}`;

  // Table body
  const tbody = document.getElementById("subdomain-table-body");
  tbody.innerHTML = subdomains.map(sd => {
    const labelClass = sd.label ? sd.label.toLowerCase() : "unknown";
    const riskScore  = sd.risk_score != null ? sd.risk_score.toFixed(1) : "—";
    const mlScore    = sd.ml_score   != null ? sd.ml_score.toFixed(3)  : "—";

    // Source badge
    const srcBadge = sd.source === "both"
      ? '<span class="auth-pill auth-pass">CT + DNS</span>'
      : sd.source === "crtsh"
        ? '<span class="auth-pill auth-none">crt.sh</span>'
        : '<span class="auth-pill auth-none">brute-force</span>';

    // Resolves pill
    const resolvesPill = sd.resolves
      ? '<span class="auth-pill auth-pass">Yes</span>'
      : '<span class="auth-pill auth-fail">No</span>';

    // SSL pill (only meaningful if subdomain resolves)
    let sslPill = "—";
    if (sd.resolves) {
      sslPill = sd.ssl_valid
        ? '<span class="auth-pill auth-pass">valid</span>'
        : '<span class="auth-pill auth-fail">invalid</span>';
    }

    // ML score pill
    let mlPill = `<span class="score-pill score-${labelClass}">${mlScore}</span>`;

    // Risk score pill
    let riskPill;
    if (sd.risk_score != null) {
      const fillClass = sd.risk_score < 30 ? "fill-safe"
                      : sd.risk_score < 70 ? "fill-suspicious"
                      : "fill-malicious";
      riskPill = `<span class="score-pill ${fillClass}">${riskScore}</span>`;
    } else {
      riskPill = "—";
    }

    // Label badge
    const labelBadge = sd.label
      ? `<span class="label-badge label-${labelClass}">${sd.label}</span>`
      : "—";

    // Flags — compact comma list, capped at 3
    const flagList = (sd.flags || []).filter(Boolean).slice(0, 3);
    const flagsCell = flagList.length > 0
      ? `<span class="flags-compact" title="${escapeHtml((sd.flags || []).join(', '))}">${flagList.map(escapeHtml).join(", ")}</span>`
      : "—";

    // IP
    const ipCell = sd.ip || "—";

    return `<tr class="${sd.label === "MALICIOUS" ? "row-malicious" : sd.label === "SUSPICIOUS" ? "row-suspicious" : ""}">
      <td><code class="subdomain-name">${escapeHtml(sd.subdomain)}</code></td>
      <td>${srcBadge}</td>
      <td><code>${escapeHtml(ipCell)}</code></td>
      <td>${resolvesPill}</td>
      <td>${sslPill}</td>
      <td>${mlPill}</td>
      <td>${riskPill}</td>
      <td>${labelBadge}</td>
      <td class="flags-cell">${flagsCell}</td>
    </tr>`;
  }).join("");
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
      const labelClass = (s.final_label || "unknown").toLowerCase();
      const sslBadge   = s.ssl_valid
        ? '<span class="auth-pill auth-pass">valid</span>'
        : '<span class="auth-pill auth-fail">invalid</span>';
      const ageBadge   = s.domain_age_days != null
        ? `<span class="${s.domain_age_days < 180 ? "text-danger" : ""}">${s.domain_age_days}</span>`
        : "—";

      return `<tr>
        <td class="truncate" title="${escapeHtml(s.raw_url || "")}">
          <code>${escapeHtml(s.domain || "—")}</code>
        </td>
        <td>${escapeHtml(s.ip_address || "—")}</td>
        <td>${escapeHtml(s.country    || "—")}</td>
        <td>${ageBadge}</td>
        <td>${sslBadge}</td>
        <td>
          <span class="score-pill score-${labelClass}">
            ${(s.ml_score || 0).toFixed(2)}
          </span>
        </td>
        <td>
          <span class="label-badge label-${labelClass}">
            ${escapeHtml(s.final_label || "—")}
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
  if (msg) {
    const msgEl = document.getElementById("spinner-msg");
    if (msgEl) msgEl.textContent = msg;
  }
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
 * Set a cell to a coloured pass/fail pill based on a boolean.
 *
 * @param {string}  id              - element id
 * @param {*}       bool            - value to test (truthy/falsy)
 * @param {string}  trueLabel       - text when truthy
 * @param {string}  falseLabel      - text when falsy
 * @param {boolean} warningOnTrue   - show amber (auth-fail) instead of green when truthy
 * @param {boolean} neutralOnTrue   - show grey (auth-none) instead of green when truthy
 *
 * Renders "—" only when bool is strictly null or undefined.
 * Explicit false → falseLabel pill (auth-fail).
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
    const cls = neutralOnTrue  ? "auth-none"
              : warningOnTrue  ? "auth-fail"
              : "auth-pass";
    el.innerHTML = `<span class="auth-pill ${cls}">${escapeHtml(trueLabel)}</span>`;
  } else {
    // Explicit false → always auth-fail pill (never "—")
    el.innerHTML = `<span class="auth-pill auth-fail">${escapeHtml(falseLabel)}</span>`;
  }
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  try {
    // Handle both ISO strings ("2007-10-09T00:00:00") and
    // space-separated format ("2007-10-09 00:00:00") from WHOIS
    const d = new Date(isoStr.replace(" ", "T"));
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleDateString("en-GB", {
      year: "numeric", month: "short", day: "numeric"
    });
  } catch { return isoStr; }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, max) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}