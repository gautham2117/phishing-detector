// url_intel.js
// Client-side logic for the URL Intelligence dashboard page.
//
// CHANGES IN THIS VERSION:
//   1. Explanation card replaced by 3-tab panel:
//        Tab 1 — Overview: risk narrative, action, key signals
//        Tab 2 — Domain Details: collapsible WHOIS/SSL/DNS/geo/redirect sections
//        Tab 3 — Flags & ML: per-flag plain-English cards + ML detail + typosquatting
//   2. renderTyposquatting() now also populates #w-typosquat inline in WHOIS table
//   3. matched_token field used in typosquatting explanation
//   4. switchExpTab() exported to global scope for onclick= handlers
//   All existing functions (renderCertTransparency, renderSubdomains,
//   refreshHistory, helpers) are unchanged.

"use strict";

// ─── Submit a single URL ─────────────────────────────────────────────────────

async function submitUrl() {
  const urlInput = document.getElementById("url-input");
  const url      = urlInput.value.trim();

  if (!url) { alert("Please enter a URL to analyze."); return; }
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
    if (!response.ok) { alert(`Error: ${data.error || response.statusText}`); return; }
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
  document.getElementById("flags-row").innerHTML = (ui.flags || []).map(f => {
    const name = f.flag || f.description || "";
    const sev  = (f.severity || "low").toLowerCase();
    const cls  = sev === "high" ? "flag-pill flag-high"
               : sev === "medium" ? "flag-pill flag-medium"
               : "flag-pill flag-low";
    return `<span class="${cls}" title="${escapeHtml(f.description || "")}">${escapeHtml(name)}</span>`;
  }).join(" ");

  // ── WHOIS ──
  const w = ui.whois || {};
  setText("w-registrar", w.registrar || "—");
  setText("w-created",   w.creation_date ? formatDate(w.creation_date) : "—");
  setText("w-expires",   w.expiry_date   ? formatDate(w.expiry_date)   : "—");
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
  const s = ui.ssl || {};
  setBoolPill("s-https", s.has_ssl,      "HTTPS",         "HTTP only");
  setBoolPill("s-valid", s.is_valid,     "Valid",          "Invalid");
  setText("s-issuer",    s.issuer || "—");
  if (s.expires) {
    const daysLeft = s.days_to_expiry != null ? ` (${s.days_to_expiry} days)` : "";
    setText("s-expiry", formatDate(s.expires) + daysLeft);
  } else {
    setText("s-expiry", "—");
  }
  setBoolPill("s-self", s.is_self_signed, "Yes (⚠ risk)", "No", true);
  const isFree = !!(s.issuer && (
    s.issuer.toLowerCase().includes("let's encrypt") ||
    s.issuer.toLowerCase().includes("letsencrypt")   ||
    s.issuer.toLowerCase().includes("zerossl")       ||
    s.issuer.toLowerCase().includes("buypass")       ||
    s.issuer.toLowerCase().includes("r3")            ||
    s.issuer.toLowerCase().includes("e1")
  ));
  setBoolPill("s-free", isFree, "Yes", "No", false, true);

  // ── Cert transparency ──
  renderCertTransparency(ui);

  // ── IP / Geo ──
  setText("g-ip",      ui.ip      || "—");
  setText("g-country", ui.country || "—");
  setText("g-city",    ui.city    || "—");
  setText("g-org",     ui.org     || "—");
  setText("g-asn",     ui.asn     || "—");
  const cdnSource = (ui.org || ui.asn || "").toLowerCase();
  const isCdn = !!(cdnSource && (
    cdnSource.includes("cloudflare") || cdnSource.includes("fastly") ||
    cdnSource.includes("akamai")     || cdnSource.includes("amazon") ||
    cdnSource.includes("google")     || cdnSource.includes("microsoft") ||
    cdnSource.includes("cdn")
  ));
  setBoolPill("g-cdn", isCdn, "Yes (CDN)", "No", false, true);

  // ── DNS ──
  const d = ui.dns || {};
  setText("d-a",  (d.a_records  || []).map(r => r.address || r).join(", ") || "—");
  setText("d-mx", (d.mx_records || []).slice(0, 3).map(r => r.host || r).join("; ") || "—");
  setText("d-ns", (d.ns_records || []).slice(0, 2).join(", ") || "—");
  const hasSpf   = !!(d.spf_policy || (d.txt_records || []).some(t => t.startsWith("v=spf1")));
  const hasDmarc = (d.txt_records  || []).some(t => t.includes("v=DMARC1"));
  const freeNs   = (d.ns_records   || []).some(n =>
    ["freedns","namecheap","afraid","cloudns","1984"].some(f => n.includes(f))
  );
  setBoolPill("d-spf",     hasSpf,   "Present", "Missing", false, false);
  setBoolPill("d-dmarc",   hasDmarc, "Present", "Missing", false, false);
  setBoolPill("d-freedns", freeNs,   "Yes (note)", "No",   false, true);

  // ── Redirect chain ──
  const chain    = ui.redirect_chain || [];
  const hopCount = ui.redirect_count || chain.length || 0;
  document.getElementById("hop-count").textContent = `${hopCount} hop${hopCount !== 1 ? "s" : ""}`;
  const chainDiv = document.getElementById("redirect-chain-display");
  if (!chain.length) {
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
    ml.label === "MALICIOUS" ? "var(--red)"  :
    ml.label === "BENIGN"    ? "var(--green)" : "var(--text-muted)";
  const mlConf = Math.round((ml.score || 0) * 100);
  const mlBar  = document.getElementById("ml-conf-bar");
  mlBar.style.width = `${mlConf}%`;
  mlBar.className   = `confidence-bar-fill ${ml.label === "MALICIOUS" ? "fill-malicious" : "fill-safe"}`;
  document.getElementById("ml-conf-label").textContent =
    ml.label === "BENIGN" ? `${100 - mlConf}% confidence (benign)` : `${mlConf}% confidence`;
  document.getElementById("ml-model-name").textContent = ml.model || "";

  // ── Typosquatting (inline WHOIS row + later used in tab 3) ──
  renderTyposquatting(ui);

  // ── Subdomains ──
  renderSubdomains(ui.subdomains || []);

  // ── 3-tab explanation panel ──
  renderExplanationTabs(ui, data);

  // ── Show card ──
  document.getElementById("result-card").style.display = "block";
  document.getElementById("result-card").scrollIntoView({ behavior: "smooth" });
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();

  // Reset to Overview tab on each new scan
  switchExpTab("overview");
}


// ═══════════════════════════════════════════════════════════════════════════════
// 3-TAB EXPLANATION PANEL
// ═══════════════════════════════════════════════════════════════════════════════

function switchExpTab(tabName) {
  document.querySelectorAll(".exp-tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });
  document.querySelectorAll(".exp-tab-content").forEach(panel => {
    panel.classList.toggle("active", panel.id === `exp-tab-${tabName}`);
  });
}

function renderExplanationTabs(ui, data) {
  _renderOverviewTab(ui, data);
  _renderDomainDetailsTab(ui);
  _renderFlagsMLTab(ui);
}


// ─── Tab 1: Overview ──────────────────────────────────────────────────────────

function _renderOverviewTab(ui, data) {
  const el    = document.getElementById("exp-overview-body");
  const label = (data.label || "UNKNOWN").toLowerCase();
  const score = data.risk_score || 0;
  const flags = ui.flags || [];
  const typo  = ui.typosquatting || {};
  const ct    = ui.cert_transparency || {};
  const ml    = ui.ml_result || {};

  const bannerMeta = {
    safe:       { icon: "✅", label: "Safe",        color: "var(--green)", cls: "banner-safe" },
    suspicious: { icon: "⚠️",  label: "Suspicious",  color: "var(--amber)", cls: "banner-suspicious" },
    malicious:  { icon: "🚨", label: "Malicious",   color: "var(--red)",   cls: "banner-malicious" },
    unknown:    { icon: "❓", label: "Unknown",     color: "var(--text-muted)", cls: "banner-unknown" },
  };
  const bm = bannerMeta[label] || bannerMeta.unknown;

  const actionMeta = {
    ALLOW:      { label: "Allow",       cls: "action-allow",       icon: "✅" },
    WARN:       { label: "Review",      cls: "action-warn",        icon: "⚠️"  },
    QUARANTINE: { label: "Quarantine",  cls: "action-quarantine",  icon: "🚨" },
  };
  const am = actionMeta[data.recommended_action || "WARN"] || actionMeta.WARN;

  // Update tab badge (flag count)
  const flagBadgeEl = document.getElementById("exp-badge-flags");
  if (flagBadgeEl) flagBadgeEl.textContent = flags.length || "";
  const mlBadgeEl = document.getElementById("exp-badge-ml");
  if (mlBadgeEl) mlBadgeEl.textContent =
    ml.label === "MALICIOUS" ? "⚠" : "";

  // Build narrative paragraphs
  const narratives = _buildUrlNarrative(ui, data, label, score, flags, typo, ct, ml);

  el.innerHTML = `
    <div class="exp-risk-banner ${bm.cls}">
      <div class="exp-banner-icon">${bm.icon}</div>
      <div class="exp-banner-text">
        <h3 style="color:${bm.color}">${escapeHtml(ui.domain || "Domain")} — ${bm.label}</h3>
        <p>Risk score ${score.toFixed(1)}/100
          · ${flags.length} flag${flags.length !== 1 ? "s" : ""}
          · ML: ${escapeHtml(ml.label || "UNKNOWN")}
          ${typo.is_typosquatting_suspect ? "· ⚠ Typosquatting detected" : ""}
        </p>
      </div>
    </div>

    <div class="exp-section">
      <div class="exp-section-label">Risk Narrative</div>
      ${narratives.map(n => `<p class="exp-narrative-para">${escapeHtml(n)}</p>`).join("")}
    </div>

    <hr class="exp-divider">

    <div class="exp-section">
      <div class="exp-section-label">Recommended Action</div>
      <span class="exp-action-pill ${am.cls}">${am.icon} ${am.label}</span>
      ${label === "malicious" ? `
        <p class="exp-narrative-para" style="margin-top:10px;color:var(--red)">
          Do not click any links, open any attachments, or enter any credentials on this domain.
          Quarantine any emails containing this URL and report to your security team.
        </p>` : label === "suspicious" ? `
        <p class="exp-narrative-para" style="margin-top:10px">
          Treat with caution. Do not submit credentials. Verify the domain with the
          legitimate organisation through an independent channel before proceeding.
        </p>` : ""}
    </div>
  `;
}

function _buildUrlNarrative(ui, data, label, score, flags, typo, ct, ml) {
  const parts   = [];
  const domain  = ui.domain || "the domain";
  const ageDays = ui.domain_age_days;

  // Sentence 1 — overall verdict
  if (label === "safe") {
    parts.push(
      `Analysis of ${domain} returned a risk score of ${score.toFixed(1)}/100, ` +
      `classified as SAFE. No high-severity indicators were detected across WHOIS, SSL, ` +
      `DNS, redirect chain, and ML classification checks.`
    );
  } else if (label === "suspicious") {
    const highFlags = flags.filter(f => f.severity === "high");
    parts.push(
      `${domain} scored ${score.toFixed(1)}/100 — classified as SUSPICIOUS. ` +
      `${highFlags.length} high-severity flag${highFlags.length !== 1 ? "s" : ""} ` +
      `${highFlags.length > 0
        ? `(${highFlags.slice(0, 2).map(f => f.flag).join(", ")})`
        : ""} ` +
      `were detected. While not conclusively malicious, this domain warrants caution.`
    );
  } else if (label === "malicious") {
    parts.push(
      `${domain} scored ${score.toFixed(1)}/100 — classified as MALICIOUS. ` +
      `Multiple strong phishing indicators were detected. This domain should be ` +
      `blocked and any associated emails quarantined immediately.`
    );
  } else {
    parts.push(`Analysis of ${domain} returned score ${score.toFixed(1)}/100 (${label.toUpperCase()}).`);
  }

  // Sentence 2 — domain age
  if (ageDays != null && ageDays < 180) {
    parts.push(
      `The domain is only ${ageDays} day${ageDays !== 1 ? "s" : ""} old. ` +
      `Domains registered less than 6 months ago are disproportionately associated ` +
      `with phishing campaigns — attackers register fresh domains specifically to avoid blocklists.`
    );
  }

  // Sentence 3 — typosquatting
  if (typo.is_typosquatting_suspect) {
    const tok  = typo.matched_token || typo.closest_brand || "";
    const dist = typo.edit_distance;
    const tech = typo.technique || "";
    parts.push(
      `Typosquatting detected: the token "${tok}" in this domain closely resembles ` +
      `"${typo.closest_brand}" (edit distance: ${dist}, technique: ${tech}). ` +
      `This is a strong signal that the domain was registered to impersonate a trusted brand.`
    );
  }

  // Sentence 4 — cert transparency
  if (ct.is_freshly_certified) {
    parts.push(
      `The SSL certificate was issued only ${ct.days_since_issued} day${ct.days_since_issued !== 1 ? "s" : ""} ago. ` +
      `Freshly issued certificates are a common phishing signal — attackers obtain ` +
      `free TLS certs immediately after registering a throwaway domain.`
    );
  }

  // Sentence 5 — ML
  if (ml.label === "MALICIOUS") {
    const conf = Math.round((ml.score || 0) * 100);
    parts.push(
      `The BERT URL classifier flagged this URL as malicious with ${conf}% confidence. ` +
      `This model was trained to detect phishing, malware distribution, and command-and-control URLs.`
    );
  }

  // Sentence 6 — SSL issues
  const s = ui.ssl || {};
  if (!s.has_ssl) {
    parts.push(
      `The domain does not serve HTTPS. Any data submitted on this domain is transmitted ` +
      `in plain text and can be intercepted. Legitimate services never collect credentials over HTTP.`
    );
  } else if (s.is_self_signed) {
    parts.push(
      `The SSL certificate is self-signed (not issued by a trusted Certificate Authority). ` +
      `This means the identity of the server cannot be verified — anyone could have generated it.`
    );
  }

  // Sentence 7 — clean bill if nothing found
  if (parts.length === 1 && label === "safe") {
    parts.push(
      `WHOIS shows a ${ageDays != null ? ageDays + "-day-old" : "registered"} domain ` +
      `with a valid SSL certificate${s.issuer ? " from " + s.issuer : ""}. ` +
      `DNS records appear standard and no redirect anomalies were observed.`
    );
  }

  return parts;
}


// ─── Tab 2: Domain Details ────────────────────────────────────────────────────

function _renderDomainDetailsTab(ui) {
  const el = document.getElementById("exp-domaindetails-body");

  const w      = ui.whois || {};
  const s      = ui.ssl   || {};
  const d      = ui.dns   || {};
  const chain  = ui.redirect_chain || [];
  const ageDays = ui.domain_age_days;

  const sections = [
    {
      icon: "📋", label: "WHOIS & Registration",
      id:   "dd-whois",
      rows: [
        ["Registrar",     w.registrar     || "Not available"],
        ["Created",       w.creation_date ? formatDate(w.creation_date) : "Unknown"],
        ["Expires",       w.expiry_date   ? formatDate(w.expiry_date)   : "Unknown"],
        ["Domain age",    ageDays != null ? `${ageDays} days${ageDays < 180 ? " ⚠ young" : ""}` : "Unknown"],
        ["Organisation",  w.org           || "Not listed"],
        ["Country",       w.country       || "Not listed"],
      ],
      note: ageDays != null && ageDays < 180
        ? { text: `Domain is ${ageDays} days old — domains under 6 months are strongly associated with phishing. Legitimate brands use domains that are years old.`, cls: "note-warn" }
        : !w.registrar
        ? { text: "WHOIS returned no registrar data — domain may use privacy protection or have a restricted registry.", cls: "" }
        : { text: `Domain has been registered for ${ageDays} days — no age-related concerns.`, cls: "note-ok" },
    },
    {
      icon: "🔒", label: "SSL / TLS Certificate",
      id:   "dd-ssl",
      rows: [
        ["Has HTTPS",     s.has_ssl    ? "✅ Yes" : "❌ No — HTTP only"],
        ["Certificate",   s.is_valid   ? "✅ Valid" : "❌ Invalid"],
        ["Issuer",        s.issuer     || "N/A"],
        ["Expires",       s.expires    ? formatDate(s.expires) + (s.days_to_expiry != null ? ` (${s.days_to_expiry} days)` : "") : "N/A"],
        ["Self-signed",   s.is_self_signed ? "⚠ Yes" : "No"],
        ["SAN mismatch",  s.san_mismatch   ? "⚠ Yes" : "No"],
        ["CT issued",     ui.cert_transparency?.issued_date ? formatDate(ui.cert_transparency.issued_date) : "Unknown"],
        ["Fresh cert",    ui.cert_transparency?.is_freshly_certified ? `⚠ Yes — ${ui.cert_transparency.days_since_issued} days ago` : "No"],
      ],
      note: !s.has_ssl
        ? { text: "No HTTPS detected. All data sent to this domain is unencrypted and can be intercepted. Login forms over HTTP are a major red flag.", cls: "note-critical" }
        : s.is_self_signed
        ? { text: "Self-signed certificate — the server identity cannot be verified by a trusted third party. This is common on phishing sites that want HTTPS without paying for a trusted cert.", cls: "note-warn" }
        : s.is_valid
        ? { text: `Valid certificate issued by ${s.issuer || "a trusted CA"}. SSL alone does not prove the site is safe — phishers also use valid free certs.`, cls: "note-ok" }
        : { text: "SSL certificate is invalid. Do not enter credentials.", cls: "note-critical" },
    },
    {
      icon: "🌐", label: "DNS & Email Infrastructure",
      id:   "dd-dns",
      rows: [
        ["A records",   (d.a_records  || []).map(r => r.address || r).join(", ") || "None"],
        ["MX records",  (d.mx_records || []).map(r => r.host || r).join("; ")   || "None — no email"],
        ["NS records",  (d.ns_records || []).join(", ")                          || "Unknown"],
        ["SPF policy",  d.spf_policy  || "Missing"],
        ["Has DMARC",   (d.txt_records || []).some(t => t.includes("v=DMARC1")) ? "Yes" : "Missing"],
      ],
      note: !d.spf_policy && !(d.txt_records || []).some(t => t.includes("v=DMARC1"))
        ? { text: "No SPF or DMARC records. This domain has no email authentication, meaning attackers can easily forge emails appearing to come from it.", cls: "note-warn" }
        : { text: "Email authentication records present. This reduces the risk of domain spoofing in email.", cls: "note-ok" },
    },
    {
      icon: "🌍", label: "IP & Geolocation",
      id:   "dd-geo",
      rows: [
        ["IP address",   ui.ip      || "Unresolved"],
        ["Country",      ui.country || "Unknown"],
        ["City",         ui.city    || "Unknown"],
        ["Organisation", ui.org     || "Unknown"],
        ["ASN",          ui.asn     || "Unknown"],
      ],
      note: null,
    },
    {
      icon: "↩", label: `Redirect Chain (${chain.length} hop${chain.length !== 1 ? "s" : ""})`,
      id:   "dd-redirect",
      rows: chain.length
        ? chain.map((h, i) => [`Hop ${i + 1}`, truncate(String(h), 70)])
        : [["Status", "No redirects — URL resolves directly"]],
      note: chain.length > 2
        ? { text: `${chain.length} redirect hops before final destination. Long chains are used to route victims through trusted domains before landing on a phishing page.`, cls: "note-warn" }
        : chain.length > 0
        ? { text: "Short redirect chain — common for legitimate URL shorteners and analytics tracking.", cls: "" }
        : null,
    },
  ];

  el.innerHTML = sections.map(sec => `
    <div class="dd-section">
      <div class="dd-section-header" onclick="toggleDdSection('${sec.id}')">
        <span>${sec.icon}</span>
        <span>${sec.label}</span>
        <span class="dd-chevron" id="dd-chv-${sec.id}">▶</span>
      </div>
      <div class="dd-section-body" id="${sec.id}">
        <div class="dd-kv-grid">
          ${sec.rows.map(([k, v]) => `
            <span class="dd-kv-label">${escapeHtml(k)}</span>
            <span class="dd-kv-value">${escapeHtml(String(v || "—"))}</span>
          `).join("")}
        </div>
        ${sec.note ? `<div class="dd-note ${sec.note.cls || ""}">${escapeHtml(sec.note.text)}</div>` : ""}
      </div>
    </div>`).join("");
}

function toggleDdSection(id) {
  const body    = document.getElementById(id);
  const chevron = document.getElementById(`dd-chv-${id}`);
  if (!body) return;
  const isOpen = body.classList.contains("open");
  body.classList.toggle("open", !isOpen);
  if (chevron) chevron.classList.toggle("open", !isOpen);
}


// ─── Tab 3: Flags & ML ────────────────────────────────────────────────────────

function _renderFlagsMLTab(ui) {
  const el    = document.getElementById("exp-flagsml-body");
  const flags = ui.flags || [];
  const ml    = ui.ml_result || {};
  const typo  = ui.typosquatting || {};

  // Per-flag plain-English explanation lookup
  const flagExplanations = {
    "long_url":           "Excessively long URLs are used to hide the real destination domain by pushing it beyond what's visible. Phishing URLs often embed base64-encoded redirects or fake domain prefixes.",
    "ip_address_url":     "Legitimate services never ask users to visit a raw IP address. This technique bypasses domain-based blocklists and is almost exclusively used for phishing and malware distribution.",
    "suspicious_tld":     "This TLD is disproportionately used for throwaway phishing domains because registrations are free or very cheap. Legitimate businesses rarely use these TLDs.",
    "deep_subdomains":    "Multiple subdomain levels are used to make phishing URLs look more legitimate — e.g. account.secure.paypal.com.evil.xyz. The real domain is always the last two labels before the TLD.",
    "long_redirect_chain":"Long redirect chains route victims through trusted or CDN domains to evade URL filters, before finally landing on the phishing page.",
    "young_domain":       "Newly registered domains are strongly associated with phishing — attackers register fresh domains specifically to avoid existing blocklists and reputational filters.",
    "no_whois":           "No registrar data in WHOIS. This may indicate privacy protection (common for legitimate sites) or a domain registered through an obscure/offshore registrar.",
    "no_https":           "The domain does not serve HTTPS. Any data entered on this site is transmitted in plain text. No legitimate service should collect credentials over HTTP.",
    "expired_cert":       "The SSL certificate has expired. A responsible operator would not let this happen on an active site — this may indicate an abandoned domain repurposed for phishing.",
    "self_signed_cert":   "Self-signed certificates are generated by the server itself without verification from a trusted Certificate Authority. Phishers use them to get HTTPS without paying for a real cert.",
    "ssl_san_mismatch":   "The certificate's Subject Alternative Names do not include this domain. The cert was issued for a different domain — a major red flag for phishing.",
    "ml_malicious":       "The BERT machine learning classifier, trained on millions of phishing and malware URLs, assigned a high malicious probability to this URL based on its structural patterns.",
  };

  let html = "";

  if (!flags.length) {
    html += `
      <div class="clean-banner">
        <div class="clean-banner-icon">✅</div>
        <div>
          <strong>No flags triggered.</strong><br>
          <span style="font-size:12px;color:var(--text-muted)">
            All automated heuristic checks passed for this domain.
            Always combine automated results with manual verification.
          </span>
        </div>
      </div>`;
  } else {
    html += flags.map(f => {
      const sev  = (f.severity || "low").toLowerCase();
      const name = f.flag || f.description || "";
      const expl = flagExplanations[f.flag] || f.description || "No additional detail available.";
      return `
        <div class="flag-detail-card">
          <div class="flag-detail-header">
            <span class="flag-sev-chip chip-${sev}">${sev.toUpperCase()}</span>
            <span style="font-weight:600">${escapeHtml(name)}</span>
          </div>
          <div class="flag-detail-body">${escapeHtml(expl)}</div>
        </div>`;
    }).join("");
  }

  // ML detail box
  const mlConf = Math.round((ml.score || 0) * 100);
  html += `
    <div class="ml-detail-box">
      <h4>ML Classifier — ${escapeHtml(ml.model || "BERT")}</h4>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
        <span style="font-size:16px;font-weight:700;color:${
          ml.label === "MALICIOUS" ? "var(--red)" :
          ml.label === "BENIGN"    ? "var(--green)" : "var(--text-muted)"
        }">${escapeHtml(ml.label || "UNKNOWN")}</span>
        <div class="confidence-bar-track" style="width:160px;height:6px">
          <div class="confidence-bar-fill ${ml.label === "MALICIOUS" ? "fill-malicious" : "fill-safe"}"
               style="width:${mlConf}%;height:100%"></div>
        </div>
        <span style="font-size:12px;color:var(--text-muted)">${mlConf}% confidence</span>
      </div>
      <p style="font-size:12px;color:var(--text-muted);line-height:1.65;margin:0">
        ${ml.label === "MALICIOUS"
          ? `The model assigned ${mlConf}% malicious probability. This is based on structural URL patterns — subdomain depth, token entropy, TLD risk, and character composition — that match known phishing and malware URLs in the training data.`
          : ml.label === "BENIGN"
          ? `The model assigned ${100 - mlConf}% benign probability. The URL's structural features resemble known-safe domains. Note that ML alone is not sufficient — always cross-reference with WHOIS age, SSL, and redirect data.`
          : "Model was unavailable or returned an inconclusive result. Manual verification is recommended."}
      </p>
    </div>`;

  // Typosquatting detail box
  if (typo.is_typosquatting_suspect) {
    const candidates = typo.candidates || [];
    html += `
      <div class="typo-detail-box">
        <h4>Typosquatting Analysis</h4>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;">
          <span style="color:var(--red);font-weight:700;font-size:13px">SUSPECT</span>
          <span style="font-size:12px;color:var(--text-muted)">
            Closest brand: <strong>${escapeHtml(typo.closest_brand)}</strong>
            · Edit distance: <strong>${typo.edit_distance}</strong>
            · Technique: <em>${escapeHtml(typo.technique)}</em>
            ${typo.matched_token ? `· Matched token: <code>${escapeHtml(typo.matched_token)}</code>` : ""}
          </span>
        </div>
        ${candidates.length > 1 ? `
        <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;">
          <thead>
            <tr style="color:var(--text-muted);text-align:left;border-bottom:1px solid var(--border)">
              <th style="padding:4px 8px">Brand</th>
              <th style="padding:4px 8px">Token</th>
              <th style="padding:4px 8px">Distance</th>
              <th style="padding:4px 8px">Technique</th>
              <th style="padding:4px 8px">Risk</th>
            </tr>
          </thead>
          <tbody>
            ${candidates.map(c => `
            <tr style="border-bottom:1px solid rgba(42,38,80,.4)">
              <td style="padding:4px 8px;font-weight:600">${escapeHtml(c.brand)}</td>
              <td style="padding:4px 8px;font-family:monospace">${escapeHtml(c.matched_token || "—")}</td>
              <td style="padding:4px 8px">${c.edit_distance}</td>
              <td style="padding:4px 8px">${escapeHtml(c.technique)}</td>
              <td style="padding:4px 8px">
                <span class="label-badge ${c.risk === "HIGH" ? "label-malicious" : "label-suspicious"}">
                  ${escapeHtml(c.risk)}
                </span>
              </td>
            </tr>`).join("")}
          </tbody>
        </table>` : ""}
      </div>`;
  }

  el.innerHTML = html;
}


// ─── Cert transparency renderer ───────────────────────────────────────────────

function renderCertTransparency(ui) {
  const ct = ui.cert_transparency || {};

  const issuedEl = document.getElementById("s-ct-issued");
  if (issuedEl) issuedEl.textContent = ct.issued_date ? formatDate(ct.issued_date) : "—";

  const freshEl = document.getElementById("s-ct-fresh");
  if (!freshEl) return;

  if (ct.issued_date === undefined && ct.is_freshly_certified === undefined) {
    freshEl.textContent = "—";
    return;
  }

  if (ct.is_freshly_certified) {
    const days = ct.days_since_issued != null ? ct.days_since_issued : "?";
    freshEl.innerHTML = `
      <span class="ct-fresh-badge ct-fresh-warn">⚠ Yes — ${days} day${days !== 1 ? "s" : ""} ago</span>
      <span style="font-size:.75rem;color:var(--text-muted);margin-left:6px">
        Freshly issued certs are a common phishing indicator
      </span>`;
  } else {
    const days = ct.days_since_issued != null ? ` (${ct.days_since_issued} days ago)` : "";
    freshEl.innerHTML = `<span class="ct-fresh-badge ct-fresh-ok">No${days}</span>`;
  }
}


// ─── Typosquatting renderer ───────────────────────────────────────────────────
// Populates:
//   #w-typosquat  — inline row in the WHOIS card (always)
//   #typosquat-card — the dedicated card below (if present in DOM)

function renderTyposquatting(ui) {
  const typo   = ui.typosquatting;
  const domain = ui.domain || "";

  // ── Inline WHOIS row ──────────────────────────────────────────────────
  const inlineEl = document.getElementById("w-typosquat");
  if (inlineEl) {
    if (!typo) {
      inlineEl.textContent = "—";
    } else if (typo.is_typosquatting_suspect) {
      const dist = typo.edit_distance != null ? typo.edit_distance : "?";
      inlineEl.innerHTML = `
        <span class="typo-inline-suspect">
          ⚠ Suspect — resembles "${escapeHtml(typo.closest_brand)}"
          (dist: ${dist})
        </span>`;
    } else {
      inlineEl.innerHTML = `<span class="typo-inline-clean">✅ Clean</span>`;
    }
  }

  // ── Dedicated typosquat card (from original JS — keep for backwards compat) ──
  const card = document.getElementById("typosquat-card");
  if (!card) return;

  if (!typo) { card.style.display = "none"; return; }

  card.style.display = "block";

  const suspect = typo.is_typosquatting_suspect;
  const brand   = typo.closest_brand   || "";
  const dist    = typo.edit_distance   != null ? typo.edit_distance : "—";
  const tech    = typo.technique       || "—";

  const verdictBadge = document.getElementById("typosquat-verdict-badge");
  if (verdictBadge) {
    verdictBadge.textContent = suspect ? "SUSPECT" : "Clean";
    verdictBadge.className   = `typosquat-verdict-badge ${suspect ? "typo-suspect" : "typo-clean"}`;
  }

  if (suspect) {
    const summaryRow = document.getElementById("typosquat-summary-row");
    if (summaryRow) summaryRow.style.display = "flex";
    setText("typosquat-brand",     brand || "—");
    setText("typosquat-dist",      dist);
    setText("typosquat-technique", tech);

    const explEl = document.getElementById("typosquat-explanation");
    if (explEl) {
      explEl.className = "typosquat-explanation expl-suspect";
      const matched = typo.matched_token || "";
      explEl.innerHTML = `
        <strong style="color:var(--red)">Typosquatting suspected.</strong>
        The token <code>${escapeHtml(matched || domain)}</code> within this domain is within
        edit distance ${dist} of the brand <strong>${escapeHtml(brand)}</strong>
        (technique: <em>${escapeHtml(tech)}</em>).
        <br><br>
        Typosquatting domains are registered to intercept traffic from users who mistype
        a well-known URL, or to host phishing pages that appear credible because the domain
        almost matches the real brand. Edit distance ${dist} is
        ${typeof dist === "number" && dist <= 2 ? "extremely close — visually almost indistinguishable" : "close enough to deceive casual inspection"}.
      `;
    }

    const tableWrap = document.getElementById("typosquat-table-wrap");
    const tbody     = document.getElementById("typosquat-table-body");
    const candidates = typo.candidates || [];
    if (tbody && candidates.length > 0) {
      if (tableWrap) tableWrap.style.display = "block";
      tbody.innerHTML = candidates.map(c => {
        const d       = c.edit_distance != null ? c.edit_distance : "—";
        const dClass  = typeof d === "number" ? (d <= 1 ? "dist-low" : d <= 2 ? "dist-medium" : "dist-high") : "";
        const riskLbl = c.risk || "—";
        const rkCls   = riskLbl === "HIGH" ? "label-malicious" : riskLbl === "MEDIUM" ? "label-suspicious" : "label-safe";
        return `<tr>
          <td><strong>${escapeHtml(c.brand || "—")}</strong></td>
          <td><code>${escapeHtml(c.matched_token || "—")}</code></td>
          <td><span class="${dClass}">${d}</span></td>
          <td>${escapeHtml(c.technique || "—")}</td>
          <td><span class="label-badge ${rkCls}">${escapeHtml(riskLbl)}</span></td>
        </tr>`;
      }).join("");
    } else if (tableWrap) {
      tableWrap.style.display = "none";
    }

    const cleanNote = document.getElementById("typosquat-clean-note");
    if (cleanNote) cleanNote.style.display = "none";

  } else {
    const summaryRow = document.getElementById("typosquat-summary-row");
    if (summaryRow) summaryRow.style.display = "none";
    const tableWrap = document.getElementById("typosquat-table-wrap");
    if (tableWrap) tableWrap.style.display = "none";

    const explEl = document.getElementById("typosquat-explanation");
    if (explEl) { explEl.className = "typosquat-explanation expl-clean"; explEl.textContent = ""; }

    const cleanNote = document.getElementById("typosquat-clean-note");
    if (cleanNote) {
      cleanNote.style.display = "block";
      cleanNote.textContent =
        `No typosquatting patterns detected. "${domain}" does not closely resemble ` +
        `any monitored brand within the configured edit-distance threshold.`;
    }
  }
}


// ─── Subdomain card renderer ──────────────────────────────────────────────────

function renderSubdomains(subdomains) {
  const card = document.getElementById("subdomain-card");
  if (!subdomains || !subdomains.length) { if (card) card.style.display = "none"; return; }
  if (card) card.style.display = "block";

  const total    = subdomains.length;
  const resolves = subdomains.filter(s => s.resolves).length;
  const safe     = subdomains.filter(s => s.label === "SAFE").length;
  const susp     = subdomains.filter(s => s.label === "SUSPICIOUS").length;
  const mali     = subdomains.filter(s => s.label === "MALICIOUS").length;
  const unscored = subdomains.filter(s => s.label == null).length;

  setText("subdomain-total-badge", `${total} found`);
  const resolvesBadge = document.getElementById("subdomain-resolve-badge");
  if (resolvesBadge) { resolvesBadge.textContent = `${resolves} resolve`; resolvesBadge.style.display = "inline"; }

  const pills = [];
  if (mali     > 0) pills.push(`<span class="label-badge label-malicious">${mali} malicious</span>`);
  if (susp     > 0) pills.push(`<span class="label-badge label-suspicious">${susp} suspicious</span>`);
  if (safe     > 0) pills.push(`<span class="label-badge label-safe">${safe} safe</span>`);
  if (unscored > 0) pills.push(`<span class="label-badge label-unknown">${unscored} unresolved/unscored</span>`);
  const summaryDiv = document.getElementById("subdomain-risk-summary");
  if (summaryDiv) summaryDiv.innerHTML = pills.join(" ");

  const sources   = [...new Set(subdomains.map(s => s.source))];
  const sourceMap = { crtsh: "crt.sh (CT logs)", bruteforce: "DNS brute-force", both: "crt.sh + DNS" };
  const snEl      = document.getElementById("subdomain-source-note");
  if (snEl) snEl.textContent = `Sources: ${sources.map(src => sourceMap[src] || src).join(" · ")}`;

  const tbody = document.getElementById("subdomain-table-body");
  if (!tbody) return;
  tbody.innerHTML = subdomains.map(sd => {
    const labelClass = sd.label ? sd.label.toLowerCase() : "unknown";
    const riskScore  = sd.risk_score != null ? sd.risk_score.toFixed(1) : "—";
    const mlScore    = sd.ml_score   != null ? sd.ml_score.toFixed(3)   : "—";
    const srcBadge   = sd.source === "both" ? '<span class="auth-pill auth-pass">CT + DNS</span>'
                     : sd.source === "crtsh" ? '<span class="auth-pill auth-none">crt.sh</span>'
                     : '<span class="auth-pill auth-none">brute-force</span>';
    const resolvesPill = sd.resolves ? '<span class="auth-pill auth-pass">Yes</span>' : '<span class="auth-pill auth-fail">No</span>';
    let sslPill = "—";
    if (sd.resolves) sslPill = sd.ssl_valid ? '<span class="auth-pill auth-pass">valid</span>' : '<span class="auth-pill auth-fail">invalid</span>';
    const fillClass  = sd.risk_score != null ? (sd.risk_score < 30 ? "fill-safe" : sd.risk_score < 70 ? "fill-suspicious" : "fill-malicious") : "";
    const riskPill   = sd.risk_score != null ? `<span class="score-pill ${fillClass}">${riskScore}</span>` : "—";
    const labelBadge = sd.label ? `<span class="label-badge label-${labelClass}">${sd.label}</span>` : "—";
    const flagList   = (sd.flags || []).filter(Boolean).slice(0, 3);
    const flagsCell  = flagList.length > 0
      ? `<span class="flags-compact" title="${escapeHtml((sd.flags||[]).join(', '))}">${flagList.map(escapeHtml).join(", ")}</span>`
      : "—";
    return `<tr class="${sd.label === "MALICIOUS" ? "row-malicious" : sd.label === "SUSPICIOUS" ? "row-suspicious" : ""}">
      <td><code class="subdomain-name">${escapeHtml(sd.subdomain)}</code></td>
      <td>${srcBadge}</td><td><code>${escapeHtml(sd.ip || "—")}</code></td>
      <td>${resolvesPill}</td><td>${sslPill}</td>
      <td><span class="score-pill score-${labelClass}">${mlScore}</span></td>
      <td>${riskPill}</td><td>${labelBadge}</td>
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
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No URL scans yet</td></tr>';
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
        <td class="truncate" title="${escapeHtml(s.raw_url || "")}"><code>${escapeHtml(s.domain || "—")}</code></td>
        <td>${escapeHtml(s.ip_address || "—")}</td>
        <td>${escapeHtml(s.country    || "—")}</td>
        <td>${ageBadge}</td>
        <td>${sslBadge}</td>
        <td><span class="score-pill score-${labelClass}">${(s.ml_score || 0).toFixed(2)}</span></td>
        <td><span class="label-badge label-${labelClass}">${escapeHtml(s.final_label || "—")}</span></td>
        <td>${s.scanned_at ? new Date(s.scanned_at).toLocaleString() : "—"}</td>
      </tr>`;
    }).join("");

    document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
  } catch (err) {
    console.warn("URL history refresh failed:", err.message);
  }
}

if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── Helpers ─────────────────────────────────────────────────────────────────

function showSpinner(show, msg = "") {
  const el = document.getElementById("spinner");
  if (!el) return;
  el.style.display = show ? "flex" : "none";
  if (msg) { const m = document.getElementById("spinner-msg"); if (m) m.textContent = msg; }
}

function hideResultCard() {
  const el = document.getElementById("result-card");
  if (el) el.style.display = "none";
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setBoolPill(id, bool, trueLabel, falseLabel,
                     warningOnTrue = false, neutralOnTrue = false) {
  const el = document.getElementById(id);
  if (!el) return;
  if (bool === null || bool === undefined) { el.textContent = "—"; return; }
  if (bool) {
    const cls = neutralOnTrue ? "auth-none" : warningOnTrue ? "auth-fail" : "auth-pass";
    el.innerHTML = `<span class="auth-pill ${cls}">${escapeHtml(trueLabel)}</span>`;
  } else {
    el.innerHTML = `<span class="auth-pill auth-fail">${escapeHtml(falseLabel)}</span>`;
  }
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  try {
    const d = new Date(isoStr.replace(" ", "T"));
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "numeric" });
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