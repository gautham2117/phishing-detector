// scan_ui.js
// Client-side logic for the Email Scan dashboard page.
//
// Responsibilities:
//   - Handle file drag-and-drop and file input
//   - Submit scans to Flask proxy (/email/submit)
//   - Render scan results into the result card DOM elements
//   - Poll /email/history every 5 seconds for live updates
//
// NEW IN THIS VERSION:
//   renderDistilbertDetail(distil) — replaces the flat one-liner with a
//     verdict badge, colour-coded confidence bar, plain-English
//     interpretation paragraph, and a score breakdown mini-table.
//   renderDnsbl(ep)  — fills the DNSBL / blocklist card inside the auth
//     section; shows listed zones as red pills or a green "clean" badge.
//   renderBec(ep)    — fills the BEC display name spoofing card; shows
//     display name / from domain / reply-to domain / executive keyword
//     metadata tiles and a signal list when suspect.

"use strict";

// ─── Tab switching ────────────────────────────────────────────────────────

function switchTab(tab) {
  document.getElementById("panel-upload").style.display = tab === "upload" ? "block" : "none";
  document.getElementById("panel-paste").style.display  = tab === "paste"  ? "block" : "none";
  document.getElementById("tab-upload").classList.toggle("active", tab === "upload");
  document.getElementById("tab-paste").classList.toggle("active",  tab === "paste");
}


// ─── File drag-and-drop ───────────────────────────────────────────────────

const dropZone = document.getElementById("drop-zone");
if (dropZone) {
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");

    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith(".eml")) {
      uploadEmlFile(file);
    } else {
      showError("Please drop a .eml file.");
    }
  });
}


// ─── File input handler ───────────────────────────────────────────────────

function handleFileSelect(input) {
  const file = input.files[0];
  if (!file) return;

  if (!file.name.endsWith(".eml")) {
    showError("Only .eml files are accepted.");
    return;
  }

  uploadEmlFile(file);
}


// ─── Upload .eml file to Flask ────────────────────────────────────────────

async function uploadEmlFile(file) {
  showSpinner(true);
  hideResultCard();

  const formData = new FormData();
  formData.append("eml_file", file);

  try {
    const response = await fetch("/email/submit", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      showError(data.error || `Server error: ${response.status}`);
      return;
    }

    renderScanResult(data);

    const urls = data.module_results?.email_parser?.urls?.map(u => u.raw) || [];
    if (urls.length > 0 && data.scan_id) {
      fetch("/url/submit/batch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ urls, email_scan_id: data.scan_id })
      });
    }

    refreshHistory();

  } catch (err) {
    showError(`Network error: ${err.message}. Is the Flask server running?`);
  } finally {
    showSpinner(false);
  }
}


// ─── Submit pasted raw email ──────────────────────────────────────────────

async function submitPastedEmail() {
  const rawEmail = document.getElementById("raw-email-input").value.trim();

  if (!rawEmail) {
    showError("Please paste an email into the text area.");
    return;
  }

  showSpinner(true);
  hideResultCard();

  try {
    const response = await fetch("/email/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_email: rawEmail })
    });

    const data = await response.json();

    if (!response.ok) {
      showError(data.error || `Server error: ${response.status}`);
      return;
    }

    renderScanResult(data);
    refreshHistory();

  } catch (err) {
    showError(`Network error: ${err.message}`);
  } finally {
    showSpinner(false);
  }
}


// ─── Render scan result ───────────────────────────────────────────────────

function renderScanResult(data) {
  const card = document.getElementById("result-card");
  const ep   = data.module_results?.email_parser || {};

  // ── Risk badge and score bar ──────────────────────────────────────────
  const badge = document.getElementById("risk-badge");
  badge.textContent = data.label || "UNKNOWN";
  badge.className   = `risk-badge badge-${(data.label || "unknown").toLowerCase()}`;

  const scoreBar = document.getElementById("score-bar");
  const scoreNum = document.getElementById("score-number");
  const score    = data.risk_score || 0;
  scoreBar.style.width = `${score}%`;
  scoreBar.className   = `score-bar-fill ${
    score < 30 ? "fill-safe" : score < 70 ? "fill-suspicious" : "fill-malicious"
  }`;
  scoreNum.textContent = score.toFixed(1);

  // ── Recommended action ────────────────────────────────────────────────
  const actionPill = document.getElementById("action-pill");
  actionPill.textContent = `Recommended: ${data.recommended_action || "—"}`;
  actionPill.className   = `action-pill action-${(data.recommended_action || "warn").toLowerCase()}`;

  // ── DistilBERT — expanded detail ──────────────────────────────────────
  renderDistilbertDetail(ep.distilbert || {});

  // ── Auth results pills ────────────────────────────────────────────────
  function authClass(r) {
    if (!r || r === "none") return "auth-none";
    if (r === "pass")       return "auth-pass";
    return "auth-fail";
  }
  const auth = ep.auth_results || {};
  document.getElementById("spf-pill").textContent  = `SPF: ${auth.spf   || "none"}`;
  document.getElementById("spf-pill").className    = `auth-pill ${authClass(auth.spf)}`;
  document.getElementById("dkim-pill").textContent = `DKIM: ${auth.dkim  || "none"}`;
  document.getElementById("dkim-pill").className   = `auth-pill ${authClass(auth.dkim)}`;
  document.getElementById("dmarc-pill").textContent= `DMARC: ${auth.dmarc|| "none"}`;
  document.getElementById("dmarc-pill").className  = `auth-pill ${authClass(auth.dmarc)}`;

  // ── DNSBL ─────────────────────────────────────────────────────────────
  renderDnsbl(ep);

  // ── BEC spoofing ──────────────────────────────────────────────────────
  renderBec(ep);

  // ── Anomalies ─────────────────────────────────────────────────────────
  const anomalyList = document.getElementById("anomaly-list");
  const anomalies   = ep.anomalies || [];
  document.getElementById("anomaly-count").textContent = anomalies.length;

  anomalyList.innerHTML = anomalies.length === 0
    ? '<li class="empty-state">No anomalies detected</li>'
    : anomalies.map(a =>
        `<li class="anomaly-item severity-${a.severity}">
           <strong>${a.type.replace(/_/g, " ")}</strong>
           — ${escapeHtml(a.description)}
           <span class="severity-tag">${a.severity}</span>
         </li>`
      ).join("");

  // ── URLs table ────────────────────────────────────────────────────────
  const urlTableBody = document.getElementById("url-table-body");
  const urls         = ep.urls || [];
  document.getElementById("url-count").textContent = urls.length;

  urlTableBody.innerHTML = urls.length === 0
    ? '<tr><td colspan="4" class="empty-state">No URLs found in email</td></tr>'
    : urls.map(u => {
        const flagHtml = (u.flags || []).map(f =>
          `<span class="flag-pill">${f.replace(/_/g, " ")}</span>`
        ).join(" ");
        const shortenerBadge = u.is_shortener
          ? '<span class="flag-pill shortener">shortener</span>' : "";
        const displayUrl = u.raw.length > 60
          ? u.raw.substring(0, 57) + "..." : u.raw;

        return `<tr>
          <td title="${escapeHtml(u.raw)}"><code>${escapeHtml(displayUrl)}</code></td>
          <td>${escapeHtml(u.domain)}</td>
          <td>${flagHtml || "—"}</td>
          <td>${shortenerBadge || "—"}</td>
        </tr>`;
      }).join("");

  // ── Explanation ───────────────────────────────────────────────────────
  document.getElementById("explanation-text").textContent =
    data.explanation || "No explanation available.";

  // ── Show card ─────────────────────────────────────────────────────────
  card.style.display = "block";
  card.scrollIntoView({ behavior: "smooth", block: "start" });
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
}


// ─── DistilBERT full explanation renderer ─────────────────────────────────

function renderDistilbertDetail(distil) {
  /*
   * Populates the full DistilBERT explanation panel:
   *
   *  1. Verdict badge  — colour-coded PHISHING / SAFE / UNKNOWN
   *  2. Confidence meter — bar + tick marks at 60 / 80 / 95 %
   *  3. Explanation block — what DistilBERT is, what the score means,
   *       why the confidence is at this level (four tiers per verdict)
   *  4. Score breakdown grid — raw score / confidence tier /
   *       risk contribution / model input size
   *  5. Next-steps list — concrete actions the analyst should take,
   *       tailored to the verdict and confidence tier
   *  6. Model attribution footer
   */

  const label    = (distil.label || "UNKNOWN").toUpperCase();
  const rawScore = distil.score  || 0;
  const pct      = Math.round(rawScore * 100);
  const model    = distil.model  || "unknown model";
  const note     = distil.note   || "";

  // ── 1. Verdict badge ─────────────────────────────────────────────────
  const verdictBadge = document.getElementById("distil-verdict-badge");
  verdictBadge.textContent = label;
  verdictBadge.className   = "distil-verdict-badge " +
    (label === "PHISHING" ? "dvb-phishing" :
     label === "SAFE"     ? "dvb-safe"     : "dvb-unknown");

  // ── 2. Confidence meter ──────────────────────────────────────────────
  const confBar = document.getElementById("confidence-bar");
  confBar.style.width = `${pct}%`;
  confBar.className   = `confidence-bar-fill ${
    label === "PHISHING" ? "fill-malicious" :
    label === "SAFE"     ? "fill-safe"      : "fill-suspicious"
  }`;
  // The meter label changes depending on direction of the score:
  // for PHISHING the bar shows "phishing confidence",
  // for SAFE it shows "legitimate confidence"
  document.getElementById("distil-meter-left").textContent =
    label === "SAFE" ? "Legitimate confidence" : "Phishing confidence";
  document.getElementById("distil-conf-pct").textContent = `${pct}%`;

  // ── 3. Explanation block ─────────────────────────────────────────────
  // Four tiers per verdict.  Each block has:
  //   - A headline summarising the tier
  //   - A paragraph explaining what the score means technically
  //   - A sentence on why the model might be at this confidence level
  const explEl = document.getElementById("distil-explanation-block");
  let headline = "";
  let hlClass  = "hl-unknown";
  let body     = "";
  let explClass = "distil-explanation-block";

  if (label === "PHISHING") {
    explClass += " expl-phishing";
    hlClass    = "hl-phishing";

    if (pct >= 95) {
      headline = `Very high confidence — ${pct}% phishing probability`;
      body = `DistilBERT is a lightweight transformer model (66M parameters) fine-tuned on
        a large corpus of labelled phishing and legitimate emails. A score of ${pct}% means
        the body text pattern almost perfectly matches known phishing campaigns in its
        training data — this level of certainty is typically produced by emails that combine
        multiple strong signals: urgency language, impersonation of a trusted brand,
        credential-harvesting links, and deceptive call-to-action phrasing.
        <br><br>
        The raw output score of <strong>${rawScore.toFixed(4)}</strong> is fed into the
        overall risk scorer as <strong>+${Math.round(rawScore * 60)} points</strong>
        (score × 60), making DistilBERT the single largest contributor to this email's
        total risk score when it fires at this confidence.`;
    } else if (pct >= 80) {
      headline = `High confidence — ${pct}% phishing probability`;
      body = `DistilBERT assigned an ${pct}% phishing probability to this email body.
        This is a strong signal — the text contains recognisable phishing patterns such
        as urgency triggers ("your account will be suspended"), credential requests, or
        brand impersonation phrasing. At this confidence level the model has seen very
        similar language in confirmed phishing emails during training.
        <br><br>
        The raw score of <strong>${rawScore.toFixed(4)}</strong> contributes
        <strong>+${Math.round(rawScore * 60)} points</strong> to the overall risk score.
        Header anomalies and URL flags are independent checks — a high DistilBERT score
        combined with SPF/DKIM failures or suspicious URLs is a strong compound indicator.`;
    } else if (pct >= 60) {
      headline = `Moderate confidence — ${pct}% phishing probability`;
      body = `The model leans toward phishing at ${pct}%, but is not fully certain.
        This confidence level typically arises when the email uses softer social engineering
        — for example, vague urgency without explicit credential requests, or brand
        keywords without a clear harvesting link. It may also indicate a phishing variant
        the model has seen less frequently in training.
        <br><br>
        Raw score <strong>${rawScore.toFixed(4)}</strong> → 
        <strong>+${Math.round(rawScore * 60)} risk points</strong>.
        Do not rely on the body classifier alone at this tier — check the authentication
        results, header anomalies, and each extracted URL before making a final decision.`;
    } else {
      headline = `Low–moderate phishing signal — ${pct}%`;
      body = `The model classified this as phishing but with limited confidence (${pct}%).
        At this level, the body text contains some features that overlap with phishing
        patterns — perhaps urgency keywords or brand mentions — but lacks the full
        combination of signals the model associates with confirmed attacks. This could be
        a borderline marketing email, a cold outreach message, or a novel phishing variant.
        <br><br>
        Raw score <strong>${rawScore.toFixed(4)}</strong> →
        <strong>+${Math.round(rawScore * 60)} risk points</strong>.
        Weight this signal alongside authentication failures and URL flags rather than
        treating it as definitive.`;
    }

  } else if (label === "SAFE") {
    explClass += " expl-safe";
    hlClass    = "hl-safe";

    if (pct >= 95) {
      headline = `Very high confidence — ${pct}% legitimate probability`;
      body = `DistilBERT is ${pct}% confident this email is legitimate. At this confidence
        level, the body text closely matches patterns found in normal, non-phishing
        correspondence in the training set — no urgency language, no credential harvesting
        phrases, and no brand impersonation patterns were detected.
        <br><br>
        Raw score <strong>${rawScore.toFixed(4)}</strong> adds only
        <strong>+${Math.round((1 - rawScore) * 10)} risk points</strong> (a small penalty
        for residual uncertainty). Note that a clean body classifier result does not
        guarantee the email is safe — header spoofing, domain impersonation, and malicious
        attachments operate independently of the body text.`;
    } else if (pct >= 80) {
      headline = `High confidence — ${pct}% legitimate probability`;
      body = `The email body does not contain typical phishing language — the model is
        ${pct}% confident it is legitimate. The text likely reads as straightforward
        business or personal correspondence without urgency triggers or suspicious
        call-to-action phrasing.
        <br><br>
        Raw score <strong>${rawScore.toFixed(4)}</strong> →
        <strong>+${Math.round((1 - rawScore) * 10)} risk points</strong>.
        Even with a safe body classification, review the authentication results and any
        extracted URLs, as a spoofed sender or malicious link can be hidden inside an
        otherwise benign-looking message.`;
    } else {
      headline = `Moderate confidence — ${pct}% legitimate probability`;
      body = `The model leans toward legitimate but with moderate certainty (${pct}%).
        This can occur when the body is very short, heavily HTML-encoded, or written in a
        style the model has less training data for. The absence of obvious phishing keywords
        produces a safe label, but the model's uncertainty means you should not rely on
        this result alone.
        <br><br>
        Raw score <strong>${rawScore.toFixed(4)}</strong> →
        <strong>+${Math.round((1 - rawScore) * 10)} risk points</strong>.
        Cross-reference with authentication checks and header anomalies.`;
    }

  } else {
    // UNKNOWN
    headline  = "Classification unavailable";
    hlClass   = "hl-unknown";
    body = note
      ? `The model could not classify this email: <em>${escapeHtml(note)}</em>.
         This usually means the body was too short (under 10 characters), empty, or could
         not be decoded from the email's character encoding. DistilBERT requires a
         readable body to produce a probability score.
         <br><br>
         Fall back on the authentication results, header anomaly checks, and URL analysis
         to assess risk.`
      : `DistilBERT could not produce a verdict for this email. The body may be empty,
         too short, or in an unsupported encoding. The overall risk score is based entirely
         on header anomalies, authentication failures, and URL flags for this scan.`;
  }

  explEl.className = explClass;
  explEl.innerHTML = `
    <span class="expl-headline ${hlClass}">${headline}</span>
    <span>${body}</span>
  `;

  // ── 4. Score breakdown grid ──────────────────────────────────────────
  const tier = label === "PHISHING"
    ? (pct >= 95 ? "Very High" : pct >= 80 ? "High" : pct >= 60 ? "Moderate" : "Low")
    : label === "SAFE"
      ? (pct >= 95 ? "Very High" : pct >= 80 ? "High" : "Moderate")
      : "N/A";

  const riskPts = label === "PHISHING"
    ? Math.round(rawScore * 60)
    : label === "SAFE"
      ? Math.round((1 - rawScore) * 10)
      : 0;

  const riskColor = label === "PHISHING"
    ? (riskPts >= 48 ? "val-red" : riskPts >= 30 ? "val-amber" : "val-muted")
    : "val-green";

  document.getElementById("distil-breakdown-grid").innerHTML = `
    <div class="distil-breakdown-cell">
      <span class="distil-breakdown-key">Raw model output</span>
      <span class="distil-breakdown-val">${rawScore.toFixed(4)}</span>
    </div>
    <div class="distil-breakdown-cell">
      <span class="distil-breakdown-key">Confidence tier</span>
      <span class="distil-breakdown-val">${tier}</span>
    </div>
    <div class="distil-breakdown-cell">
      <span class="distil-breakdown-key">Risk score impact</span>
      <span class="distil-breakdown-val ${riskColor}">+${riskPts} pts</span>
    </div>
  `;

  // ── 5. Next-steps list ───────────────────────────────────────────────
  // Tailored to verdict + confidence tier so the analyst knows
  // exactly what to do next with this specific result.
  let steps = [];

  if (label === "PHISHING") {
    if (pct >= 80) {
      steps = [
        `<strong>Do not interact with this email.</strong> Do not click any links, open attachments, or reply.`,
        `<strong>Check the extracted URLs below</strong> — run each through the URL Intelligence scanner to confirm malicious destinations.`,
        `<strong>Review authentication results.</strong> SPF/DKIM/DMARC failures alongside a high DistilBERT score are a near-certain compound indicator of phishing.`,
        `<strong>Check header anomalies</strong> — Reply-To mismatch or Return-Path mismatch suggest the sender is attempting to intercept replies.`,
        `<strong>Report and quarantine</strong> this message if it arrived in a real inbox. Alert your security team if this is a production environment.`,
      ];
    } else {
      steps = [
        `<strong>Treat with caution</strong> — the model flags phishing but is not fully certain. Do not click links until further checks are done.`,
        `<strong>Scan all extracted URLs</strong> using the URL Intelligence module to independently confirm or rule out malicious destinations.`,
        `<strong>Check authentication.</strong> If SPF and DKIM both pass, the phishing signal may be a false positive from unusual-but-legitimate phrasing.`,
        `<strong>Re-read the subject and body manually</strong> for urgency language, brand impersonation, or requests for credentials or payment.`,
      ];
    }
  } else if (label === "SAFE") {
    if (pct >= 80) {
      steps = [
        `<strong>Body content appears clean</strong>, but always verify the sender domain independently — spoofed display names can fool visual inspection.`,
        `<strong>Check authentication results.</strong> A legitimate-looking body combined with SPF or DKIM failure still warrants caution.`,
        `<strong>Scan any attachments</strong> using the Attachment Analysis module — malicious payloads can be embedded independently of the email body.`,
        `<strong>Hover over links</strong> before clicking to verify the actual destination matches the displayed text.`,
      ];
    } else {
      steps = [
        `<strong>Model confidence is moderate</strong> — do not rely on this result alone. Verify through authentication results and URL scanning.`,
        `<strong>Scan extracted URLs</strong> even though the body appears safe. A safe body can accompany a malicious link.`,
        `<strong>Check for header anomalies</strong> — mismatch between Return-Path and From is a red flag regardless of body content.`,
      ];
    }
  } else {
    steps = [
      `<strong>DistilBERT could not classify this email</strong> — rely on the other analysis layers below.`,
      `<strong>Check authentication results</strong> (SPF, DKIM, DMARC) for independent sender verification.`,
      `<strong>Review header anomalies</strong> and <strong>scan all extracted URLs</strong> manually.`,
    ];
  }

  document.getElementById("distil-next-steps").innerHTML = `
    <span class="distil-next-steps-title">What to do next</span>
    <ol>${steps.map(s => `<li>${s}</li>`).join("")}</ol>
  `;

  // ── 6. Model footer ──────────────────────────────────────────────────
  document.getElementById("distil-model-name").textContent = model;
}


// ─── DNSBL renderer ───────────────────────────────────────────────────────

function renderDnsbl(ep) {
  /*
   * ep.dnsbl_result = {
   *   listed: bool,
   *   zones_hit: string[],
   *   zones_checked: int,
   *   ip: string | null,
   *   note?: string
   * }
   *
   * Shows/hides the dnsbl-block inside the auth card.
   * If no IP was found (no Received headers), hides the block entirely.
   */
  const dnsbl = ep.dnsbl_result || {};
  const block = document.getElementById("dnsbl-block");
  if (!block) return;

  // If there's no IP and no note, there's nothing useful to show
  if (!dnsbl.ip && !dnsbl.note) {
    block.style.display = "none";
    return;
  }

  block.style.display = "block";

  // IP badge
  const ipEl = document.getElementById("dnsbl-ip");
  ipEl.textContent = dnsbl.ip ? dnsbl.ip : "no IP found";
  ipEl.style.display = dnsbl.ip ? "inline-block" : "none";

  // Status badge
  const statusBadge = document.getElementById("dnsbl-status-badge");
  if (!dnsbl.ip) {
    statusBadge.textContent = "N/A";
    statusBadge.className   = "dnsbl-status-badge dnsbl-unknown";
  } else if (dnsbl.listed) {
    const n = dnsbl.zones_hit.length;
    statusBadge.textContent = `LISTED on ${n} zone${n > 1 ? "s" : ""}`;
    statusBadge.className   = "dnsbl-status-badge dnsbl-listed";
  } else {
    const checked = dnsbl.zones_checked || 0;
    statusBadge.textContent = `Clean — ${checked} zone${checked !== 1 ? "s" : ""} checked`;
    statusBadge.className   = "dnsbl-status-badge dnsbl-clean";
  }

  // Zones hit list
  const zonesRow  = document.getElementById("dnsbl-zones-row");
  const zonesList = document.getElementById("dnsbl-zones-list");

  if (dnsbl.listed && dnsbl.zones_hit && dnsbl.zones_hit.length > 0) {
    zonesRow.style.display = "flex";
    zonesList.innerHTML = dnsbl.zones_hit
      .map(z => `<span class="dnsbl-zone-pill">${escapeHtml(z)}</span>`)
      .join("");
  } else {
    zonesRow.style.display = "none";
  }

  // Note line (e.g. "dnspython not installed")
  const noteEl = document.getElementById("dnsbl-note");
  noteEl.textContent = dnsbl.note || "";
  noteEl.style.display = dnsbl.note ? "block" : "none";
}


// ─── BEC renderer ─────────────────────────────────────────────────────────

function renderBec(ep) {
  /*
   * ep.bec_result = {
   *   is_bec_suspect: bool,
   *   display_name: string,
   *   from_domain: string,
   *   reply_to_domain: string | null,
   *   executive_keyword_found: string,
   *   risk_signals: string[]
   * }
   *
   * Always shows the BEC card (provides the user with metadata even when
   * no spoofing is suspected — the "clean" note explains the check).
   */
  const bec  = ep.bec_result || {};
  const card = document.getElementById("bec-card");
  if (!card) return;

  card.style.display = "block";

  // ── Status badge on the heading ──
  const statusBadge = document.getElementById("bec-status-badge");
  if (bec.is_bec_suspect) {
    statusBadge.textContent = "SUSPECT";
    statusBadge.className   = "bec-status-badge bec-suspect";
  } else {
    statusBadge.textContent = "Clean";
    statusBadge.className   = "bec-status-badge bec-clean";
  }

  // ── Metadata tiles ──
  document.getElementById("bec-display-name").textContent =
    bec.display_name || "(none)";
  document.getElementById("bec-from-domain").textContent  =
    bec.from_domain  || "—";

  // Reply-To domain — only show tile if present and different from From
  const replyToItem = document.getElementById("bec-replyto-item");
  if (bec.reply_to_domain && bec.reply_to_domain !== bec.from_domain) {
    replyToItem.style.display = "flex";
    document.getElementById("bec-replyto-domain").textContent = bec.reply_to_domain;
  } else {
    replyToItem.style.display = "none";
  }

  // Executive keyword — only show tile if found
  const kwItem = document.getElementById("bec-kw-item");
  if (bec.executive_keyword_found) {
    kwItem.style.display = "flex";
    document.getElementById("bec-exec-kw").textContent =
      bec.executive_keyword_found.toUpperCase();
  } else {
    kwItem.style.display = "none";
  }

  // ── Risk signals list ──
  const signalsList = document.getElementById("bec-signals-list");
  const cleanNote   = document.getElementById("bec-clean-note");

  const signals = bec.risk_signals || [];
  if (signals.length > 0) {
    signalsList.style.display = "flex";
    cleanNote.style.display   = "none";
    signalsList.innerHTML = signals.map(s =>
      `<li class="bec-signal-item">
         <span class="bec-signal-icon">⚠</span>
         <span>${escapeHtml(s)}</span>
       </li>`
    ).join("");
  } else {
    signalsList.style.display = "none";
    cleanNote.style.display   = "block";
  }
}


// ─── Live history polling ─────────────────────────────────────────────────

async function refreshHistory() {
  try {
    const response = await fetch("/email/history");
    if (!response.ok) return;

    const scans = await response.json();
    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    if (scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans yet</td></tr>';
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const labelClass = (s.label || "unknown").toLowerCase();
      const date = s.scanned_at
        ? new Date(s.scanned_at).toLocaleString() : "—";

      return `<tr>
        <td>${s.id}</td>
        <td>${escapeHtml(s.filename || "—")}</td>
        <td class="truncate" title="${escapeHtml(s.sender  || "")}">${escapeHtml(truncate(s.sender,  30))}</td>
        <td class="truncate" title="${escapeHtml(s.subject || "")}">${escapeHtml(truncate(s.subject, 35))}</td>
        <td><span class="score-pill score-${labelClass}">${(s.risk_score || 0).toFixed(1)}</span></td>
        <td><span class="label-badge label-${labelClass}">${s.label || "—"}</span></td>
        <td>${date}</td>
      </tr>`;
    }).join("");

    document.getElementById("update-time").textContent = new Date().toLocaleTimeString();

  } catch (err) {
    console.warn("History refresh failed:", err.message);
  }
}

if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── UI helpers ───────────────────────────────────────────────────────────

function showSpinner(show) {
  const spinner = document.getElementById("spinner");
  if (spinner) spinner.style.display = show ? "flex" : "none";
}

function hideResultCard() {
  const card = document.getElementById("result-card");
  if (card) card.style.display = "none";
}

function showError(message) {
  alert(`Error: ${message}`);
  console.error(message);
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, maxLen) {
  if (!str) return "—";
  return str.length > maxLen ? str.substring(0, maxLen - 3) + "..." : str;
}