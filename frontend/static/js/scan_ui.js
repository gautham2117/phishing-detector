// scan_ui.js
// Client-side logic for the Email Scan dashboard page.
//
// Responsibilities:
//   - Handle file drag-and-drop and file input
//   - Submit scans to Flask proxy (/email/submit)
//   - Render scan results into the result card DOM elements
//   - Poll /email/history every 5 seconds for live updates

"use strict";

// ─── Tab switching ────────────────────────────────────────────────────────

function switchTab(tab) {
  // Show the correct panel and mark the correct tab as active
  document.getElementById("panel-upload").style.display = tab === "upload" ? "block" : "none";
  document.getElementById("panel-paste").style.display  = tab === "paste"  ? "block" : "none";
  document.getElementById("tab-upload").classList.toggle("active", tab === "upload");
  document.getElementById("tab-paste").classList.toggle("active",  tab === "paste");
}


// ─── File drag-and-drop ───────────────────────────────────────────────────

const dropZone = document.getElementById("drop-zone");
if (dropZone) {
  // Prevent the browser from opening the dropped file
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
  // Called when the user clicks "Choose file" and selects a .eml
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

  // FormData lets us send file + text fields in a single multipart request
  const formData = new FormData();
  formData.append("eml_file", file);

  try {
    const response = await fetch("/email/submit", {
      method: "POST",
      body: formData
      // Note: do NOT set Content-Type header manually when using FormData —
      // the browser sets it automatically with the correct boundary.
    });

    const data = await response.json();

    if (!response.ok) {
      showError(data.error || `Server error: ${response.status}`);
      return;
    }

    renderScanResult(data);

    // In scan_ui.js — add after renderScanResult(data):
    // Auto-trigger URL batch scan for all URLs found in the email
    const urls = data.module_results?.email_parser?.urls?.map(u => u.raw) || [];
    if (urls.length > 0 && data.scan_id) {
      fetch("/url/submit/batch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ urls, email_scan_id: data.scan_id })
      });
      // Results will appear in the URL Intelligence history within ~30 seconds
     }
    // Immediately refresh the history table to show the new scan
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
  /*
   * data follows the standard response schema:
   * {
   *   status, risk_score, label, recommended_action,
   *   explanation, timestamp, scan_id,
   *   module_results: {
   *     email_parser: {
   *       sender, subject, auth_results, anomalies,
   *       urls, distilbert: {label, score}
   *     }
   *   }
   * }
   */

  const card = document.getElementById("result-card");
  const ep   = data.module_results?.email_parser || {};

  // ── Risk badge and score bar ──
  const badge = document.getElementById("risk-badge");
  badge.textContent = data.label || "UNKNOWN";
  badge.className   = `risk-badge badge-${(data.label || "unknown").toLowerCase()}`;

  const scoreBar = document.getElementById("score-bar");
  const scoreNum = document.getElementById("score-number");
  const score    = data.risk_score || 0;
  scoreBar.style.width = `${score}%`;
  // Color the bar: green < 30, amber 30–70, red ≥ 70
  scoreBar.className = `score-bar-fill ${score < 30 ? "fill-safe" : score < 70 ? "fill-suspicious" : "fill-malicious"}`;
  scoreNum.textContent = score.toFixed(1);

  // ── Recommended action ──
  const actionPill = document.getElementById("action-pill");
  actionPill.textContent = `Recommended: ${data.recommended_action || "—"}`;
  actionPill.className   = `action-pill action-${(data.recommended_action || "warn").toLowerCase()}`;

  // ── DistilBERT result ──
  const distil = ep.distilbert || {};
  document.getElementById("distilbert-result").textContent =
    `${distil.label || "—"}   (model: ${distil.model || "—"})`;

  const confScore = Math.round((distil.score || 0) * 100);
  const confBar   = document.getElementById("confidence-bar");
  confBar.style.width = `${confScore}%`;
  confBar.className   = `confidence-bar-fill ${distil.label === "PHISHING" ? "fill-malicious" : "fill-safe"}`;
  document.getElementById("confidence-label").textContent = `${confScore}% confidence`;

  // ── Auth results pills ──
  function authClass(result) {
    if (!result || result === "none") return "auth-none";
    if (result === "pass") return "auth-pass";
    return "auth-fail";
  }
  const auth = ep.auth_results || {};
  document.getElementById("spf-pill").textContent  = `SPF: ${auth.spf  || "none"}`;
  document.getElementById("spf-pill").className    = `auth-pill ${authClass(auth.spf)}`;
  document.getElementById("dkim-pill").textContent = `DKIM: ${auth.dkim || "none"}`;
  document.getElementById("dkim-pill").className   = `auth-pill ${authClass(auth.dkim)}`;
  document.getElementById("dmarc-pill").textContent= `DMARC: ${auth.dmarc || "none"}`;
  document.getElementById("dmarc-pill").className  = `auth-pill ${authClass(auth.dmarc)}`;

  // ── Anomalies list ──
  const anomalyList  = document.getElementById("anomaly-list");
  const anomalies    = ep.anomalies || [];
  document.getElementById("anomaly-count").textContent = anomalies.length;

  anomalyList.innerHTML = anomalies.length === 0
    ? '<li class="empty-state">No anomalies detected</li>'
    : anomalies.map(a =>
        `<li class="anomaly-item severity-${a.severity}">
           <strong>${a.type.replace(/_/g, " ")}</strong>
           — ${a.description}
           <span class="severity-tag">${a.severity}</span>
         </li>`
      ).join("");

  // ── URLs table ──
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

        // Truncate long URLs for display
        const displayUrl = u.raw.length > 60
          ? u.raw.substring(0, 57) + "..." : u.raw;

        return `<tr>
          <td title="${escapeHtml(u.raw)}">
            <code>${escapeHtml(displayUrl)}</code>
          </td>
          <td>${escapeHtml(u.domain)}</td>
          <td>${flagHtml || "—"}</td>
          <td>${shortenerBadge || "—"}</td>
        </tr>`;
      }).join("");

  // ── Explanation ──
  document.getElementById("explanation-text").textContent =
    data.explanation || "No explanation available.";

  // ── Show the result card ──
  card.style.display = "block";
  card.scrollIntoView({ behavior: "smooth", block: "start" });

  // Update the last-updated timestamp
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
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
        ? new Date(s.scanned_at).toLocaleString()
        : "—";

      return `<tr>
        <td>${s.id}</td>
        <td>${escapeHtml(s.filename || "—")}</td>
        <td class="truncate" title="${escapeHtml(s.sender || "")}">${escapeHtml(truncate(s.sender, 30))}</td>
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

// Poll every 5 seconds — only start polling if we're on the email scan page
if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── UI helpers ──────────────────────────────────────────────────────────

function showSpinner(show) {
  const spinner = document.getElementById("spinner");
  if (spinner) spinner.style.display = show ? "flex" : "none";
}

function hideResultCard() {
  const card = document.getElementById("result-card");
  if (card) card.style.display = "none";
}

function showError(message) {
  // Simple error display — in Phase 13 this will connect to the Alert system
  alert(`Error: ${message}`);
  console.error(message);
}

function escapeHtml(str) {
  // Prevent XSS when inserting untrusted content into innerHTML
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