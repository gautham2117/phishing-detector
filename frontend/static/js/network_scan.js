// network_scan.js
// Client-side logic for the Network Scan dashboard page.
"use strict";

// Stores the pending scan request when waiting for consent confirmation
let _pendingScanPayload = null;


// ─── Initiate scan — may trigger consent dialog ───────────────────────────────

async function initiateScan() {
  const target   = document.getElementById("target-input").value.trim();
  const scanType = document.getElementById("scan-type-select").value;

  if (!target) {
    alert("Please enter a target domain or IP address.");
    return;
  }

  // Try to submit without consent first.
  // Flask will return 403 + requires_consent=true if needed.
  await _submitScan(target, scanType, false);
}


// ─── Core scan submission ─────────────────────────────────────────────────────

async function _submitScan(target, scanType, consentConfirmed) {
  showSpinner(true, `Running ${scanType} Nmap scan on ${target}...`);
  hideResultCard();

  const payload = {
    target,
    scan_type:         scanType,
    consent_confirmed: consentConfirmed
  };

  try {
    const response = await fetch("/network/submit", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload)
    });

    const data = await response.json();
    showSpinner(false);

    // ── Consent required ──
    if (response.status === 403 && data.requires_consent) {
      // Store the payload so confirmConsent() can resend it
      _pendingScanPayload = { target, scanType };
      showConsentDialog(data.message);
      return;
    }

    if (!response.ok) {
      alert(`Scan error: ${data.error || response.statusText}`);
      return;
    }

    renderScanResult(data);
    refreshHistory();

  } catch (err) {
    showSpinner(false);
    alert(`Network error: ${err.message}`);
  }
}


// ─── Consent dialog ────────────────────────────────────────────────────────────

function showConsentDialog(message) {
  document.getElementById("consent-message").textContent = message;
  document.getElementById("consent-checkbox").checked    = false;
  document.getElementById("consent-confirm-btn").disabled = true;

  const overlay = document.getElementById("consent-overlay");
  overlay.style.display = "flex";
}

// Enable the confirm button only when the checkbox is ticked
document.getElementById("consent-checkbox")?.addEventListener("change", function () {
  document.getElementById("consent-confirm-btn").disabled = !this.checked;
});

function confirmConsent() {
  document.getElementById("consent-overlay").style.display = "none";

  if (_pendingScanPayload) {
    _submitScan(
      _pendingScanPayload.target,
      _pendingScanPayload.scanType,
      true  // consent_confirmed = true
    );
    _pendingScanPayload = null;
  }
}

function cancelConsent() {
  document.getElementById("consent-overlay").style.display = "none";
  _pendingScanPayload = null;
}


// ─── Render scan result ────────────────────────────────────────────────────────

function renderScanResult(data) {
  /*
   * data.module_results.network_scan contains:
   * {
   *   target, ip_resolved, scan_type, nmap_version, os_guess,
   *   ports: [{port, protocol, state, service_name, service_product,
   *             service_version, service_extra, is_dangerous,
   *             danger_reason, risk_level}],
   *   open_port_count, admin_exposures, risk_level,
   *   risk_flags, scan_duration_s, authorized, error
   * }
   */
  const ns = data.module_results?.network_scan || {};

  // ── Handle blocked / error ──
  if (!ns.authorized) {
    alert(`Scan blocked: ${ns.block_reason || ns.error || "Authorization required"}`);
    return;
  }

  if (ns.error && ns.ports?.length === 0) {
    alert(`Scan error: ${ns.error}`);
    return;
  }

  // ── Header ──
  document.getElementById("res-target").textContent = ns.target || "—";
  document.getElementById("res-ip").textContent     =
    ns.ip_resolved ? `Resolved to: ${ns.ip_resolved}` : "";

  // ── Risk badge ──
  const label = data.label || "UNKNOWN";
  const badge = document.getElementById("risk-badge");
  badge.textContent = ns.risk_level || label;
  badge.className   = `risk-badge badge-${
    ns.risk_level === "LOW" ? "safe" :
    ns.risk_level === "CRITICAL" ? "malicious" : "suspicious"
  }`;

  // ── Stats ──
  const dangerCount = (ns.ports || []).filter(p => p.is_dangerous).length;
  document.getElementById("stat-open").textContent      = ns.open_port_count || 0;
  document.getElementById("stat-dangerous").textContent = dangerCount;
  document.getElementById("stat-admin").textContent     =
    (ns.admin_exposures || []).length;
  document.getElementById("stat-duration").textContent  =
    ns.scan_duration_s != null ? `${ns.scan_duration_s.toFixed(1)}s` : "—";

  // ── Risk flags ──
  const flagsRow = document.getElementById("risk-flags-row");
  flagsRow.innerHTML = (ns.risk_flags || [])
    .map(f => `<span class="flag-pill">${escapeHtml(f)}</span>`)
    .join(" ");

  // ── Port table ──
  const tbody     = document.getElementById("port-table-body");
  const portBadge = document.getElementById("port-count-badge");
  const ports     = ns.ports || [];

  portBadge.textContent = ports.length;

  if (ports.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="empty-state">No open ports found</td></tr>';
  } else {
    tbody.innerHTML = ports.map(p => {
      const riskCls = p.is_dangerous
        ? `port-row-${(p.risk_level || "info").toLowerCase()}`
        : "";
      const dangerTag = p.is_dangerous
        ? `<span class="danger-tag danger-${(p.risk_level||"info").toLowerCase()}">
             ${p.risk_level || "INFO"}
           </span>`
        : '<span class="danger-tag danger-info">—</span>';

      return `<tr class="${riskCls}">
        <td><strong>${p.port}</strong></td>
        <td>${p.protocol}</td>
        <td>${escapeHtml(p.service_name || "—")}</td>
        <td>${escapeHtml(p.service_product || "—")}</td>
        <td>${escapeHtml(p.service_version || "—")}</td>
        <td>${dangerTag}</td>
        <td class="truncate" title="${escapeHtml(p.danger_reason || p.service_extra || "")}">
          ${escapeHtml(truncate(p.danger_reason || p.service_extra || "—", 48))}
        </td>
      </tr>`;
    }).join("");
  }

  // ── Admin panels ──
  const adminCard = document.getElementById("admin-card");
  const adminList = document.getElementById("admin-list");
  const admins    = ns.admin_exposures || [];

  if (admins.length > 0) {
    adminCard.style.display = "block";
    adminList.innerHTML = admins.map(a => `
      <div class="admin-exposure-card">
        <strong>Port ${a.port} — ${escapeHtml(a.panel_type)}</strong>
        <p style="margin-top:4px;color:var(--text-muted)">
          ${escapeHtml(a.description)}
        </p>
      </div>`
    ).join("");
  } else {
    adminCard.style.display = "none";
  }

  // ── OS fingerprint ──
  const osCard = document.getElementById("os-card");
  if (ns.os_guess) {
    osCard.style.display = "block";
    document.getElementById("os-text").textContent = ns.os_guess;
  } else {
    osCard.style.display = "none";
  }

  // ── Explanation ──
  document.getElementById("explanation-text").textContent =
    data.explanation || "—";

  // ── Show result card ──
  document.getElementById("result-card").style.display = "block";
  document.getElementById("result-card")
    .scrollIntoView({ behavior: "smooth" });
  document.getElementById("update-time").textContent =
    new Date().toLocaleTimeString();
}


// ─── Live history polling ──────────────────────────────────────────────────────

async function refreshHistory() {
  try {
    const resp  = await fetch("/network/history");
    if (!resp.ok) return;
    const scans = await resp.json();

    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    if (!scans.length) {
      tbody.innerHTML =
        '<tr><td colspan="8" class="empty-state">No network scans yet</td></tr>';
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const riskLower = (s.risk_level || "unknown").toLowerCase();
      const labelClass =
        riskLower === "low"      ? "safe"       :
        riskLower === "critical" ? "malicious"  :
        riskLower === "unknown"  ? "unknown"    : "suspicious";

      return `<tr>
        <td><code>${escapeHtml(s.target)}</code></td>
        <td>${escapeHtml(s.ip_resolved || "—")}</td>
        <td><span class="auth-pill auth-none">${s.scan_type}</span></td>
        <td>${s.total_open_ports}</td>
        <td>
          <span class="label-badge label-${labelClass}">
            ${s.risk_level || "—"}
          </span>
        </td>
        <td>${s.scan_duration_s != null
          ? s.scan_duration_s.toFixed(1) + "s" : "—"}</td>
        <td>
          ${s.authorized
            ? '<span class="auth-pill auth-pass">yes</span>'
            : '<span class="auth-pill auth-fail">blocked</span>'}
        </td>
        <td>${s.scanned_at
          ? new Date(s.scanned_at).toLocaleString() : "—"}</td>
      </tr>`;
    }).join("");

    document.getElementById("update-time").textContent =
      new Date().toLocaleTimeString();

  } catch (err) {
    console.warn("Network history refresh failed:", err.message);
  }
}

if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── Helpers ──────────────────────────────────────────────────────────────────

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