// network_scan.js
// Client-side logic for the Network Scan dashboard page.
// Includes CVE expand/collapse in port table + 3-tab explanation panel.
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

  await _submitScan(target, scanType, false);
}


// ─── Core scan submission ─────────────────────────────────────────────────────

async function _submitScan(target, scanType, consentConfirmed) {
  showSpinner(true, `Running ${scanType} Nmap scan on ${target}...`);
  hideResultCard();

  const payload = {
    target,
    scan_type:         scanType,
    consent_confirmed: consentConfirmed,
  };

  try {
    const response = await fetch("/network/submit", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });

    const data = await response.json();
    showSpinner(false);

    if (response.status === 403 && data.requires_consent) {
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
  document.getElementById("consent-message").textContent  = message;
  document.getElementById("consent-checkbox").checked     = false;
  document.getElementById("consent-confirm-btn").disabled = true;
  document.getElementById("consent-overlay").style.display = "flex";
}

document.getElementById("consent-checkbox")?.addEventListener("change", function () {
  document.getElementById("consent-confirm-btn").disabled = !this.checked;
});

function confirmConsent() {
  document.getElementById("consent-overlay").style.display = "none";
  if (_pendingScanPayload) {
    _submitScan(_pendingScanPayload.target, _pendingScanPayload.scanType, true);
    _pendingScanPayload = null;
  }
}

function cancelConsent() {
  document.getElementById("consent-overlay").style.display = "none";
  _pendingScanPayload = null;
}


// ─── Main render ──────────────────────────────────────────────────────────────

function renderScanResult(data) {
  const ns = data.module_results?.network_scan || {};

  if (!ns.authorized) {
    alert(`Scan blocked: ${ns.block_reason || ns.error || "Authorization required"}`);
    return;
  }
  if (ns.error && !ns.ports?.length) {
    alert(`Scan error: ${ns.error}`);
    return;
  }

  // ── Header ──────────────────────────────────────────────────────────────
  document.getElementById("res-target").textContent = ns.target || "—";
  document.getElementById("res-ip").textContent =
    ns.ip_resolved ? `Resolved to: ${ns.ip_resolved}` : "";

  const badge = document.getElementById("risk-badge");
  badge.textContent = ns.risk_level || data.label || "UNKNOWN";
  badge.className   = `risk-badge badge-${
    ns.risk_level === "LOW"      ? "safe"      :
    ns.risk_level === "CRITICAL" ? "malicious" : "suspicious"
  }`;

  // ── Stats ────────────────────────────────────────────────────────────────
  const ports = ns.ports || [];
  let totalCves = 0;
  for (const p of ports) totalCves += (p.cve_data?.cves?.length || 0);

  document.getElementById("stat-open").textContent      = ns.open_port_count || 0;
  document.getElementById("stat-dangerous").textContent = ports.filter(p => p.is_dangerous).length;
  document.getElementById("stat-admin").textContent     = (ns.admin_exposures || []).length;
  document.getElementById("stat-cve").textContent       = totalCves;
  document.getElementById("stat-duration").textContent  =
    ns.scan_duration_s != null ? `${ns.scan_duration_s.toFixed(1)}s` : "—";

  // ── Risk flags ───────────────────────────────────────────────────────────
  document.getElementById("risk-flags-row").innerHTML =
    (ns.risk_flags || [])
      .map(f => `<span class="flag-pill">${escHtml(f)}</span>`)
      .join(" ");

  // ── Port table ───────────────────────────────────────────────────────────
  renderPortTable(ports);

  // ── Admin panels ─────────────────────────────────────────────────────────
  const adminCard = document.getElementById("admin-card");
  const admins    = ns.admin_exposures || [];
  if (admins.length) {
    adminCard.style.display = "block";
    document.getElementById("admin-list").innerHTML = admins.map(a => `
      <div class="admin-exposure-card">
        <strong>Port ${a.port} — ${escHtml(a.panel_type)}</strong>
        <p style="margin-top:4px;color:var(--text-muted)">${escHtml(a.description)}</p>
      </div>`).join("");
  } else {
    adminCard.style.display = "none";
  }

  // ── OS fingerprint ───────────────────────────────────────────────────────
  const osCard = document.getElementById("os-card");
  if (ns.os_guess) {
    osCard.style.display = "block";
    document.getElementById("os-text").textContent = ns.os_guess;
  } else {
    osCard.style.display = "none";
  }

  // ── 3-tab explanation panel ──────────────────────────────────────────────
  renderExplanationTabs(ns, data.explanation || "");

  // ── Show card ────────────────────────────────────────────────────────────
  document.getElementById("result-card").style.display = "block";
  document.getElementById("result-card").scrollIntoView({ behavior: "smooth" });
  document.getElementById("update-time").textContent = new Date().toLocaleTimeString();

  // Reset to Overview tab on each new scan
  switchExpTab("overview");
}


// ─── Port table with CVE expand rows ─────────────────────────────────────────

function renderPortTable(ports) {
  const tbody     = document.getElementById("port-table-body");
  const portBadge = document.getElementById("port-count-badge");
  portBadge.textContent = ports.length;

  if (!ports.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No open ports found</td></tr>';
    return;
  }

  tbody.innerHTML = "";

  ports.forEach((p, idx) => {
    const riskCls  = p.is_dangerous ? `port-row-${(p.risk_level || "info").toLowerCase()}` : "";
    const dangerTag = p.is_dangerous
      ? `<span class="danger-tag danger-${(p.risk_level || "info").toLowerCase()}">${p.risk_level || "INFO"}</span>`
      : `<span class="danger-tag danger-info">—</span>`;

    // CVE badge
    const cveData     = p.cve_data || {};
    const cveList     = cveData.cves || [];
    const cveCount    = cveList.length;
    const critCount   = cveData.critical_count || 0;
    const highCount   = cveData.high_count     || 0;
    const highestCvss = cveData.highest_cvss   || 0.0;

    let cveBadge = `<span class="cve-badge-btn no-cve">—</span>`;
    if (cveCount > 0) {
      const cls      = critCount > 0 ? "has-critical" : highCount > 0 ? "has-high" : "";
      const cvssText = highestCvss > 0 ? ` · CVSS ${highestCvss.toFixed(1)}` : "";
      cveBadge = `
        <button class="cve-badge-btn ${cls}"
                onclick="toggleCveRow(${idx})"
                id="cve-btn-${idx}"
                title="Click to expand CVE details">
          ⚠ ${cveCount} CVE${cveCount > 1 ? "s" : ""}${cvssText}
        </button>`;
    }

    // Main row
    const tr = document.createElement("tr");
    tr.className = riskCls;
    tr.id = `port-row-${idx}`;
    tr.innerHTML = `
      <td><strong>${p.port}</strong></td>
      <td>${p.protocol}</td>
      <td>${escHtml(p.service_name || "—")}</td>
      <td>${escHtml(p.service_product || "—")}</td>
      <td>${escHtml(p.service_version || "—")}</td>
      <td>${dangerTag}</td>
      <td>${cveBadge}</td>
      <td class="truncate" title="${escHtml(p.danger_reason || p.service_extra || "")}">
        ${escHtml(trunc(p.danger_reason || p.service_extra || "—", 48))}
      </td>`;
    tbody.appendChild(tr);

    // CVE expand row
    if (cveCount > 0) {
      const expandTr = document.createElement("tr");
      expandTr.className    = "cve-expand-row";
      expandTr.id           = `cve-expand-${idx}`;
      expandTr.style.display = "none";

      const productLabel = p.service_product
        ? `${escHtml(p.service_product)} ${escHtml(p.service_version || "")}`.trim()
        : `Port ${p.port}`;

      let cveRows = "";
      for (const cve of cveList) {
        const sev      = (cve.severity || "UNKNOWN").toLowerCase();
        const cvss     = typeof cve.cvss_score === "number" ? cve.cvss_score : 0;
        const cvssDisp = cvss > 0 ? cvss.toFixed(1) : "N/A";
        cveRows += `
          <div class="cve-item">
            <span class="cve-id">${escHtml(cve.cve_id || "—")}</span>
            <span class="cve-cvss cvss-${sev}">${cvssDisp}</span>
            <span class="cve-sev-pill sev-${sev}">${escHtml(cve.severity || "UNKNOWN")}</span>
            <span></span>
            <span class="cve-desc">${escHtml(cve.description || "No description available.")}</span>
          </div>`;
      }

      expandTr.innerHTML = `
        <td colspan="8">
          <div class="cve-expand-inner">
            <h4>CVEs for ${productLabel}</h4>
            ${cveRows}
          </div>
        </td>`;
      tbody.appendChild(expandTr);
    }
  });
}


// ─── CVE row toggle ────────────────────────────────────────────────────────────

function toggleCveRow(idx) {
  const row = document.getElementById(`cve-expand-${idx}`);
  const btn = document.getElementById(`cve-btn-${idx}`);
  if (!row) return;

  const isOpen = row.style.display !== "none";
  if (isOpen) {
    row.style.display = "none";
    if (btn) btn.title = "Click to expand CVE details";
  } else {
    row.style.display  = "table-row";
    row.style.opacity  = "0";
    row.style.transition = "opacity 0.2s ease";
    requestAnimationFrame(() => { row.style.opacity = "1"; });
    if (btn) btn.title = "Click to collapse";
  }
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

function renderExplanationTabs(ns, rawExplanation) {
  _renderOverviewTab(ns, rawExplanation);
  _renderPortDetailsTab(ns);
  _renderCveDetailsTab(ns);
}


// ─── Tab 1: Overview ──────────────────────────────────────────────────────────

function _renderOverviewTab(ns, rawExplanation) {
  const el = document.getElementById("exp-overview-body");

  const riskLevel    = (ns.risk_level || "UNKNOWN").toUpperCase();
  const openCount    = ns.open_port_count || 0;
  const dangerPorts  = (ns.ports || []).filter(p => p.is_dangerous);
  const adminCount   = (ns.admin_exposures || []).length;
  const totalCves    = (ns.ports || []).reduce((s, p) => s + (p.cve_data?.cves?.length || 0), 0);
  const critCves     = (ns.ports || []).reduce((s, p) => s + (p.cve_data?.critical_count || 0), 0);
  const duration     = ns.scan_duration_s != null ? `${ns.scan_duration_s.toFixed(1)}s` : "unknown";

  // Banner
  const bannerMeta = {
    LOW:      { icon: "✅", label: "Low Risk",      cls: "banner-low",      color: "var(--green)" },
    MEDIUM:   { icon: "⚠️",  label: "Medium Risk",   cls: "banner-medium",   color: "var(--amber)" },
    HIGH:     { icon: "🔴", label: "High Risk",     cls: "banner-high",     color: "var(--amber)" },
    CRITICAL: { icon: "🚨", label: "Critical Risk", cls: "banner-critical", color: "var(--red)"   },
    UNKNOWN:  { icon: "❓", label: "Unknown",       cls: "banner-unknown",  color: "var(--text-muted)" },
  };
  const bm = bannerMeta[riskLevel] || bannerMeta.UNKNOWN;

  // Action recommendation
  const actionMeta = {
    LOW:      { label: "Monitor",      cls: "action-allow",       icon: "✅" },
    MEDIUM:   { label: "Review",       cls: "action-warn",        icon: "⚠️"  },
    HIGH:     { label: "Investigate",  cls: "action-investigate", icon: "🔍" },
    CRITICAL: { label: "Act Now",      cls: "action-quarantine",  icon: "🚨" },
    UNKNOWN:  { label: "Re-scan",      cls: "action-warn",        icon: "❓" },
  };
  const am = actionMeta[riskLevel] || actionMeta.UNKNOWN;

  // Narrative paragraphs — generated from data
  const narratives = _buildOverviewNarrative(ns, riskLevel, openCount,
    dangerPorts, adminCount, totalCves, critCves, duration);

  // Tab badge (dangerous port count)
  const portBadgeEl = document.getElementById("exp-badge-portdetails");
  if (portBadgeEl) portBadgeEl.textContent = dangerPorts.length || "";

  // CVE tab badge
  const cveBadgeEl = document.getElementById("exp-badge-cvedetails");
  if (cveBadgeEl) cveBadgeEl.textContent = totalCves || "";

  el.innerHTML = `
    <div class="exp-risk-banner ${bm.cls}">
      <div class="exp-banner-icon">${bm.icon}</div>
      <div class="exp-banner-text">
        <h3 style="color:${bm.color}">${escHtml(ns.target || "Target")} — ${bm.label}</h3>
        <p>${openCount} open port${openCount !== 1 ? "s" : ""} detected
           in ${duration} · ${dangerPorts.length} dangerous
           · ${totalCves} CVE${totalCves !== 1 ? "s" : ""} found</p>
      </div>
    </div>

    <div class="exp-section">
      <div class="exp-section-label">Risk Narrative</div>
      ${narratives.map(n => `<p class="exp-narrative-para">${escHtml(n)}</p>`).join("")}
    </div>

    <hr class="exp-divider">

    <div class="exp-section">
      <div class="exp-section-label">Recommended Action</div>
      <span class="exp-action-pill ${am.cls}">${am.icon} ${am.label}</span>
      ${riskLevel === "CRITICAL"
        ? `<p class="exp-narrative-para" style="margin-top:10px;color:var(--red)">
             Immediate remediation required. Restrict internet access to all dangerous
             ports, rotate any credentials that may have been exposed, and audit access logs.
           </p>`
        : riskLevel === "HIGH"
        ? `<p class="exp-narrative-para" style="margin-top:10px">
             Schedule a remediation review within 24–48 hours.
             Firewall rules should be tightened and services hardened.
           </p>`
        : ""}
    </div>

    ${ns.os_guess ? `
    <hr class="exp-divider">
    <div class="exp-section">
      <div class="exp-section-label">OS Detection</div>
      <p class="exp-narrative-para">${escHtml(ns.os_guess)}</p>
    </div>` : ""}
  `;
}

function _buildOverviewNarrative(ns, riskLevel, openCount, dangerPorts,
                                 adminCount, totalCves, critCves, duration) {
  const parts = [];
  const target = ns.target || "the target";

  // Sentence 1 — overall picture
  if (openCount === 0) {
    parts.push(
      `The scan of ${target} completed in ${duration} and found no open ports. ` +
      `This may indicate the host is behind a firewall or host-based filtering rules are in place.`
    );
  } else {
    const dangerNote = dangerPorts.length > 0
      ? `, of which ${dangerPorts.length} are classified as dangerous`
      : ", none of which are classified as immediately dangerous";
    parts.push(
      `The ${duration} scan of ${target} discovered ${openCount} open ` +
      `port${openCount !== 1 ? "s" : ""}${dangerNote}. ` +
      `The overall risk level is ${riskLevel}.`
    );
  }

  // Sentence 2 — most alarming port(s)
  if (dangerPorts.length > 0) {
    const critical = dangerPorts.filter(p => p.risk_level === "CRITICAL");
    const high     = dangerPorts.filter(p => p.risk_level === "HIGH");

    if (critical.length > 0) {
      const names = critical.slice(0, 3)
        .map(p => `port ${p.port} (${p.service_name || "unknown"})`)
        .join(", ");
      parts.push(
        `${critical.length} CRITICAL port${critical.length > 1 ? "s" : ""} ` +
        `${critical.length > 1 ? "were" : "was"} found open: ${names}. ` +
        `These services pose direct remote exploitation risk and should be ` +
        `firewalled immediately unless explicitly required.`
      );
    } else if (high.length > 0) {
      const names = high.slice(0, 3)
        .map(p => `port ${p.port} (${p.service_name || "unknown"})`)
        .join(", ");
      parts.push(
        `${high.length} HIGH severity port${high.length > 1 ? "s" : ""} detected: ${names}. ` +
        `These services increase attack surface and should be reviewed for necessity ` +
        `and hardened if retained.`
      );
    }
  }

  // Sentence 3 — CVEs
  if (totalCves > 0) {
    if (critCves > 0) {
      parts.push(
        `CVE lookup returned ${totalCves} known vulnerabilit${totalCves > 1 ? "ies" : "y"} ` +
        `across open services, including ${critCves} CRITICAL-severity ` +
        `CVE${critCves > 1 ? "s" : ""} with a CVSS score of 9.0 or above. ` +
        `These represent known, weaponized attack paths and require immediate patching.`
      );
    } else {
      parts.push(
        `CVE lookup identified ${totalCves} known vulnerabilit${totalCves > 1 ? "ies" : "y"} ` +
        `in the detected service versions. Review the CVE Details tab for specifics ` +
        `and prioritize patching by CVSS score.`
      );
    }
  }

  // Sentence 4 — admin panels
  if (adminCount > 0) {
    const ports = (ns.admin_exposures || [])
      .slice(0, 3)
      .map(a => `port ${a.port}`)
      .join(", ");
    parts.push(
      `${adminCount} admin panel${adminCount > 1 ? "s" : ""} ${adminCount > 1 ? "are" : "is"} ` +
      `internet-accessible (${ports}). Administrative interfaces should never be ` +
      `exposed to the public internet — restrict with firewall rules or move ` +
      `behind a VPN immediately.`
    );
  }

  // Sentence 5 — clean bill of health if nothing bad
  if (dangerPorts.length === 0 && totalCves === 0 && adminCount === 0 && openCount > 0) {
    parts.push(
      `No immediately dangerous services were detected. The open ports observed ` +
      `(${(ns.ports || []).slice(0, 5).map(p => p.port).join(", ")}) ` +
      `appear to be standard web or application services. Continue monitoring and ` +
      `ensure all software is kept up to date.`
    );
  }

  return parts;
}


// ─── Tab 2: Port Details ──────────────────────────────────────────────────────

function _renderPortDetailsTab(ns) {
  const el    = document.getElementById("exp-portdetails-body");
  const ports = (ns.ports || []).filter(p => p.is_dangerous);

  if (!ports.length) {
    el.innerHTML = `
      <div class="port-safe-note">
        <div style="font-size:32px;margin-bottom:8px">✅</div>
        No dangerous ports were detected on this target.
      </div>`;
    return;
  }

  el.innerHTML = ports.map((p, idx) => {
    const riskLower = (p.risk_level || "info").toLowerCase();
    const chipCls   = `chip-${riskLower}`;
    const whyCls    = `why-${riskLower}`;

    const explanation = _portExplanation(p);
    const recommendation = _portRecommendation(p);

    return `
      <div class="port-detail-card">
        <div class="port-detail-header" onclick="togglePortDetail('pd-${idx}')">
          <span class="port-num-badge">:${p.port}</span>
          <span class="port-proto-tag">${escHtml(p.protocol)}</span>
          <span class="port-service-label">
            ${escHtml(p.service_product || p.service_name || "Unknown service")}
            ${p.service_version ? `<span style="color:var(--text-muted);font-weight:400"> v${escHtml(p.service_version)}</span>` : ""}
          </span>
          <span class="port-risk-chip ${chipCls}">${p.risk_level || "INFO"}</span>
          <span class="port-chevron" id="chevron-pd-${idx}">▶</span>
        </div>

        <div class="port-detail-body" id="pd-${idx}">
          <div class="port-meta-grid">
            <div class="port-meta-item">
              <div class="meta-lbl">Port</div>
              <div class="meta-val">${p.port}/${p.protocol}</div>
            </div>
            <div class="port-meta-item">
              <div class="meta-lbl">Service</div>
              <div class="meta-val">${escHtml(p.service_name || "—")}</div>
            </div>
            <div class="port-meta-item">
              <div class="meta-lbl">Product</div>
              <div class="meta-val">${escHtml(p.service_product || "—")}</div>
            </div>
            <div class="port-meta-item">
              <div class="meta-lbl">Version</div>
              <div class="meta-val">${escHtml(p.service_version || "—")}</div>
            </div>
            ${p.cpe ? `
            <div class="port-meta-item">
              <div class="meta-lbl">CPE</div>
              <div class="meta-val">${escHtml(trunc(p.cpe, 36))}</div>
            </div>` : ""}
            <div class="port-meta-item">
              <div class="meta-lbl">CVEs found</div>
              <div class="meta-val">${p.cve_data?.cves?.length || 0}</div>
            </div>
          </div>

          <div class="port-why-box ${whyCls}">
            ${escHtml(explanation)}
          </div>

          <div class="port-rec">
            <span class="port-rec-icon">💡</span>
            <span>${escHtml(recommendation)}</span>
          </div>
        </div>
      </div>`;
  }).join("");
}

function togglePortDetail(id) {
  const body    = document.getElementById(id);
  const chevron = document.getElementById(`chevron-${id}`);
  if (!body) return;
  const isOpen = body.classList.contains("body-open");
  body.classList.toggle("body-open", !isOpen);
  if (chevron) chevron.classList.toggle("chevron-open", !isOpen);
}

// Plain-English explanation for a port based on its service + risk level
function _portExplanation(p) {
  const port    = p.port;
  const service = (p.service_name || "").toLowerCase();
  const product = p.service_product || p.service_name || "this service";
  const version = p.service_version ? ` ${p.service_version}` : "";

  const knownExplanations = {
    23:    `Telnet (port 23) transmits all data — including usernames and passwords — in plain text. Anyone on the same network path can intercept credentials with a simple packet sniffer. This protocol was considered obsolete in the 1990s and should never be exposed to the internet.`,
    21:    `FTP (port 21) sends credentials and file data in plain text. Even in "authenticated" mode, login details are trivially captured. Use SFTP (over SSH port 22) or FTPS instead.`,
    22:    `SSH (port 22) is the standard encrypted remote shell protocol. While inherently more secure than Telnet, an exposed SSH port is a high-value target for brute-force and credential-stuffing attacks. Ensure password authentication is disabled and only key-based auth is permitted. Fail2ban or equivalent should be active.`,
    3389:  `RDP (port 3389) is Windows Remote Desktop. It has been the entry point for major ransomware campaigns (WannaCry, REvil). Without MFA and IP allowlisting, exposed RDP is one of the single highest-risk configurations a Windows server can have.`,
    3306:  `MySQL (port 3306) exposed to the internet means your database is directly reachable. With a weak root password or default credentials, an attacker can dump, modify, or destroy your entire database within seconds. This should never be publicly accessible.`,
    5432:  `PostgreSQL (port 5432) exposed to the internet allows direct database access. While PostgreSQL has strong security features, they are moot if the port is reachable by anyone. Restrict to localhost or a private network only.`,
    27017: `MongoDB (port 27017) defaults to no authentication in older versions. Thousands of MongoDB instances have been wiped and ransomed by attackers who found them exposed on this port. Always enable authentication and bind to localhost.`,
    6379:  `Redis (port 6379) has no authentication by default and is designed for use inside trusted networks only. An exposed Redis instance allows full read/write access to all stored data, and in some configurations can be used to achieve Remote Code Execution via config file manipulation.`,
    2375:  `Docker daemon (port 2375) without TLS gives an attacker complete control over all containers and the host. From here they can create privileged containers, escape to the host filesystem, install backdoors, or mine cryptocurrency. This is one of the most critical misconfigurations possible.`,
    445:   `SMB (port 445) was the attack vector for the EternalBlue exploit used by WannaCry, NotPetya, and other catastrophic ransomware campaigns. Modern SMB has been hardened but an exposed port still allows relay attacks, brute-force, and exploitation of unpatched systems.`,
    9200:  `Elasticsearch (port 9200) HTTP API is unauthenticated by default. Exposed Elasticsearch clusters have led to some of the largest data breaches in history — millions of records readable by anyone with the IP address.`,
    4444:  `Port 4444 is the default listener port for Metasploit reverse shells and other C2 frameworks. If this port is open and listening, the host may already be compromised or is running penetration testing infrastructure that should not be internet-accessible.`,
    1433:  `SQL Server (port 1433) exposed to the internet is a critical risk. Automated scanners hit this port constantly looking for weak sa passwords and misconfigured instances. Database exposure can lead to full data exfiltration or ransomware deployment via xp_cmdshell.`,
  };

  if (knownExplanations[port]) return knownExplanations[port];

  // Fallback based on risk level
  const riskPhrases = {
    CRITICAL: `${product}${version} on port ${port} is classified as CRITICAL risk. This service presents a direct remote exploitation pathway and should be removed from internet exposure immediately. The danger reason recorded by the scanner: "${p.danger_reason || "high-risk service"}".`,
    HIGH:     `${product}${version} on port ${port} is classified as HIGH risk. While not always immediately exploitable, this service significantly increases the attack surface. Verify whether it needs to be internet-accessible and apply hardening if retained.`,
    MEDIUM:   `${product}${version} on port ${port} is classified as MEDIUM risk. This service is not inherently insecure but deserves attention — ensure it is patched, configured securely, and monitored for unusual access patterns.`,
  };
  return riskPhrases[p.risk_level] || `${product}${version} on port ${port} was flagged by the scanner. Review access controls and ensure this service is intentionally exposed.`;
}

// Concise actionable recommendation for a port
function _portRecommendation(p) {
  const recs = {
    23:    "Disable Telnet immediately. Replace with SSH. No exceptions.",
    21:    "Replace FTP with SFTP (SSH-based) or FTPS with explicit TLS. Restrict to allowlisted IPs.",
    22:    "Disable password auth (PasswordAuthentication no in sshd_config). Enable fail2ban. Consider moving to a non-standard port.",
    3389:  "Restrict RDP to a VPN or specific IP allowlist. Enforce MFA. Disable if not actively required.",
    3306:  "Bind MySQL to 127.0.0.1 only. Never expose to the internet. Use SSH tunnels for remote access.",
    5432:  "Bind PostgreSQL to localhost. Use SSH tunnels or a private VPN for remote administration.",
    27017: "Enable MongoDB authentication immediately. Bind to localhost or a private network address.",
    6379:  "Set a requirepass in redis.conf. Bind to 127.0.0.1. Use an SSH tunnel for remote access.",
    2375:  "Disable the unauthenticated Docker socket immediately. If remote access is needed, use TLS client certificate auth (port 2376).",
    445:   "Block SMB at the firewall perimeter. Apply all Windows security patches. Disable SMBv1 entirely.",
    9200:  "Enable Elasticsearch security (xpack.security.enabled: true). Bind to localhost or a private network. Require authentication.",
    4444:  "Investigate this host for signs of compromise. Terminate any listener on this port and audit for backdoors.",
    1433:  "Restrict SQL Server to trusted IP ranges only. Disable sa account. Enable SQL Server Audit.",
  };
  return recs[p.port] || (
    p.risk_level === "CRITICAL"
      ? "Block this port at the firewall immediately and investigate whether this service is required."
      : p.risk_level === "HIGH"
      ? "Restrict access to trusted IP ranges. Review service configuration and apply security hardening."
      : "Ensure this service is patched and access is logged. Restrict if not actively required."
  );
}


// ─── Tab 3: CVE Details ───────────────────────────────────────────────────────

function _renderCveDetailsTab(ns) {
  const el    = document.getElementById("exp-cvedetails-body");
  const ports = (ns.ports || []).filter(p => (p.cve_data?.cves?.length || 0) > 0);

  if (!ports.length) {
    el.innerHTML = `
      <div class="cve-no-results">
        <div class="no-icon">🛡</div>
        <p>No CVEs were found for the detected service versions.</p>
        <p style="margin-top:6px;font-size:12px">
          CVE lookup requires both a product name and version to be detected by nmap (-sV).
          Try a more thorough scan type for better version detection.
        </p>
      </div>`;
    return;
  }

  el.innerHTML = ports.map(p => {
    const cves        = p.cve_data.cves || [];
    const productLabel = p.service_product
      ? `${escHtml(p.service_product)} ${escHtml(p.service_version || "")}`.trim()
      : `Unknown service`;

    const cveCards = cves.map(cve => {
      const sev      = (cve.severity || "UNKNOWN").toLowerCase();
      const cvss     = typeof cve.cvss_score === "number" ? cve.cvss_score : 0;
      const cvssDisp = cvss > 0 ? cvss.toFixed(1) : "N/A";
      const cardCls  = `card-${sev}`;
      const cvssClass= `cvss-${sev}`;
      const noteCls  = sev === "critical" ? "note-critical" : sev === "high" ? "note-high" : "";

      const plainEnglish = _cveNarrative(cve, p);

      // version_matched=false means results are product-level (no version detected)
      const versionNote = (p.cve_data.version_matched === false && p.cve_data.search_term)
        ? `<div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;
                       padding:4px 8px;background:var(--bg2);border-radius:4px;">
             ⚠ Product-level match — nmap did not detect a specific version.
             Results are for all known CVEs in <code>${escHtml(p.cve_data.search_term)}</code>,
             not a specific release. Use a Thorough scan for version-exact results.
           </div>`
        : "";

      return `
        <div class="cve-full-card ${cardCls}">
          <div class="cve-full-header">
            <span class="cve-full-id">${escHtml(cve.cve_id || "—")}</span>
            <span class="cve-full-cvss ${cvssClass}">CVSS ${cvssDisp}</span>
            <span class="cve-sev-pill sev-${sev}">${escHtml(cve.severity || "UNKNOWN")}</span>
          </div>
          ${versionNote}
          <p class="cve-full-desc">${escHtml(cve.description || "No description available.")}</p>
          <div class="cve-plain-english ${noteCls}">
            💬 <strong>What this means:</strong> ${escHtml(plainEnglish)}
          </div>
        </div>`;
    }).join("");

    return `
      <div class="cve-detail-port-group">
        <div class="cve-port-group-header">
          <span class="port-num-badge">:${p.port}</span>
          <span class="cve-port-group-svc">${productLabel}</span>
          <span class="cve-port-group-count">${cves.length} CVE${cves.length > 1 ? "s" : ""}</span>
        </div>
        ${cveCards}
      </div>`;
  }).join("");
}

// Plain-English interpretation of a CVE based on its score + context
function _cveNarrative(cve, port) {
  const cvss    = cve.cvss_score || 0;
  const sev     = (cve.severity || "UNKNOWN").toUpperCase();
  const id      = cve.cve_id || "This CVE";
  const product = port.service_product || port.service_name || "this service";
  const portNum = port.port;

  if (sev === "CRITICAL" || cvss >= 9.0) {
    return `${id} is rated CRITICAL (CVSS ${cvss.toFixed(1)}/10). This vulnerability in ` +
      `${product} on port ${portNum} can likely be exploited remotely without authentication. ` +
      `Exploitation typically leads to full system compromise. Patch immediately — ` +
      `there is a high probability that public exploits exist for this CVE.`;
  }
  if (sev === "HIGH" || cvss >= 7.0) {
    return `${id} is a HIGH severity vulnerability (CVSS ${cvss.toFixed(1)}/10) in ${product}. ` +
      `An attacker who can reach port ${portNum} may be able to exploit this to escalate ` +
      `privileges, extract sensitive data, or disrupt service availability. ` +
      `Schedule patching within the next maintenance window.`;
  }
  if (sev === "MEDIUM" || cvss >= 4.0) {
    return `${id} is a MEDIUM severity issue (CVSS ${cvss.toFixed(1)}/10) affecting ${product}. ` +
      `Exploitation typically requires specific conditions or prior access. ` +
      `Include this in your next regular patching cycle.`;
  }
  return `${id} (CVSS ${cvss > 0 ? cvss.toFixed(1) : "N/A"}/10) is a lower-severity finding ` +
    `in ${product}. While not an immediate threat, keeping software up to date ` +
    `eliminates unnecessary risk.`;
}


// ─── Live history polling ──────────────────────────────────────────────────────

async function refreshHistory() {
  try {
    const resp = await fetch("/network/history");
    if (!resp.ok) return;
    const scans = await resp.json();

    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;

    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No network scans yet</td></tr>';
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const rl  = (s.risk_level || "unknown").toLowerCase();
      const lbl = rl === "low" ? "safe" : rl === "critical" ? "malicious" : rl === "unknown" ? "unknown" : "suspicious";
      return `<tr>
        <td><code>${escHtml(s.target)}</code></td>
        <td>${escHtml(s.ip_resolved || "—")}</td>
        <td><span class="auth-pill auth-none">${s.scan_type}</span></td>
        <td>${s.total_open_ports}</td>
        <td><span class="label-badge label-${lbl}">${s.risk_level || "—"}</span></td>
        <td>${s.scan_duration_s != null ? s.scan_duration_s.toFixed(1) + "s" : "—"}</td>
        <td>${s.authorized
          ? '<span class="auth-pill auth-pass">yes</span>'
          : '<span class="auth-pill auth-fail">blocked</span>'}</td>
        <td>${s.scanned_at ? new Date(s.scanned_at).toLocaleString() : "—"}</td>
      </tr>`;
    }).join("");

    document.getElementById("update-time").textContent = new Date().toLocaleTimeString();
  } catch (err) {
    console.warn("Network history refresh failed:", err.message);
  }
}

if (document.getElementById("history-table-body")) {
  setInterval(refreshHistory, 5000);
}


// ─── Utilities ────────────────────────────────────────────────────────────────

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

function escHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function trunc(str, max) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}