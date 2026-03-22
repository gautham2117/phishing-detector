"use strict";

// ── Bootstrap — read URLs from data island ────────────────────────────────────
var _pd         = document.getElementById("page-data");
var SCAN_URL    = _pd.dataset.scanUrl;
var HISTORY_URL = _pd.dataset.historyUrl;
var DETAIL_URL  = _pd.dataset.detailUrl;

// ── DOM handles ───────────────────────────────────────────────────────────────
var dropZone     = document.getElementById("dropZone");
var fileInput    = document.getElementById("fileInput");
var scanBtn      = document.getElementById("scanBtn");
var btnSpinner   = document.getElementById("btnSpinner");
var uploadError  = document.getElementById("uploadError");
var selectedInfo = document.getElementById("selectedInfo");
var selectedName = document.getElementById("selectedName");
var selectedSize = document.getElementById("selectedSize");
var resultsPanel = document.getElementById("resultsPanel");
var historyBody  = document.getElementById("historyBody");

var _selectedFile = null;
var _pollTimer    = null;


// ════════════════════════════════════════════════════════════════════════════
// FILE SELECTION
// ════════════════════════════════════════════════════════════════════════════

function setFile(file) {
    _selectedFile              = file;
    selectedName.textContent   = file.name;
    selectedSize.textContent   = "(" + formatBytes(file.size) + ")";
    selectedInfo.style.display = "flex";
    scanBtn.disabled           = false;
    hideError();
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    if (bytes < 1024)          return bytes + " B";
    if (bytes < 1048576)       return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(2) + " MB";
}

fileInput.addEventListener("change", function () {
    if (this.files && this.files[0]) setFile(this.files[0]);
});

dropZone.addEventListener("dragover", function (e) {
    e.preventDefault();
    dropZone.classList.add("att-drop-active");
});
dropZone.addEventListener("dragleave", function () {
    dropZone.classList.remove("att-drop-active");
});
dropZone.addEventListener("drop", function (e) {
    e.preventDefault();
    dropZone.classList.remove("att-drop-active");
    var files = e.dataTransfer.files;
    if (files && files[0]) setFile(files[0]);
});
dropZone.addEventListener("click", function (e) {
    if (e.target.tagName !== "LABEL" && e.target.tagName !== "INPUT") {
        fileInput.click();
    }
});


// ════════════════════════════════════════════════════════════════════════════
// SCAN SUBMISSION
// ════════════════════════════════════════════════════════════════════════════

scanBtn.addEventListener("click", function () {
    if (!_selectedFile) return;
    submitScan(_selectedFile);
});

function submitScan(file) {
    hideError();
    setScanLoading(true);
    resultsPanel.style.display = "none";

    var emailId = document.getElementById("emailScanId").value.trim();
    var fd      = new FormData();
    fd.append("file", file);
    if (emailId) fd.append("email_scan_id", emailId);

    fetch(SCAN_URL, { method: "POST", body: fd })
        .then(function (r) {
            if (!r.ok) throw new Error("Server responded " + r.status);
            return r.json();
        })
        .then(function (data) {
            setScanLoading(false);
            if (data.error) { showError(data.error || "Analysis failed."); return; }
            renderResults(data);
            resultsPanel.style.display = "block";
            resultsPanel.scrollIntoView({ behavior: "smooth" });
            loadHistory();
        })
        .catch(function (err) {
            setScanLoading(false);
            showError("Request failed: " + err.message);
        });
}

function setScanLoading(on) {
    scanBtn.disabled = on;
    var btnText = document.querySelector(".btn-text");
    if (btnText)   btnText.style.display   = on ? "none"   : "inline";
    if (btnSpinner) btnSpinner.style.display = on ? "inline" : "none";
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING — master dispatcher
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var fa = (data.module_results || {}).file_analysis || {};
    renderVerdict(fa, data);
    renderTypeMismatch(fa);
    renderHashes(fa);
    renderVtResult(fa);
    renderEntropy(fa);
    renderYara(fa);
    renderCapa(fa);
    renderStrings(fa);
    renderMacroDetail(fa);
    renderDeepFindings(fa);
    renderArchiveContents(fa);
    renderEmbeddedUrls(fa);
    renderExplanation(data, fa);   // ← 3-tab explanation
    switchExpTab("att-overview");  // always reset to Overview
}


// ── Verdict ───────────────────────────────────────────────────────────────────
function renderVerdict(fa, data) {
    var verdict = (fa.verdict || data.label || "UNKNOWN").toUpperCase();
    var badge   = document.getElementById("verdictBadge");
    badge.textContent = verdict;
    badge.className   = "att-verdict-badge att-verdict-" + verdict.toLowerCase();

    document.getElementById("verdictFilename").textContent = fa.filename || "";
    document.getElementById("verdictType").textContent     = "Type: " + (fa.file_type || "unknown");
    document.getElementById("verdictSize").textContent     = "Size: " + formatBytes(fa.file_size || 0);

    var actionMap = { ALLOW: "✅ Allow", WARN: "⚠ Warn", QUARANTINE: "🔒 Quarantine", BLOCK: "🚫 Block" };
    document.getElementById("verdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");
}


// ── Type mismatch ─────────────────────────────────────────────────────────────
function renderTypeMismatch(fa) {
    var banner = document.getElementById("typeMismatchBanner");
    if (!banner) return;
    if (fa.type_mismatch) {
        banner.style.display = "block";
        banner.innerHTML =
            "⚠ <strong>File type mismatch detected</strong> — magic bytes indicate <code>"
            + escapeHtml(fa.file_type) + "</code> but the extension suggests a different type.";
    } else {
        banner.style.display = "none";
    }
}


// ── Hashes ────────────────────────────────────────────────────────────────────
function renderHashes(fa) {
    var h = fa.hashes || {};
    document.getElementById("hashMd5").textContent    = h.md5    || "—";
    document.getElementById("hashSha256").textContent = h.sha256 || "—";
    var knownBad = document.getElementById("knownBadBadge");
    if (knownBad) knownBad.style.display = fa.known_bad ? "inline-flex" : "none";
}


// ── VirusTotal ────────────────────────────────────────────────────────────────
function renderVtResult(fa) {
    var card = document.getElementById("vtCard");
    if (!card) return;
    var vt = fa.vt_result;
    if (!vt) { card.style.display = "none"; return; }
    card.style.display = "block";
    var malicious = vt.malicious || 0, total = vt.total || 0;
    var vtSummary = document.getElementById("vtSummary");
    if (vtSummary) {
        var cls = malicious >= 10 ? "att-verdict-malicious"
                : malicious >= 3  ? "att-verdict-suspicious" : "att-verdict-clean";
        vtSummary.innerHTML =
            "<span class='att-verdict-badge " + cls + "'>" + malicious + " / " + total + " engines</span>"
            + (malicious >= 3 ? " &nbsp;<span class='att-flag-pill att-flag-danger'>Known Bad</span>"
                              : " &nbsp;<span class='att-flag-pill att-flag-safe'>Not Flagged</span>")
            + (vt.last_analysis_date ? " &nbsp;<span class='att-ts'>Last scan: " + escapeHtml(vt.last_analysis_date.slice(0,10)) + "</span>" : "")
            + (vt.permalink ? " &nbsp;<a href='" + escapeHtml(vt.permalink) + "' target='_blank' class='att-vt-link'>View on VirusTotal ↗</a>" : "");
    }
}


// ── Entropy gauge ─────────────────────────────────────────────────────────────
function renderEntropy(fa) {
    var entropy = parseFloat(fa.entropy) || 0.0;
    document.getElementById("entropyValue").textContent = entropy.toFixed(4);
    var pct  = Math.min((entropy / 8.0) * 100, 100);
    var fill = document.getElementById("entropyFill");
    fill.style.width = pct + "%";
    var note = document.getElementById("entropyNote");
    if (entropy > 7.2) {
        fill.className   = "att-entropy-bar-fill att-entropy-red";
        note.textContent = "⚠ High entropy — file may be packed or encrypted";
        note.style.color = "var(--red)";
    } else if (entropy > 6.0) {
        fill.className   = "att-entropy-bar-fill att-entropy-amber";
        note.textContent = "Moderately elevated entropy";
        note.style.color = "var(--amber)";
    } else {
        fill.className   = "att-entropy-bar-fill att-entropy-green";
        note.textContent = "Normal entropy range";
        note.style.color = "var(--green)";
    }
}


// ════════════════════════════════════════════════════════════════════════════
// YARA
// ════════════════════════════════════════════════════════════════════════════

function renderYara(fa) {
    var matches = fa.yara_matches || [];
    var countEl = document.getElementById("yaraCount");
    if (countEl) countEl.textContent = matches.length;
    var list = document.getElementById("yaraList");
    if (!list) return;
    list.innerHTML = "";
    if (matches.length === 0) {
        var e = document.createElement("span");
        e.className   = "att-empty-note";
        e.textContent = "No YARA rules matched — file passed all signature checks.";
        list.appendChild(e);
        return;
    }
    matches.forEach(function (rule) {
        var ruleName, severity, namespace;
        if (typeof rule === "string") {
            ruleName = rule; severity = "MEDIUM"; namespace = "";
        } else {
            ruleName  = rule.rule || rule.name || JSON.stringify(rule);
            severity  = (rule.severity || "MEDIUM").toUpperCase();
            namespace = rule.namespace ? "[" + rule.namespace + "] " : "";
        }
        var tagClass = "att-tag " + (severity === "CRITICAL" || severity === "HIGH" ? "att-tag-danger" : "att-tag-warn");
        var tag = document.createElement("span");
        tag.className   = tagClass;
        tag.textContent = namespace + ruleName + " [" + severity + "]";
        list.appendChild(tag);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// CAPA
// ════════════════════════════════════════════════════════════════════════════

function renderCapa(fa) {
    var card            = document.getElementById("capaCard");
    var unavailableBody = document.getElementById("capaUnavailableBody");
    var resultsBody     = document.getElementById("capaResultsBody");
    var countEl         = document.getElementById("capaCount");
    var infoBox         = document.getElementById("capaInfoBox");
    if (!card || !unavailableBody || !resultsBody) return;

    var ca       = fa.capa_analysis || {};
    var capCount = (ca.capabilities || []).length;
    if (countEl) countEl.textContent = capCount;

    if (ca.available && capCount > 0) {
        unavailableBody.style.display = "none";
        resultsBody.style.display     = "block";
        _renderCapaTactics(ca);
        _renderCapaMbc(ca);
        _renderCapaNamespaceSummary(ca);
        _renderCapaTable(ca);
        return;
    }

    unavailableBody.style.display = "block";
    resultsBody.style.display     = "none";
    if (!infoBox) return;

    var explanation  = ca.explanation  || "";
    var setupMessage = ca.setup_message || "";
    var fileType     = (fa.file_type   || "").toLowerCase();
    var isEligible   = (fileType === "exe" || fileType === "elf" || fileType === "dll");

    if (isEligible && setupMessage) {
        var setupLines = setupMessage.split(/\n/).map(function (l) { return l.trim(); }).filter(Boolean);
        var cmdLines   = setupLines.filter(function (l) { return l.startsWith("pip ") || l.startsWith("git ") || l.startsWith("Run:"); });
        var textLines  = setupLines.filter(function (l) { return !l.startsWith("pip ") && !l.startsWith("git ") && !l.startsWith("Run:"); });
        var stepsHtml  = cmdLines.length
            ? "<ul class='capa-setup-steps'>" + cmdLines.map(function (l) { return "<li>" + escapeHtml(l.replace(/^Run:\s*/, "")) + "</li>"; }).join("") + "</ul>"
            : "";
        infoBox.innerHTML =
            "<div class='capa-info-title'>🧠 CAPA Not Installed</div>"
            + "<p>" + escapeHtml(explanation) + "</p>"
            + (textLines.length ? "<p style='margin-top:6px'>" + escapeHtml(textLines.join(" ")) + "</p>" : "")
            + (stepsHtml ? "<p style='margin-top:8px;font-weight:600;color:var(--text);font-size:0.82rem'>Setup commands:</p>" + stepsHtml : "");
    } else {
        infoBox.innerHTML =
            "<div class='capa-info-title'>ℹ CAPA — Not Applicable for This File Type</div>"
            + "<p>" + escapeHtml(explanation) + "</p>";
    }
}

function _renderCapaTactics(ca) {
    var tacticsRow = document.getElementById("capaTacticsRow");
    if (!tacticsRow) return;
    tacticsRow.innerHTML = "";
    var tactics      = ca.attack_tactics || [];
    var capabilities = ca.capabilities   || [];
    var highestSev   = (ca.highest_severity || "LOW").toUpperCase();
    if (tactics.length === 0) {
        var none = document.createElement("span");
        none.className   = "att-capa-tactic-pill sev-low";
        none.textContent = "No ATT&CK tactics mapped";
        tacticsRow.appendChild(none);
        return;
    }
    var tacticSeverity = {};
    capabilities.forEach(function (cap) {
        var sev = (cap.severity || "LOW").toUpperCase();
        (cap.attack_tactics || []).forEach(function (t) {
            var cur = tacticSeverity[t];
            if (!cur || _sevOrder(sev) < _sevOrder(cur)) tacticSeverity[t] = sev;
        });
    });
    tactics.forEach(function (tactic) {
        var sev  = tacticSeverity[tactic] || highestSev;
        var pill = document.createElement("span");
        pill.className   = "att-capa-tactic-pill sev-" + sev.toLowerCase();
        pill.textContent = tactic;
        tacticsRow.appendChild(pill);
    });
}

function _renderCapaMbc(ca) {
    var mbcRow   = document.getElementById("capaMbcRow");
    var mbcLabel = document.getElementById("capaMbcLabel");
    if (!mbcRow || !mbcLabel) return;
    var objectives = ca.mbc_objectives || [];
    if (objectives.length === 0) { mbcRow.style.display = "none"; mbcLabel.style.display = "none"; return; }
    mbcRow.style.display = "flex"; mbcLabel.style.display = "block";
    mbcRow.innerHTML = "";
    objectives.forEach(function (obj) {
        var pill = document.createElement("span");
        pill.className   = "att-capa-tactic-pill sev-medium";
        pill.textContent = obj;
        mbcRow.appendChild(pill);
    });
}

function _renderCapaNamespaceSummary(ca) {
    var container = document.getElementById("capaNsSummary");
    var label     = document.getElementById("capaNsLabel");
    if (!container || !label) return;
    var nsSummary = ca.namespace_summary || {};
    var entries   = Object.keys(nsSummary);
    if (entries.length === 0) { container.style.display = "none"; label.style.display = "none"; return; }
    container.style.display = "block"; label.style.display = "block";
    container.innerHTML = "";
    entries.sort(function (a, b) { return (nsSummary[b] || 0) - (nsSummary[a] || 0); });
    var maxCount = nsSummary[entries[0]] || 1;
    entries.forEach(function (ns) {
        var count = nsSummary[ns] || 0;
        var pct   = Math.round((count / maxCount) * 100);
        var row   = document.createElement("div");
        row.className = "att-capa-ns-row";
        row.innerHTML =
            "<div class='att-capa-ns-name' title='" + escapeHtml(ns) + "'>" + escapeHtml(ns) + "</div>"
            + "<div class='att-capa-ns-bar-bg'><div class='att-capa-ns-bar-fill' style='width:" + pct + "%'></div></div>"
            + "<div class='att-capa-ns-count'>" + count + "</div>";
        container.appendChild(row);
    });
}

function _renderCapaTable(ca) {
    var tbody = document.getElementById("capaTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    var capabilities = ca.capabilities || [];
    if (capabilities.length === 0) {
        var tr = document.createElement("tr");
        tr.innerHTML = "<td colspan='5' class='att-empty-row'>No capabilities detected.</td>";
        tbody.appendChild(tr);
        return;
    }
    capabilities.forEach(function (cap) {
        var name      = cap.name      || "—";
        var namespace = cap.namespace || "—";
        var severity  = (cap.severity || "LOW").toUpperCase();
        var tactics   = cap.attack_tactics || [];
        var mbc       = cap.mbc || [];
        var sevClass  = "att-capa-sev-badge sev-" + severity.toLowerCase();

        var tacticsHtml = tactics.length === 0
            ? "<span class='att-capa-cell-item'>—</span>"
            : "<div class='att-capa-cell-list'>"
              + tactics.slice(0, 3).map(function (t, i) {
                  return "<span class='att-capa-cell-item" + (i === 0 ? " primary" : "") + "'>" + escapeHtml(t) + "</span>";
                }).join("")
              + (tactics.length > 3 ? "<span class='att-capa-cell-item'>+" + (tactics.length - 3) + " more</span>" : "")
              + "</div>";

        var mbcHtml = mbc.length === 0
            ? "<span class='att-capa-cell-item'>—</span>"
            : "<div class='att-capa-cell-list'>"
              + mbc.slice(0, 2).map(function (m, i) {
                  return "<span class='att-capa-cell-item" + (i === 0 ? " primary" : "") + "'>" + escapeHtml(m) + "</span>";
                }).join("")
              + (mbc.length > 2 ? "<span class='att-capa-cell-item'>+" + (mbc.length - 2) + " more</span>" : "")
              + "</div>";

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td><div class='att-capa-cap-name' title='" + escapeHtml(name) + "'>" + escapeHtml(name) + "</div></td>"
            + "<td><div class='att-capa-namespace' title='" + escapeHtml(namespace) + "'>" + escapeHtml(namespace) + "</div></td>"
            + "<td><span class='" + sevClass + "'>" + severity + "</span></td>"
            + "<td>" + tacticsHtml + "</td>"
            + "<td>" + mbcHtml    + "</td>";
        tbody.appendChild(tr);
    });
}

function _sevOrder(sev) {
    return ({ "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3 }[sev] !== undefined)
        ? { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3 }[sev] : 4;
}


// ════════════════════════════════════════════════════════════════════════════
// STRINGS
// ════════════════════════════════════════════════════════════════════════════

function renderStrings(fa) {
    var susStrings  = fa.suspicious_strings  || [];
    var staticFinds = fa.static_findings     || [];
    var useRich     = staticFinds.length > 0;
    var countEl     = document.getElementById("stringsCount");
    if (countEl) countEl.textContent = useRich ? staticFinds.length : susStrings.length;
    var list = document.getElementById("stringsList");
    if (!list) return;
    list.innerHTML = "";
    var totalItems = useRich ? staticFinds.length : susStrings.length;
    if (totalItems === 0) {
        var e = document.createElement("span");
        e.className   = "att-empty-note";
        e.textContent = "No suspicious strings found in this file.";
        list.appendChild(e);
        return;
    }
    if (useRich) {
        staticFinds.forEach(function (item) {
            var wrapper = document.createElement("span");
            wrapper.className = "att-tag att-tag-warn";
            wrapper.style.cursor = "help";
            wrapper.title = (item.count || 1) + " occurrence(s)" + (item.context ? "\nContext: …" + item.context + "…" : "");
            wrapper.appendChild(document.createTextNode(item.string || ""));
            if ((item.count || 1) > 1) {
                var badge = document.createElement("sup");
                badge.style.cssText  = "font-size:10px;margin-left:3px;opacity:.7";
                badge.textContent    = "×" + item.count;
                wrapper.appendChild(badge);
            }
            list.appendChild(wrapper);
        });
    } else {
        susStrings.forEach(function (s) {
            var tag = document.createElement("span");
            tag.className   = "att-tag att-tag-warn";
            tag.textContent = typeof s === "string" ? s : (s.string || JSON.stringify(s));
            list.appendChild(tag);
        });
    }
}


// ── Macro detail ──────────────────────────────────────────────────────────────
function renderMacroDetail(fa) {
    var card = document.getElementById("macroCard");
    if (!card) return;
    var ma = fa.macro_analysis || {};
    if (!ma.has_macros) { card.style.display = "none"; return; }
    card.style.display = "block";

    var streamsEl  = document.getElementById("macroStreams");
    var keywordsEl = document.getElementById("macroKeywords");
    if (streamsEl) {
        streamsEl.textContent = (ma.vba_streams || []).length > 0
            ? ma.vba_streams.join(", ") : "vbaProject.bin";
    }
    if (keywordsEl) {
        keywordsEl.innerHTML = "";
        var kws = ma.macro_keywords || [];
        if (kws.length === 0) {
            keywordsEl.innerHTML = '<span class="att-empty-note">No keyword detail.</span>';
        } else {
            kws.forEach(function (kw) {
                var tag = document.createElement("span");
                tag.className   = "att-tag att-tag-danger";
                tag.textContent = kw;
                keywordsEl.appendChild(tag);
            });
        }
    }

    // Phase 6: suspicious VBA keywords from source
    var vbaSuspiciousRow  = document.getElementById("vbaSuspiciousRow");
    var vbaKeywordsList   = document.getElementById("vbaKeywordsList");
    var macroKeywordCount = document.getElementById("macroKeywordCount");
    var susKws = ma.suspicious_vba_keywords || [];
    if (susKws.length > 0 && vbaSuspiciousRow && vbaKeywordsList) {
        vbaSuspiciousRow.style.display = "block";
        vbaKeywordsList.innerHTML = "";
        if (macroKeywordCount) { macroKeywordCount.textContent = susKws.length; macroKeywordCount.style.display = "inline-flex"; }
        susKws.forEach(function (kw) {
            var tag = document.createElement("span");
            tag.className   = "att-tag att-tag-danger";
            tag.textContent = kw;
            vbaKeywordsList.appendChild(tag);
        });
    } else {
        if (vbaSuspiciousRow) vbaSuspiciousRow.style.display = "none";
        if (macroKeywordCount) macroKeywordCount.style.display = "none";
    }

    // VBA source preview
    var vbaSection = document.getElementById("vbaSourceSection");
    var vbaPreEl   = document.getElementById("vbaSourcePre");
    var vbaSource  = ma.vba_source_preview || "";
    if (vbaSection && vbaPreEl && vbaSource && vbaSource.trim().length > 0) {
        vbaSection.style.display = "block";
        vbaPreEl.innerHTML = _highlightVba(vbaSource);
    } else {
        if (vbaSection) vbaSection.style.display = "none";
    }
}

function toggleVbaSource() {
    var body    = document.getElementById("vbaSourceBody");
    var chevron = document.getElementById("vbaChevron");
    var hint    = document.getElementById("vbaToggleHint");
    if (!body) return;
    var isOpen = body.style.display !== "none";
    body.style.display = isOpen ? "none" : "block";
    if (chevron) chevron.classList.toggle("open", !isOpen);
    if (hint)    hint.textContent = isOpen ? "Click to expand" : "Click to collapse";
}

function _highlightVba(source) {
    var keywords = [
        "Sub","End Sub","Function","End Function","Private","Public","Dim","As","Set","Let",
        "Const","If","Then","Else","ElseIf","End If","For","Each","To","Next","Do","While",
        "Loop","Until","Select","Case","End Select","With","End With","Call","Return","Exit",
        "GoTo","On","Error","Resume","ReDim","Preserve","True","False","Nothing","Empty","Null",
        "String","Integer","Long","Single","Double","Boolean","Object","Variant","Date","Byte",
        "New","Is","Not","And","Or","Xor","Mod","Shell","CreateObject","GetObject","MsgBox",
        "InputBox","Chr","Asc","Len","Left","Right","Mid","InStr","UCase","LCase","Trim",
        "Environ","SendKeys"
    ];
    keywords.sort(function (a, b) { return b.length - a.length; });
    var kwPattern = new RegExp("\\b(" + keywords.map(function (k) { return k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|") + ")\\b", "g");

    return source.split("\n").map(function (line) {
        var commentIdx = _findCommentStart(line);
        if (commentIdx !== -1) {
            var codePart    = _applyKwAndString(escapeHtml(line.slice(0, commentIdx)), kwPattern);
            var commentPart = escapeHtml(line.slice(commentIdx));
            return codePart + '<span class="vba-comment">' + commentPart + "</span>";
        }
        return _applyKwAndString(escapeHtml(line), kwPattern);
    }).join("\n");
}

function _findCommentStart(line) {
    var inString = false;
    for (var i = 0; i < line.length; i++) {
        if (line[i] === '"') inString = !inString;
        else if (line[i] === "'" && !inString) return i;
    }
    return -1;
}

function _applyKwAndString(escaped, kwPattern) {
    escaped = escaped.replace(/(&quot;[^&]*(?:&[a-z]+;[^&]*)*&quot;)/g, '<span class="vba-string">$1</span>');
    escaped = escaped.replace(/(<[^>]+>)|([^<]+)/g, function (m, tag, text) {
        if (tag) return tag;
        return text.replace(kwPattern, '<span class="vba-keyword">$1</span>');
    });
    escaped = escaped.replace(/(<[^>]+>)|(\b\d+(?:\.\d+)?\b)/g, function (m, tag, num) {
        if (tag) return tag;
        return '<span class="vba-number">' + num + "</span>";
    });
    return escaped;
}


// ── Deep findings ─────────────────────────────────────────────────────────────
function renderDeepFindings(fa) {
    var allFindings = [];
    [
        { src: (fa.html_analysis   || {}).html_findings,    icon: "🌐", sev: "danger" },
        { src: (fa.pdf_analysis    || {}).pdf_findings,     icon: "📄", sev: "warn"   },
        { src: (fa.macro_analysis  || {}).macro_findings,   icon: "📝", sev: "danger" },
        { src: (fa.zip_analysis    || {}).zip_findings,     icon: "🗜", sev: "warn"   },
        { src: (fa.script_analysis || {}).script_findings,  icon: "⚡", sev: "warn"   },
        { src: (fa.exe_analysis    || {}).exe_findings,     icon: "🔩", sev: "warn"   },
    ].forEach(function (entry) {
        (entry.src || []).forEach(function (f) {
            allFindings.push({ icon: entry.icon, text: f, sev: entry.sev });
        });
    });

    var card  = document.getElementById("deepCard");
    var listEl = document.getElementById("deepFindings");
    if (!card || !listEl) return;
    listEl.innerHTML = "";
    if (allFindings.length === 0) { card.style.display = "none"; return; }
    card.style.display = "block";
    allFindings.forEach(function (item) {
        var row = document.createElement("div");
        row.className   = "att-finding-row att-finding-" + item.sev;
        row.textContent = item.icon + " " + item.text;
        listEl.appendChild(row);
    });
}


// ── Archive contents ──────────────────────────────────────────────────────────
function renderArchiveContents(fa) {
    var card = document.getElementById("archiveCard");
    if (!card) return;
    var za       = fa.zip_analysis || {};
    var fileList = za.file_list    || [];
    if (fileList.length === 0) { card.style.display = "none"; return; }
    card.style.display = "block";
    var countEl = document.getElementById("archiveFileCount");
    if (countEl) countEl.textContent = za.file_count || fileList.length;
    var tbody = document.getElementById("archiveTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    fileList.slice(0, 30).forEach(function (entry) {
        var name  = typeof entry === "string" ? entry : (entry.name || "");
        var isSus = typeof entry === "object"  ? entry.suspicious : false;
        var tr    = document.createElement("tr");
        if (isSus) tr.className = "row-suspicious";
        tr.innerHTML = "<td><code>" + escapeHtml(name) + "</code>"
            + (isSus ? " <span class='att-tag att-tag-danger'>suspicious</span>" : "") + "</td>";
        tbody.appendChild(tr);
    });
}


// ── Embedded URLs ─────────────────────────────────────────────────────────────
function renderEmbeddedUrls(fa) {
    var card = document.getElementById("embeddedUrlsCard");
    var list = document.getElementById("embeddedUrlList");
    if (!card || !list) return;
    var urls = fa.embedded_urls || [];
    list.innerHTML = "";
    if (urls.length === 0) { card.style.display = "none"; return; }
    card.style.display = "block";
    var countEl = document.getElementById("embeddedUrlCount");
    if (countEl) countEl.textContent = urls.length;
    urls.forEach(function (url) {
        var li = document.createElement("li");
        li.className   = "att-url-item";
        li.textContent = url;
        list.appendChild(li);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// 3-TAB EXPLANATION PANEL
// ════════════════════════════════════════════════════════════════════════════

function switchExpTab(tabName) {
    document.querySelectorAll(".exp-tab").forEach(function (btn) {
        btn.classList.toggle("active", btn.dataset.tab === tabName);
    });
    document.querySelectorAll(".exp-tab-content").forEach(function (panel) {
        panel.classList.toggle("active", panel.id === "exp-tab-" + tabName);
    });
}

function renderExplanation(data, fa) {
    var exp = data.explanation;

    // Fallback: plain string
    if (!exp || typeof exp === "string") {
        var ob = document.getElementById("attExpOverviewBody");
        if (ob) ob.innerHTML = '<p style="color:#cbd5e1;font-size:0.88rem;">' + escapeHtml(exp || "Analysis complete.") + '</p>';
        _renderEmailLink(fa);
        return;
    }

    _renderOverviewTab(exp, data, fa);
    _renderFileDetailsTab(exp);
    _renderSignaturesTab(exp);

    // Update signatures badge
    var sigBadge = document.getElementById("expBadgeSig");
    if (sigBadge) {
        var sigCount = (exp.yara_analysis && exp.yara_analysis.hit_count > 0 ? 1 : 0)
                     + (exp.static_analysis && exp.static_analysis.hit_count > 0 ? 1 : 0);
        sigBadge.textContent = sigCount || "";
    }

    _renderEmailLink(fa);
}


// ── Tab 1: Overview ───────────────────────────────────────────────────────────
function _renderOverviewTab(exp, data, fa) {
    var el = document.getElementById("attExpOverviewBody");
    if (!el) return;

    var verdict  = (exp.verdict   || "CLEAN").toUpperCase();
    var score    = exp.risk_score || 0;
    var action   = (exp.action    || "ALLOW").toUpperCase();
    var summary  = exp.summary    || "";
    var reasons  = exp.verdict_reasons || [];
    var fileInfo = exp.file_info  || {};

    var bannerColour = { CLEAN: "#22c55e", SUSPICIOUS: "#f59e0b", MALICIOUS: "#ef4444" }[verdict] || "#94a3b8";
    var bannerBg     = { CLEAN: "rgba(74,222,128,.07)", SUSPICIOUS: "rgba(251,191,36,.07)", MALICIOUS: "rgba(248,113,113,.09)" }[verdict] || "var(--bg3)";
    var bannerBorder = { CLEAN: "rgba(74,222,128,.25)", SUSPICIOUS: "rgba(251,191,36,.25)", MALICIOUS: "rgba(248,113,113,.30)" }[verdict] || "var(--border)";
    var bannerIcon   = { CLEAN: "✅", SUSPICIOUS: "⚠️", MALICIOUS: "🚨" }[verdict] || "❓";

    var actionColour = { ALLOW: "#22c55e", WARN: "#f59e0b", QUARANTINE: "#ef4444" }[action] || "#94a3b8";
    var actionIcon   = { ALLOW: "✅", WARN: "⚠️", QUARANTINE: "🔒" }[action] || "—";
    var actionLabel  = { ALLOW: "Allow", WARN: "Review", QUARANTINE: "Quarantine" }[action] || action;

    var html =
        '<div style="display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:var(--radius);'
        + 'margin-bottom:20px;border:1px solid ' + bannerBorder + ';background:' + bannerBg + '">'
        + '<div style="font-size:28px;line-height:1">' + bannerIcon + '</div>'
        + '<div>'
        +   '<div style="font-size:15px;font-weight:700;color:' + bannerColour + ';margin-bottom:4px">'
        +     escapeHtml(fileInfo.filename || "File") + ' — ' + verdict
        +   '</div>'
        +   '<div style="font-size:13px;color:var(--text-muted)">'
        +     'Risk score ' + score.toFixed(1) + '/100'
        +     (fileInfo.type    ? ' · Type: '     + escapeHtml(fileInfo.type)           : '')
        +     (fileInfo.size_kb ? ' · '           + fileInfo.size_kb + ' KB'             : '')
        +     (fileInfo.type_mismatch ? ' · <span style="color:var(--red)">⚠ Type mismatch</span>' : '')
        +   '</div>'
        + '</div>'
        + '</div>';

    if (summary) {
        html +=
            '<div style="margin-bottom:16px">'
            + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
            +   'color:var(--text-muted);margin-bottom:8px">Summary</div>'
            + '<p style="font-size:13px;line-height:1.8;color:var(--text);margin:0">' + escapeHtml(summary) + '</p>'
            + '</div>';
    }

    if (reasons.length > 0) {
        html +=
            '<div style="margin-bottom:16px">'
            + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
            +   'color:var(--text-muted);margin-bottom:8px">Why This Verdict</div>'
            + '<ul style="margin:0;padding-left:18px">'
            + reasons.map(function (r) {
                return '<li style="font-size:13px;color:var(--text);margin-bottom:4px">' + escapeHtml(r) + '</li>';
              }).join("")
            + '</ul>'
            + '</div>';
    }

    html +=
        '<div>'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
        +   'color:var(--text-muted);margin-bottom:8px">Recommended Action</div>'
        + '<span style="display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:20px;'
        +   'font-size:12px;font-weight:700;text-transform:uppercase;'
        +   'background:' + actionColour + '18;color:' + actionColour
        +   ';border:1px solid ' + actionColour + '44">'
        +   actionIcon + ' ' + actionLabel
        + '</span>'
        + '</div>';

    el.innerHTML = html;
}


// ── Tab 2: File Details ───────────────────────────────────────────────────────
function _renderFileDetailsTab(exp) {
    var el = document.getElementById("attExpFileDetailsBody");
    if (!el) return;

    var fileInfo = exp.file_info         || {};
    var entropyA = exp.entropy_analysis  || {};
    var pdfA     = exp.pdf_analysis      || null;
    var capaA    = exp.capa_analysis     || null;

    var html = "";

    // File properties grid
    var props = [
        { label: "Filename", value: fileInfo.filename  || "—", mono: true },
        { label: "Type",     value: fileInfo.type      || "—" },
        { label: "Size",     value: (fileInfo.size_kb  || 0) + " KB" },
        { label: "Category", value: fileInfo.category  || "—" },
        { label: "Mismatch", value: fileInfo.type_mismatch ? "⚠ Yes" : "No",
          highlight: !!fileInfo.type_mismatch },
    ];

    html +=
        '<div style="margin-bottom:18px">'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
        +   'color:var(--text-muted);margin-bottom:8px">File Properties</div>'
        + '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px">';

    props.forEach(function (p) {
        html +=
            '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px">'
            + '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">'
            +   escapeHtml(p.label) + '</div>'
            + '<div style="font-size:13px;font-weight:600;word-break:break-all;'
            +   'color:' + (p.highlight ? 'var(--red)' : 'var(--text)') + ';'
            +   (p.mono ? 'font-family:monospace' : '') + '">'
            +   escapeHtml(String(p.value)) + '</div>'
            + '</div>';
    });
    html += '</div></div>';

    // Entropy
    var eVal    = entropyA.value     || 0;
    var eColour = { green: "#22c55e", amber: "#f59e0b", red: "#ef4444" }[entropyA.colour] || "#94a3b8";
    var ePct    = entropyA.bar_pct   || 0;
    var eIcon   = entropyA.colour === "red" ? "🔴" : entropyA.colour === "amber" ? "🟡" : "🟢";

    html +=
        '<div style="margin-bottom:18px">'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
        +   'color:var(--text-muted);margin-bottom:8px">' + eIcon + ' Shannon Entropy</div>'
        + '<div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px 14px">'
        +   '<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
        +     '<span style="font-size:12px;color:var(--text-muted)">Entropy value</span>'
        +     '<span style="font-size:14px;font-weight:700;color:' + eColour + '">' + eVal.toFixed(4) + ' / 8.0</span>'
        +   '</div>'
        +   '<div style="background:var(--bg2);border-radius:4px;height:6px;overflow:hidden;margin-bottom:8px">'
        +     '<div style="width:' + ePct + '%;height:100%;background:' + eColour + ';transition:width .4s"></div>'
        +   '</div>'
        +   '<p style="font-size:13px;color:var(--text);margin:0">' + escapeHtml(entropyA.interpretation || "") + '</p>'
        + '</div>'
        + '</div>';

    // PDF analysis
    if (pdfA) {
        var pdfFlags  = pdfA.flags || [];
        var pdfColour = pdfFlags.length > 0 ? "#f97316" : "#22c55e";
        html +=
            '<div style="margin-bottom:18px">'
            + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
            +   'color:var(--text-muted);margin-bottom:8px">📄 PDF Structure Analysis</div>'
            + '<div style="background:var(--bg3);border:1px solid ' + pdfColour + '44;border-radius:6px;padding:12px 14px">'
            + '<p style="font-size:13px;color:var(--text);margin-bottom:' + (pdfFlags.length ? "10px" : "0") + '">'
            +   escapeHtml(pdfA.explanation || "") + '</p>';
        if (pdfFlags.length > 0) {
            html += '<ul style="margin:0;padding-left:18px">';
            pdfFlags.forEach(function (f) {
                html += '<li style="color:#fed7aa;font-size:12px;margin-bottom:4px">⚠ ' + escapeHtml(f) + '</li>';
            });
            html += '</ul>';
        }
        html += '</div></div>';
    }

    // CAPA
    if (capaA) {
        var capCount   = capaA.capability_count || 0;
        var highestSev = (capaA.highest_severity || "NONE").toUpperCase();
        var capColour  = highestSev === "CRITICAL" ? "#ef4444"
                       : highestSev === "HIGH"     ? "#f97316"
                       : highestSev === "MEDIUM"   ? "#f59e0b"
                       : capCount > 0 ? "#22c55e" : "#64748b";
        var capIcon    = !capaA.available ? "ℹ"
                       : capCount === 0   ? "✅"
                       : highestSev === "CRITICAL" ? "🚨" : "🧠";

        html +=
            '<div style="margin-bottom:18px">'
            + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
            +   'color:var(--text-muted);margin-bottom:8px">' + capIcon + ' CAPA Behavioral Analysis</div>'
            + '<div style="background:var(--bg3);border:1px solid ' + capColour + '44;border-radius:6px;padding:12px 14px">'
            + '<p style="font-size:13px;color:var(--text);margin-bottom:' + ((capaA.attack_tactics || []).length ? "10px" : "0") + '">'
            +   escapeHtml(capaA.explanation || "") + '</p>';
        if ((capaA.attack_tactics || []).length > 0) {
            html += '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">';
            capaA.attack_tactics.forEach(function (t) {
                html +=
                    '<span style="padding:2px 8px;border-radius:99px;font-size:11px;'
                    + 'background:' + capColour + '18;color:' + capColour
                    + ';border:1px solid ' + capColour + '44">' + escapeHtml(t) + '</span>';
            });
            html += '</div>';
        }
        if (capaA.risk_contribution > 0) {
            html += '<p style="font-size:11px;color:var(--text-muted);margin-top:8px">CAPA contributed '
                  + capaA.risk_contribution.toFixed(1) + ' points to the risk score.</p>';
        }
        html += '</div></div>';
    }

    el.innerHTML = html;
}


// ── Tab 3: Signatures & Entropy ───────────────────────────────────────────────
function _renderSignaturesTab(exp) {
    var el = document.getElementById("attExpSignaturesBody");
    if (!el) return;

    var staticA = exp.static_analysis || {};
    var yaraA   = exp.yara_analysis   || {};
    var html    = "";

    // Static strings
    var strHits   = staticA.hits      || [];
    var strCount  = staticA.hit_count || 0;
    var strColour = strCount > 0 ? "#f59e0b" : "#22c55e";
    html +=
        '<div style="margin-bottom:18px">'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
        +   'color:var(--text-muted);margin-bottom:8px">'
        +   (strCount > 0 ? "⚡" : "✅") + ' Static String Analysis (' + strCount + ' hit' + (strCount !== 1 ? "s" : "") + ')'
        + '</div>'
        + '<div style="background:var(--bg3);border:1px solid ' + strColour + '44;border-radius:6px;padding:12px 14px">'
        + '<p style="font-size:11px;color:var(--text-muted);margin-bottom:6px"><em>' + escapeHtml(staticA.method || "") + '</em></p>'
        + '<p style="font-size:13px;color:var(--text);margin-bottom:' + (strHits.length ? "10px" : "0") + '">'
        +   escapeHtml(staticA.explanation || "") + '</p>';
    if (strHits.length > 0) {
        html += '<div style="display:flex;flex-wrap:wrap;gap:5px">';
        strHits.forEach(function (hit) {
            var label = typeof hit === "string" ? hit : (hit.string || "");
            var count = typeof hit === "object" && hit.count ? " ×" + hit.count : "";
            html +=
                '<span style="padding:2px 8px;border-radius:99px;font-size:11px;'
                + 'background:rgba(251,191,36,0.12);color:#fbbf24;border:1px solid rgba(251,191,36,0.3)">'
                + escapeHtml(label + count) + '</span>';
        });
        html += '</div>';
    }
    html += '</div></div>';

    // YARA
    var yaraHits  = yaraA.hits      || [];
    var yaraCount = yaraA.hit_count || 0;
    var yaraColour = yaraCount > 0 ? "#ef4444" : "#22c55e";
    var sevColour  = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#94a3b8" };

    html +=
        '<div>'
        + '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;'
        +   'color:var(--text-muted);margin-bottom:8px">'
        +   (yaraCount > 0 ? "🚨" : "✅") + ' YARA Signature Matching (' + yaraCount + ' match' + (yaraCount !== 1 ? "es" : "") + ')'
        + '</div>'
        + '<div style="background:var(--bg3);border:1px solid ' + yaraColour + '44;border-radius:6px;padding:12px 14px">'
        + '<p style="font-size:11px;color:var(--text-muted);margin-bottom:6px"><em>' + escapeHtml(yaraA.method || "") + '</em></p>'
        + '<p style="font-size:13px;color:var(--text);margin-bottom:' + (yaraHits.length ? "10px" : "0") + '">'
        +   escapeHtml(yaraA.explanation || "") + '</p>';
    if (yaraHits.length > 0) {
        html += '<div style="display:flex;flex-direction:column;gap:5px">';
        yaraHits.forEach(function (m) {
            var sc = sevColour[(m.severity || "").toUpperCase()] || "#94a3b8";
            html +=
                '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;'
                + 'background:var(--bg2);border-left:3px solid ' + sc + ';border-radius:3px">'
                + '<span style="font-family:monospace;font-size:12px;color:var(--text);flex:1">'
                +   escapeHtml(m.rule || m.name || "") + '</span>'
                + '<span style="font-size:10px;font-weight:700;color:' + sc + '">' + escapeHtml(m.severity || "") + '</span>'
                + (m.namespace ? '<span style="font-size:10px;color:var(--text-muted)">' + escapeHtml(m.namespace) + '</span>' : '')
                + '</div>';
        });
        html += '</div>';
    }
    html += '</div></div>';

    el.innerHTML = html;
}

function _renderEmailLink(fa) {
    var emailId = fa ? fa.email_id : null;
    var linkRow = document.getElementById("emailLinkRow");
    var linkEl  = document.getElementById("emailScanLink");
    if (linkRow && linkEl) {
        if (emailId) {
            linkEl.textContent    = "#" + emailId;
            linkEl.href           = "/email_scan/detail/" + emailId;
            linkRow.style.display = "block";
        } else {
            linkRow.style.display = "none";
        }
    }
}


// ════════════════════════════════════════════════════════════════════════════
// COPY BUTTONS
// ════════════════════════════════════════════════════════════════════════════

document.addEventListener("click", function (e) {
    if (!e.target.classList.contains("att-copy-btn")) return;
    var el = document.getElementById(e.target.dataset.target);
    if (!el) return;
    var text = el.textContent;
    if (!text || text === "—") return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
            e.target.textContent = "Copied!";
            setTimeout(function () { e.target.textContent = "Copy"; }, 1500);
        });
    } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        e.target.textContent = "Copied!";
        setTimeout(function () { e.target.textContent = "Copy"; }, 1500);
    }
});


// ════════════════════════════════════════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") return;
            renderHistory(data.scans || []);
        })
        .catch(function () {});
}

function renderHistory(scans) {
    historyBody.innerHTML = "";
    if (!scans || scans.length === 0) {
        historyBody.innerHTML = '<tr><td colspan="8" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }
    scans.forEach(function (s) {
        var verdict      = (s.verdict || "UNKNOWN").toUpperCase();
        var verdictClass = { CLEAN: "badge-safe", SUSPICIOUS: "badge-suspicious", MALICIOUS: "badge-malicious" }[verdict] || "badge-safe";
        var ts      = s.scanned_at ? s.scanned_at.replace("T", " ").replace("Z", "").slice(0, 19) : "—";
        var yCount  = Array.isArray(s.yara_matches) ? s.yara_matches.length : 0;
        var entropy = parseFloat(s.entropy || 0);
        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + escapeHtml(String(s.id)) + "</td>"
            + "<td class='att-fname'>" + escapeHtml(s.filename || "—") + "</td>"
            + "<td class='att-type'>"  + escapeHtml(s.file_type || "—") + "</td>"
            + "<td>" + formatBytes(s.file_size || 0) + "</td>"
            + "<td class='" + (entropy > 7.2 ? "att-cell-red" : entropy > 6.0 ? "att-cell-amber" : "") + "'>"
            +   entropy.toFixed(2) + "</td>"
            + "<td class='" + (yCount > 0 ? "att-cell-red" : "") + "'>" + yCount + "</td>"
            + "<td><span class='badge " + verdictClass + "'>" + verdict + "</span></td>"
            + "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// ERROR HELPERS
// ════════════════════════════════════════════════════════════════════════════

function showError(msg) { uploadError.textContent = "⚠ " + msg; uploadError.style.display = "block"; }
function hideError()    { uploadError.style.display = "none"; uploadError.textContent = ""; }


// ════════════════════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
_pollTimer = setInterval(loadHistory, 5000);