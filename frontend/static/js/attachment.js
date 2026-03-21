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
    _selectedFile                = file;
    selectedName.textContent     = file.name;
    selectedSize.textContent     = "(" + formatBytes(file.size) + ")";
    selectedInfo.style.display   = "flex";
    scanBtn.disabled             = false;
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
            if (data.error) {
                showError(data.error || "Analysis failed.");
                return;
            }
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
    if (btnText) btnText.style.display = on ? "none" : "inline";
    if (btnSpinner) btnSpinner.style.display = on ? "inline" : "none";
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING — master dispatcher
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    // Extract the file_analysis sub-dict — all render helpers read from here
    var fa = (data.module_results || {}).file_analysis || {};

    renderVerdict(fa, data);
    renderTypeMismatch(fa);
    renderHashes(fa);
    renderVtResult(fa);
    renderEntropy(fa);
    renderYara(fa);          // ← YARA: reads fa.yara_matches
    renderStrings(fa);       // ← Suspicious strings: reads fa.suspicious_strings
    renderMacroDetail(fa);
    renderDeepFindings(fa);
    renderArchiveContents(fa);
    renderEmbeddedUrls(fa);
    renderExplanation(data, fa);
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

    var actionMap = {
        ALLOW:      "✅ Allow",
        WARN:       "⚠ Warn",
        QUARANTINE: "🔒 Quarantine",
        BLOCK:      "🚫 Block"
    };
    document.getElementById("verdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");

    var reasonsEl = document.getElementById("verdictReasons");
    if (reasonsEl) {
        var reasons = fa.verdict_reasons || [];
        if (reasons.length > 0) {
            reasonsEl.innerHTML = "<ul class='att-reasons-list'>" +
                reasons.map(function (r) {
                    return "<li>" + escapeHtml(r) + "</li>";
                }).join("") + "</ul>";
            reasonsEl.style.display = "block";
        } else {
            reasonsEl.style.display = "none";
        }
    }
}


// ── Type mismatch warning ─────────────────────────────────────────────────────
function renderTypeMismatch(fa) {
    var banner = document.getElementById("typeMismatchBanner");
    if (!banner) return;
    if (fa.type_mismatch) {
        banner.style.display = "block";
        banner.innerHTML =
            "⚠ <strong>File type mismatch detected</strong> — " +
            "magic bytes indicate <code>" + escapeHtml(fa.file_type) + "</code> " +
            "but the extension suggests a different type. " +
            "This is a common malware camouflage technique.";
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


// ── VirusTotal result ─────────────────────────────────────────────────────────
function renderVtResult(fa) {
    var card = document.getElementById("vtCard");
    if (!card) return;

    var vt = fa.vt_result;
    if (!vt) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";

    var malicious  = vt.malicious  || 0;
    var total      = vt.total      || 0;
    var permalink  = vt.permalink  || "";
    var lastDate   = vt.last_analysis_date || "";

    var vtSummary = document.getElementById("vtSummary");
    if (vtSummary) {
        var cls = malicious >= 10 ? "att-verdict-malicious"
                : malicious >= 3  ? "att-verdict-suspicious"
                : "att-verdict-clean";
        vtSummary.innerHTML =
            "<span class='att-verdict-badge " + cls + "'>" +
            malicious + " / " + total + " engines</span>" +
            (malicious >= 3
                ? " &nbsp;<span class='att-flag-pill att-flag-danger'>Known Bad</span>"
                : " &nbsp;<span class='att-flag-pill att-flag-safe'>Not Flagged</span>") +
            (lastDate ? " &nbsp;<span class='att-ts'>Last scan: " + escapeHtml(lastDate.slice(0,10)) + "</span>" : "") +
            (permalink ? " &nbsp;<a href='" + escapeHtml(permalink) + "' target='_blank' class='att-vt-link'>View on VirusTotal ↗</a>" : "");
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
        fill.className    = "att-entropy-bar-fill att-entropy-red";
        note.textContent  = "⚠ High entropy — file may be packed or encrypted";
        note.style.color  = "var(--red)";
    } else if (entropy > 6.0) {
        fill.className    = "att-entropy-bar-fill att-entropy-amber";
        note.textContent  = "Moderately elevated entropy";
        note.style.color  = "var(--amber)";
    } else {
        fill.className    = "att-entropy-bar-fill att-entropy-green";
        note.textContent  = "Normal entropy range";
        note.style.color  = "var(--green)";
    }
}


// ════════════════════════════════════════════════════════════════════════════
// YARA MATCHES — dynamic rendering
// Reads: fa.yara_matches  (list of strings or rule-objects from file_analyzer)
// ════════════════════════════════════════════════════════════════════════════

function renderYara(fa) {
    var matches = fa.yara_matches || [];

    // Always update the count badge
    var countEl = document.getElementById("yaraCount");
    if (countEl) countEl.textContent = matches.length;

    var list = document.getElementById("yaraList");
    if (!list) return;

    // Clear whatever was there before (static placeholder or previous result)
    list.innerHTML = "";

    if (matches.length === 0) {
        // No matches — show clean message
        var emptySpan = document.createElement("span");
        emptySpan.className   = "att-empty-note";
        emptySpan.textContent = "No YARA rules matched — file passed all signature checks.";
        list.appendChild(emptySpan);
        return;
    }

    // Render each match as a coloured tag
    matches.forEach(function (rule) {
        // rule may be a plain string or an object {rule, namespace, severity, ...}
        var ruleName, severity, namespace, meta;

        if (typeof rule === "string") {
            ruleName  = rule;
            severity  = "MEDIUM";
            namespace = "";
            meta      = "";
        } else {
            ruleName  = rule.rule      || rule.name || JSON.stringify(rule);
            severity  = (rule.severity || "MEDIUM").toUpperCase();
            namespace = rule.namespace ? "[" + rule.namespace + "] " : "";
            // Show meta description if present
            meta = (rule.meta && rule.meta.description)
                ? " — " + rule.meta.description
                : "";
        }

        // Choose colour based on severity
        var tagClass = "att-tag ";
        if (severity === "CRITICAL" || severity === "HIGH") {
            tagClass += "att-tag-danger";
        } else {
            tagClass += "att-tag-warn";
        }

        var tag = document.createElement("span");
        tag.className = tagClass;
        tag.title     = namespace + ruleName + meta + " [" + severity + "]";
        tag.textContent = namespace + ruleName + " [" + severity + "]";

        list.appendChild(tag);
    });

    // If more than 10 matches, add a summary badge
    if (matches.length > 10) {
        var summaryTag = document.createElement("span");
        summaryTag.className   = "att-tag att-tag-danger";
        summaryTag.textContent = "+" + (matches.length - 10) + " more rules…";
        list.appendChild(summaryTag);
    }
}


// ════════════════════════════════════════════════════════════════════════════
// SUSPICIOUS STRINGS — dynamic rendering
// Reads: fa.suspicious_strings  (list of plain strings)
//        fa.static_findings     (list of {string, count, context} objects)
// ════════════════════════════════════════════════════════════════════════════

function renderStrings(fa) {
    // suspicious_strings is a flat list of string names (e.g. "powershell")
    // static_findings has richer objects with count and context snippets
    var susStrings   = fa.suspicious_strings   || [];
    var staticFinds  = fa.static_findings      || [];

    // Prefer static_findings (richer) but fall back to suspicious_strings
    var useRich = staticFinds.length > 0;

    var countEl = document.getElementById("stringsCount");
    if (countEl) {
        countEl.textContent = useRich ? staticFinds.length : susStrings.length;
    }

    var list = document.getElementById("stringsList");
    if (!list) return;

    // Clear previous content (removes static placeholder)
    list.innerHTML = "";

    var totalItems = useRich ? staticFinds.length : susStrings.length;

    if (totalItems === 0) {
        var emptySpan = document.createElement("span");
        emptySpan.className   = "att-empty-note";
        emptySpan.textContent = "No suspicious strings found in this file.";
        list.appendChild(emptySpan);
        return;
    }

    if (useRich) {
        // Render rich objects: show string name + count badge + context tooltip
        staticFinds.forEach(function (item) {
            var strName = item.string  || "";
            var count   = item.count   || 1;
            var context = item.context || "";

            var wrapper = document.createElement("span");
            wrapper.className = "att-tag att-tag-warn";
            wrapper.style.cursor = "help";
            wrapper.title = count + " occurrence(s)" +
                (context ? "\nContext: …" + context + "…" : "");

            // String name
            var nameText = document.createTextNode(strName);
            wrapper.appendChild(nameText);

            // Count badge
            if (count > 1) {
                var badge = document.createElement("sup");
                badge.style.cssText = "font-size:10px;margin-left:3px;opacity:.7";
                badge.textContent   = "×" + count;
                wrapper.appendChild(badge);
            }

            list.appendChild(wrapper);
        });
    } else {
        // Render plain strings
        susStrings.forEach(function (s) {
            var strName = typeof s === "string" ? s : (s.string || JSON.stringify(s));
            var tag = document.createElement("span");
            tag.className   = "att-tag att-tag-warn";
            tag.textContent = strName;
            list.appendChild(tag);
        });
    }
}


// ── Macro detail ──────────────────────────────────────────────────────────────
function renderMacroDetail(fa) {
    var card = document.getElementById("macroCard");
    if (!card) return;

    var ma = fa.macro_analysis || {};
    if (!ma.has_macros) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";

    var streamsEl  = document.getElementById("macroStreams");
    var keywordsEl = document.getElementById("macroKeywords");

    if (streamsEl) {
        var streams = ma.vba_streams || [];
        streamsEl.textContent = streams.length > 0
            ? streams.join(", ")
            : "vbaProject.bin";
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
}


// ── Deep findings (HTML/PDF/Macro/ZIP) ───────────────────────────────────────
function renderDeepFindings(fa) {
    var allFindings = [];

    if ((fa.html_analysis   || {}).html_findings)   {
        (fa.html_analysis.html_findings   || []).forEach(function (f) {
            allFindings.push({ icon: "🌐", text: f, sev: "danger" });
        });
    }
    if ((fa.pdf_analysis    || {}).pdf_findings)    {
        (fa.pdf_analysis.pdf_findings     || []).forEach(function (f) {
            allFindings.push({ icon: "📄", text: f, sev: "warn" });
        });
    }
    if ((fa.macro_analysis  || {}).macro_findings)  {
        (fa.macro_analysis.macro_findings || []).forEach(function (f) {
            allFindings.push({ icon: "📝", text: f, sev: "danger" });
        });
    }
    if ((fa.zip_analysis    || {}).zip_findings)    {
        (fa.zip_analysis.zip_findings     || []).forEach(function (f) {
            allFindings.push({ icon: "🗜", text: f, sev: "warn" });
        });
    }
    if ((fa.script_analysis || {}).script_findings) {
        (fa.script_analysis.script_findings || []).forEach(function (f) {
            allFindings.push({ icon: "⚡", text: f, sev: "warn" });
        });
    }
    if ((fa.exe_analysis    || {}).exe_findings)    {
        (fa.exe_analysis.exe_findings     || []).forEach(function (f) {
            allFindings.push({ icon: "🔩", text: f, sev: "warn" });
        });
    }

    var card = document.getElementById("deepCard");
    var listEl = document.getElementById("deepFindings");
    if (!card || !listEl) return;
    listEl.innerHTML = "";

    if (allFindings.length === 0) {
        card.style.display = "none";
        return;
    }
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
    if (fileList.length === 0) {
        card.style.display = "none";
        return;
    }
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
        tr.innerHTML =
            "<td><code>" + escapeHtml(name) + "</code>" +
            (isSus ? " <span class='att-tag att-tag-danger'>suspicious</span>" : "") +
            "</td>";
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

    if (urls.length === 0) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";

    var countEl = document.getElementById("embeddedUrlCount");
    if (countEl) countEl.textContent = urls.length;

    urls.forEach(function (url) {
        var li = document.createElement("li");
        li.className = "att-url-item";
        li.textContent = url;
        list.appendChild(li);
    });
}


// ── Explanation ───────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// renderExplanation — upgraded to render the structured explanation dict
// returned by _build_file_explanation() in scan_router.py.
//
// The backend now returns data.explanation as a dict with sections:
//   verdict, risk_score, action, summary, file_info,
//   static_analysis, yara_analysis, entropy_analysis,
//   pdf_analysis (PDF only), risk_flags, verdict_reasons
//
// Falls back gracefully to plain-text if explanation is still a string
// (for backward compatibility with other scan types).
// ─────────────────────────────────────────────────────────────────────────────

function renderExplanation(data, fa) {
    var container = document.getElementById("explanationText");
    if (!container) return;

    var exp = data.explanation;

    // ── Fallback: plain string (non-file scans or old responses) ─────────────
    if (!exp || typeof exp === "string") {
        container.innerHTML =
            '<p class="att-exp-summary">' +
            _escHtml(exp || "Analysis complete.") +
            "</p>";
        _renderEmailLink(fa);
        return;
    }

    // ── Rich structured explanation (file scans) ──────────────────────────────
    var verdict   = (exp.verdict     || "CLEAN").toUpperCase();
    var score     = exp.risk_score   || 0;
    var action    = (exp.action      || "ALLOW").toUpperCase();
    var summary   = exp.summary      || "";
    var fileInfo  = exp.file_info    || {};
    var staticA   = exp.static_analysis  || {};
    var yaraA     = exp.yara_analysis    || {};
    var entropyA  = exp.entropy_analysis || {};
    var pdfA      = exp.pdf_analysis     || null;
    var reasons   = exp.verdict_reasons  || [];

    var verdictColour = { CLEAN: "#22c55e", SUSPICIOUS: "#f59e0b", MALICIOUS: "#ef4444" };
    var actionColour  = { ALLOW: "#22c55e", WARN: "#f59e0b", QUARANTINE: "#ef4444" };
    var vColour = verdictColour[verdict] || "#94a3b8";
    var aColour = actionColour[action]   || "#94a3b8";

    var html = "";

    // ── 1. Header bar ─────────────────────────────────────────────────────────
    html += '<div class="att-exp-header" style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">';
    html +=   '<span class="att-exp-verdict" style="font-size:1.05rem;font-weight:700;color:' + vColour + ';">' + verdict + '</span>';
    html +=   '<span class="att-exp-score" style="color:#94a3b8;font-size:0.85rem;">Risk Score: <strong style="color:#e2e8f0;">' + score.toFixed(1) + ' / 100</strong></span>';
    html +=   '<span class="att-exp-action" style="margin-left:auto;padding:2px 10px;border-radius:4px;font-size:0.78rem;font-weight:600;background:' + aColour + '22;color:' + aColour + ';border:1px solid ' + aColour + '44;">' + action + '</span>';
    html += '</div>';

    // ── 2. Summary paragraph ──────────────────────────────────────────────────
    if (summary) {
        html += '<p class="att-exp-summary" style="color:#cbd5e1;font-size:0.88rem;line-height:1.6;margin-bottom:14px;">' + _escHtml(summary) + '</p>';
    }

    // ── 3. File info pill row ─────────────────────────────────────────────────
    if (fileInfo.filename) {
        html += '<div class="att-exp-pills" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;">';
        html += _pill("📄 " + fileInfo.filename, "#334155");
        html += _pill("Type: " + (fileInfo.type || "?"), "#334155");
        html += _pill("Size: " + (fileInfo.size_kb || 0) + " KB", "#334155");
        if (fileInfo.type_mismatch) {
            html += _pill("⚠ Type mismatch", "#7f1d1d", "#fca5a5");
        }
        html += '</div>';
    }

    // ── 4. Verdict reasons ────────────────────────────────────────────────────
    if (reasons.length > 0) {
        html += _expSection(
            "🔍 Why This Verdict",
            "#1e293b",
            vColour + "33",
            vColour + "66",
            '<ul class="att-exp-list">' +
            reasons.map(function(r) {
                return '<li style="color:#cbd5e1;font-size:0.85rem;margin-bottom:4px;">' + _escHtml(r) + '</li>';
            }).join("") +
            '</ul>'
        );
    }

    // ── 5. Static string analysis ─────────────────────────────────────────────
    var strHits    = staticA.hits    || [];
    var strCount   = staticA.hit_count || 0;
    var strColour  = strCount > 0 ? "#f59e0b" : "#22c55e";
    var strIcon    = strCount > 0 ? "⚡" : "✅";
    var strBody    = '<p style="color:#94a3b8;font-size:0.82rem;margin-bottom:8px;">' +
                    '<em>Method: ' + _escHtml(staticA.method || "") + '</em></p>' +
                    '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (strHits.length ? "10px" : "0") + ';">' +
                    _escHtml(staticA.explanation || "") + '</p>';

    if (strHits.length > 0) {
        strBody += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';
        strHits.forEach(function(hit) {
            var label = typeof hit === "string" ? hit : (hit.string || JSON.stringify(hit));
            var count = typeof hit === "object" && hit.count ? " ×" + hit.count : "";
            strBody += _pill(label + count, "#422006", "#fbbf24");
        });
        strBody += '</div>';
    }

    html += _expSection(strIcon + " Static String Analysis (" + strCount + " hit" + (strCount !== 1 ? "s" : "") + ")",
        "#0f172a", strColour + "22", strColour + "55", strBody);

    // ── 6. YARA analysis ──────────────────────────────────────────────────────
    var yaraHits   = yaraA.hits    || [];
    var yaraCount  = yaraA.hit_count || 0;
    var yaraColour = yaraCount > 0 ? "#ef4444" : "#22c55e";
    var yaraIcon   = yaraCount > 0 ? "🚨" : "✅";
    var sevColour  = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#94a3b8" };

    var yaraBody = '<p style="color:#94a3b8;font-size:0.82rem;margin-bottom:8px;"><em>Method: ' +
                  _escHtml(yaraA.method || "") + '</em></p>' +
                  '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (yaraHits.length ? "10px" : "0") + ';">' +
                  _escHtml(yaraA.explanation || "") + '</p>';

    if (yaraHits.length > 0) {
        yaraBody += '<div style="display:flex;flex-direction:column;gap:5px;">';
        yaraHits.forEach(function(m) {
            var sc = sevColour[m.severity] || "#94a3b8";
            yaraBody += '<div style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:#1e293b;border-left:3px solid ' + sc + ';border-radius:3px;">';
            yaraBody += '<span style="font-family:monospace;font-size:0.82rem;color:#e2e8f0;">' + _escHtml(m.rule) + '</span>';
            yaraBody += '<span style="margin-left:auto;font-size:0.75rem;font-weight:600;color:' + sc + ';">' + m.severity + '</span>';
            if (m.namespace) {
                yaraBody += '<span style="font-size:0.72rem;color:#64748b;">' + _escHtml(m.namespace) + '</span>';
            }
            yaraBody += '</div>';
        });
        yaraBody += '</div>';
    }

    html += _expSection(yaraIcon + " YARA Signature Matching (" + yaraCount + " match" + (yaraCount !== 1 ? "es" : "") + ")",
        "#0f172a", yaraColour + "22", yaraColour + "55", yaraBody);

    // ── 7. PDF analysis (only for PDFs) ───────────────────────────────────────
    if (pdfA) {
        var pdfFlags  = pdfA.flags    || [];
        var pdfColour = pdfFlags.length > 0 ? "#f97316" : "#22c55e";
        var pdfIcon   = pdfFlags.length > 0 ? "📑" : "✅";
        var pdfUrls   = pdfA.urls_found || 0;

        var pdfBody = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (pdfFlags.length ? "10px" : "0") + ';">' +
                      _escHtml(pdfA.explanation || "") + '</p>';

        if (pdfFlags.length > 0) {
            pdfBody += '<ul class="att-exp-list">';
            pdfFlags.forEach(function(f) {
                pdfBody += '<li style="color:#fed7aa;font-size:0.84rem;margin-bottom:4px;">⚠ ' + _escHtml(f) + '</li>';
            });
            pdfBody += '</ul>';
        }
        if (pdfUrls > 0) {
            pdfBody += '<p style="color:#94a3b8;font-size:0.82rem;margin-top:6px;">🔗 ' + pdfUrls + ' embedded URL(s) extracted.</p>';
        }

        html += _expSection(pdfIcon + " PDF Structure Analysis",
            "#0f172a", pdfColour + "22", pdfColour + "55", pdfBody);
    }

    // ── 8. Entropy analysis ───────────────────────────────────────────────────
    var eVal     = entropyA.value     || 0;
    var eColour  = { green: "#22c55e", amber: "#f59e0b", red: "#ef4444" }[entropyA.colour] || "#94a3b8";
    var ePct     = entropyA.bar_pct   || 0;
    var eInterp  = entropyA.interpretation || "";
    var eIcon    = entropyA.colour === "red" ? "🔴" : entropyA.colour === "amber" ? "🟡" : "🟢";

    var eBody  = '<div style="margin-bottom:8px;">';
    eBody     += '  <div style="display:flex;justify-content:space-between;margin-bottom:4px;">';
    eBody     += '    <span style="font-size:0.82rem;color:#94a3b8;">Shannon Entropy</span>';
    eBody     += '    <span style="font-size:0.88rem;font-weight:600;color:' + eColour + ';">' + eVal.toFixed(4) + ' / 8.0</span>';
    eBody     += '  </div>';
    eBody     += '  <div style="background:#1e293b;border-radius:4px;height:6px;overflow:hidden;">';
    eBody     += '    <div style="width:' + ePct + '%;height:100%;background:' + eColour + ';transition:width 0.4s;"></div>';
    eBody     += '  </div>';
    eBody     += '</div>';
    eBody     += '<p style="color:#cbd5e1;font-size:0.85rem;">' + _escHtml(eInterp) + '</p>';

    html += _expSection(eIcon + " Shannon Entropy Analysis",
        "#0f172a", eColour + "22", eColour + "55", eBody);

    // ── Render ────────────────────────────────────────────────────────────────
    container.innerHTML = html;
    _renderEmailLink(fa);
}


// ─── Helpers ──────────────────────────────────────────────────────────────────

function _expSection(title, bg, borderBg, borderColour, bodyHtml) {
    return (
        '<div style="background:' + bg + ';border:1px solid ' + borderColour +
        ';border-radius:6px;padding:12px 14px;margin-bottom:10px;">' +
        '<div style="font-size:0.86rem;font-weight:600;color:#e2e8f0;margin-bottom:8px;">' +
        _escHtml(title) +
        '</div>' +
        bodyHtml +
        '</div>'
    );
}

function _pill(text, bg, colour) {
    bg     = bg     || "#1e293b";
    colour = colour || "#94a3b8";
    return (
        '<span style="display:inline-block;padding:2px 8px;border-radius:99px;' +
        'font-size:0.75rem;background:' + bg + ';color:' + colour + ';border:1px solid ' + colour + '33;">' +
        _escHtml(text) +
        '</span>'
    );
}

function _escHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
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
    var targetId = e.target.dataset.target;
    var el       = document.getElementById(targetId);
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
// HISTORY POLLING
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") return;
            renderHistory(data.scans || []);
        })
        .catch(function () { /* silent */ });
}

function renderHistory(scans) {
    historyBody.innerHTML = "";
    if (!scans || scans.length === 0) {
        historyBody.innerHTML =
            '<tr><td colspan="8" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }

    scans.forEach(function (s) {
        var verdict      = (s.verdict || "UNKNOWN").toUpperCase();
        var verdictClass = {
            CLEAN:      "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
        }[verdict] || "badge-safe";

        var ts      = s.scanned_at
            ? s.scanned_at.replace("T", " ").replace("Z", "").slice(0, 19)
            : "—";
        var yCount  = Array.isArray(s.yara_matches) ? s.yara_matches.length : 0;
        var entropy = parseFloat(s.entropy || 0);

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + escapeHtml(String(s.id)) + "</td>" +
            "<td class='att-fname'>" + escapeHtml(s.filename || "—") + "</td>" +
            "<td class='att-type'>" + escapeHtml(s.file_type || "—") + "</td>" +
            "<td>" + formatBytes(s.file_size || 0) + "</td>" +
            "<td class='" + entropyClass(entropy) + "'>" +
                entropy.toFixed(2) +
            "</td>" +
            "<td class='" + (yCount > 0 ? "att-cell-red" : "") + "'>" +
                yCount +
            "</td>" +
            "<td><span class='badge " + verdictClass + "'>" + verdict + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}

function entropyClass(e) {
    if (!e) return "";
    if (e > 7.2) return "att-cell-red";
    if (e > 6.0) return "att-cell-amber";
    return "";
}


// ════════════════════════════════════════════════════════════════════════════
// ERROR HELPERS
// ════════════════════════════════════════════════════════════════════════════

function showError(msg) {
    uploadError.textContent   = "⚠ " + msg;
    uploadError.style.display = "block";
}
function hideError() {
    uploadError.style.display = "none";
    uploadError.textContent   = "";
}


// ════════════════════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
_pollTimer = setInterval(loadHistory, 5000);