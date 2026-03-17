"use strict";

// attachments.js
// Client-side logic for the File & Attachment Analysis page.
//
// FIXES IN THIS VERSION:
//   1. renderResults() — was reading mod.verdict, mod.hashes etc. directly
//      from module_results root. The actual structure is:
//        data.module_results.file_analysis.verdict  (not data.module_results.verdict)
//      Fixed: fa = data.module_results.file_analysis || {}
//      All render helpers now receive fa (the file_analysis sub-dict).
//
//   2. renderVerdict() — verdict was always "SUSPICIOUS" because scan_router
//      was receiving "Clean" (title case) from analyze_file() and its
//      label_map only handles "CLEAN" (uppercase). Fixed in file_analyzer.py
//      (verdict is now uppercase). JS now also normalises to uppercase before
//      class lookup so it works regardless.
//
//   3. renderStrings() — was reading mod.suspicious_strings. The result dict
//      now exposes both static_findings (list of objects) and suspicious_strings
//      (list of plain strings). JS reads fa.suspicious_strings correctly.
//
//   4. renderDeepFindings() — was reading mod.html_analysis.html_findings etc.
//      These dicts are now top-level in the result under html_analysis,
//      pdf_analysis, macro_analysis, zip_analysis. The render function now
//      reads them from the correct paths.
//
//   5. loadHistory() — was checking data.status === "success" but the Flask
//      route returned a raw array []. Fixed in attachment.py — route now
//      returns {status, scans, total}. JS unchanged for this fix but now
//      correctly hits the new envelope.
//
// NEW IN THIS VERSION:
//   6. renderVtResult() — shows VirusTotal hash lookup result (engine count,
//      known-bad badge, permalink) when vt_result is present in the response.
//   7. renderTypeMismatch() — shows a warning banner when file extension
//      disagrees with magic bytes (e.g. EXE disguised as PDF).
//   8. renderEmbeddedUrls() — shows aggregated embedded URLs from all
//      analysis types (PDF, HTML, ZIP relationships).
//   9. renderArchiveContents() — shows structured file list for ZIP/Office
//      docs with suspicious entries highlighted.
//  10. renderMacroDetail() — shows VBA stream names and macro keywords.
//  11. History table now shows entropy bar + YARA hit count.


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
// RESULT RENDERING
//
// scan_router.scan_file() response shape:
// {
//   status, risk_score, label, recommended_action, explanation,
//   module_results: {
//     file_analysis: {          ← FIX: was reading module_results directly
//       filename, file_type, file_category, file_size,
//       hashes: {md5, sha1, sha256},
//       entropy, is_packed, is_high_entropy,
//       type_mismatch: bool,        NEW
//       yara_matches: [],
//       static_findings: [],
//       suspicious_strings: [],     JS reads this one
//       pdf_analysis:    {},
//       macro_analysis:  {},
//       html_analysis:   {},
//       zip_analysis:    {},
//       script_analysis: {},
//       exe_analysis:    {},
//       embedded_urls: [],           NEW
//       vt_result: {} | null,        NEW
//       known_bad: bool,             NEW
//       verdict: "CLEAN"|"SUSPICIOUS"|"MALICIOUS",  FIX: uppercase
//       risk_score, risk_flags, verdict_reasons
//     }
//   }
// }
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    // FIX: extract the correct sub-dict
    var fa = (data.module_results || {}).file_analysis || {};

    renderVerdict(fa, data);
    renderTypeMismatch(fa);       // NEW
    renderHashes(fa);
    renderVtResult(fa);           // NEW
    renderEntropy(fa);
    renderYara(fa);
    renderStrings(fa);
    renderMacroDetail(fa);        // NEW
    renderDeepFindings(fa);
    renderArchiveContents(fa);    // NEW
    renderEmbeddedUrls(fa);       // NEW
    renderPdfUrls(fa);
    renderExplanation(data, fa);
}

// ── Verdict ──────────────────────────────────────────────────────────────────
// FIX: reads fa.verdict (not mod.verdict) + normalises to uppercase
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

    // Verdict reasons list (NEW)
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

// ── Type mismatch warning (NEW) ───────────────────────────────────────────────
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
// FIX: reads fa.hashes (was mod.hashes)
function renderHashes(fa) {
    var h = fa.hashes || {};
    document.getElementById("hashMd5").textContent    = h.md5    || "—";
    document.getElementById("hashSha256").textContent = h.sha256 || "—";

    var knownBad = document.getElementById("knownBadBadge");
    if (knownBad) knownBad.style.display = fa.known_bad ? "inline-flex" : "none";
}

// ── VirusTotal result (NEW) ───────────────────────────────────────────────────
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
// FIX: reads fa.entropy
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

// ── YARA matches ──────────────────────────────────────────────────────────────
// FIX: reads fa.yara_matches
function renderYara(fa) {
    var matches = fa.yara_matches || [];
    document.getElementById("yaraCount").textContent = matches.length;
    var list = document.getElementById("yaraList");
    list.innerHTML = "";

    if (matches.length === 0) {
        list.innerHTML = '<span class="att-empty-note">No YARA rules matched.</span>';
        return;
    }
    matches.forEach(function (rule) {
        var name = typeof rule === "string" ? rule : (rule.rule || JSON.stringify(rule));
        var sev  = typeof rule === "object" ? (rule.severity || "MEDIUM") : "MEDIUM";
        var tag  = document.createElement("span");
        tag.className   = "att-tag att-tag-danger";
        tag.textContent = name + (sev !== "MEDIUM" ? " [" + sev + "]" : "");
        list.appendChild(tag);
    });
}

// ── Suspicious strings ────────────────────────────────────────────────────────
// FIX: reads fa.suspicious_strings (list of plain strings)
function renderStrings(fa) {
    // suspicious_strings is a list of plain strings; static_findings is objects
    var sus   = fa.suspicious_strings || [];
    document.getElementById("stringsCount").textContent = sus.length;
    var list  = document.getElementById("stringsList");
    list.innerHTML = "";

    if (sus.length === 0) {
        list.innerHTML = '<span class="att-empty-note">No suspicious strings found.</span>';
        return;
    }
    sus.forEach(function (s) {
        var tag = document.createElement("span");
        tag.className   = "att-tag att-tag-warn";
        tag.textContent = typeof s === "string" ? s : (s.string || JSON.stringify(s));
        list.appendChild(tag);
    });
}

// ── Macro detail (NEW) ────────────────────────────────────────────────────────
function renderMacroDetail(fa) {
    var card = document.getElementById("macroCard");
    if (!card) return;

    var ma = fa.macro_analysis || {};
    if (!ma.has_macros) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";

    var streamsEl = document.getElementById("macroStreams");
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

// ── Format-specific deep findings ─────────────────────────────────────────────
// FIX: reads from fa.html_analysis.html_findings etc. (top-level in fa)
function renderDeepFindings(fa) {
    var allFindings = [];

    (fa.html_analysis   || {}).html_findings   && (fa.html_analysis.html_findings   || []).forEach(function (f) {
        allFindings.push({ icon: "🌐", text: f, sev: "danger" });
    });
    (fa.pdf_analysis    || {}).pdf_findings    && (fa.pdf_analysis.pdf_findings     || []).forEach(function (f) {
        allFindings.push({ icon: "📄", text: f, sev: "warn" });
    });
    (fa.macro_analysis  || {}).macro_findings  && (fa.macro_analysis.macro_findings || []).forEach(function (f) {
        allFindings.push({ icon: "📝", text: f, sev: "danger" });
    });
    (fa.zip_analysis    || {}).zip_findings    && (fa.zip_analysis.zip_findings     || []).forEach(function (f) {
        allFindings.push({ icon: "🗜", text: f, sev: "warn" });
    });
    (fa.script_analysis || {}).script_findings && (fa.script_analysis.script_findings || []).forEach(function (f) {
        allFindings.push({ icon: "⚡", text: f, sev: "warn" });
    });
    (fa.exe_analysis    || {}).exe_findings    && (fa.exe_analysis.exe_findings     || []).forEach(function (f) {
        allFindings.push({ icon: "🔩", text: f, sev: "warn" });
    });

    var card = document.getElementById("deepCard");
    var list = document.getElementById("deepFindings");
    list.innerHTML = "";

    if (allFindings.length === 0) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";
    allFindings.forEach(function (item) {
        var row = document.createElement("div");
        row.className   = "att-finding-row att-finding-" + item.sev;
        row.textContent = item.icon + " " + item.text;
        list.appendChild(row);
    });
}

// ── Archive contents (NEW) ────────────────────────────────────────────────────
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
        var name    = typeof entry === "string" ? entry : (entry.name || "");
        var isSus   = typeof entry === "object"  ? entry.suspicious : false;
        var tr      = document.createElement("tr");
        if (isSus) tr.className = "row-suspicious";
        tr.innerHTML =
            "<td><code>" + escapeHtml(name) + "</code>" +
            (isSus ? " <span class='att-tag att-tag-danger'>suspicious</span>" : "") +
            "</td>";
        tbody.appendChild(tr);
    });
}

// ── Embedded URLs (NEW) ───────────────────────────────────────────────────────
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
        var li  = document.createElement("li");
        li.className = "att-url-item";
        li.textContent = url;
        list.appendChild(li);
    });
}

// ── PDF embedded URLs (kept for backward compat, now uses embedded_urls) ──────
function renderPdfUrls(fa) {
    // pdf_analysis.embedded_urls is already merged into fa.embedded_urls
    // This function is kept but does nothing to avoid double-rendering
}

// ── Explanation ───────────────────────────────────────────────────────────────
function renderExplanation(data, fa) {
    document.getElementById("explanationText").textContent =
        data.explanation || "Analysis complete.";

    var emailId = fa.email_id;
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
// HISTORY  (FIX: Flask route now returns {status, scans, total})
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            // FIX: was data.status !== "success" which failed on raw list
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
            CLEAN:     "badge-safe",
            SUSPICIOUS:"badge-suspicious",
            MALICIOUS: "badge-malicious",
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
                "<div class='att-entropy-mini'>" +
                    "<div class='att-entropy-mini-fill " + entropyFillClass(entropy) + "' " +
                    "style='width:" + Math.min((entropy / 8) * 100, 100).toFixed(0) + "%'></div>" +
                "</div>" +
            "</td>" +
            "<td>" + yCount + "</td>" +
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

function entropyFillClass(e) {
    if (e > 7.2) return "att-entropy-red";
    if (e > 6.0) return "att-entropy-amber";
    return "att-entropy-green";
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