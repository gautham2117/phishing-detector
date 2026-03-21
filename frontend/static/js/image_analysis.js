"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd         = document.getElementById("page-data");
var SCAN_URL    = _pd.dataset.scanUrl;
var HISTORY_URL = _pd.dataset.historyUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var dropZone     = document.getElementById("imgDropZone");
var fileInput    = document.getElementById("imgFileInput");
var scanBtn      = document.getElementById("imgScanBtn");
var btnText      = document.getElementById("imgBtnText");
var spinner      = document.getElementById("imgSpinner");
var imgError     = document.getElementById("imgError");
var resultsPanel = document.getElementById("imgResultsPanel");
var historyBody  = document.getElementById("imgHistoryBody");
var previewWrap  = document.getElementById("imgPreviewWrap");
var previewImg   = document.getElementById("imgPreview");
var previewMeta  = document.getElementById("imgPreviewMeta");

var _selectedFile = null;


// ════════════════════════════════════════════════════════════════════════════
// FILE SELECTION + PREVIEW
// ════════════════════════════════════════════════════════════════════════════

function setFile(file) {
    _selectedFile    = file;
    scanBtn.disabled = false;
    hideError();

    var reader = new FileReader();
    reader.onload = function (e) {
        previewImg.src         = e.target.result;
        previewMeta.textContent = file.name + "  —  " + formatBytes(file.size);
        previewWrap.style.display = "block";
    };
    reader.readAsDataURL(file);
}

fileInput.addEventListener("change", function () {
    if (this.files && this.files[0]) { setFile(this.files[0]); }
});

dropZone.addEventListener("dragover",  function (e) { e.preventDefault(); dropZone.classList.add("att-drop-active"); });
dropZone.addEventListener("dragleave", function ()  { dropZone.classList.remove("att-drop-active"); });
dropZone.addEventListener("drop", function (e) {
    e.preventDefault();
    dropZone.classList.remove("att-drop-active");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) { setFile(e.dataTransfer.files[0]); }
});
dropZone.addEventListener("click", function (e) {
    if (e.target.tagName !== "LABEL" && e.target.tagName !== "INPUT") { fileInput.click(); }
});


// ════════════════════════════════════════════════════════════════════════════
// SCAN SUBMISSION
// ════════════════════════════════════════════════════════════════════════════

scanBtn.addEventListener("click", function () {
    if (!_selectedFile) { return; }
    submitScan();
});

function submitScan() {
    hideError();
    setLoading(true);
    resultsPanel.style.display = "none";

    var fd = new FormData();
    fd.append("file", _selectedFile);

    fetch(SCAN_URL, { method: "POST", body: fd })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            setLoading(false);
            if (data.status === "error") { showError(data.message || "Analysis failed."); return; }
            renderResults(data);
            resultsPanel.style.display = "block";
            resultsPanel.scrollIntoView({ behavior: "smooth" });
        })
        .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var mod = (data.module_results || {}).image_analysis || {};
    renderVerdict(mod, data);
    renderClassifier(mod);
    renderBrands(mod);
    renderKeywords(mod);
    renderOcrText(mod);
    renderExplanation(mod, data);
}

// ── Verdict card ──────────────────────────────────────────────────────────
function renderVerdict(mod, data) {
    var verdict = (mod.verdict || "CLEAN").toUpperCase();
    var badge   = document.getElementById("imgVerdictBadge");
    badge.textContent = verdict;
    badge.className   = "ai-verdict-badge ai-verdict-" + verdict.toLowerCase().replace("_", "-");

    document.getElementById("imgRiskScore").textContent =
        "Risk score: " + (mod.risk_score || 0).toFixed(1) + " / 100";

    var w = mod.image_width || 0, h = mod.image_height || 0;
    document.getElementById("imgDimensions").textContent =
        w + " \u00d7 " + h + " px  \u00b7  " + (mod.image_format || "\u2014");

    var actionMap = {
        ALLOW: "\u2705 Allow", WARN: "\u26a0 Review carefully",
        QUARANTINE: "\ud83d\udd12 Quarantine", BLOCK: "\ud83d\udeab Block"
    };
    document.getElementById("imgAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "\u2014");
}

// ── Phishing Classifier card  ← FIXED: no more LABEL_1 displayed ─────────
function renderClassifier(mod) {
    var clf   = mod.classifier_result || {};
    var label = clf.label || "UNKNOWN";
    var score = clf.score || 0.0;
    var pct   = Math.round(score * 100);

    // Label display: if backend normalised correctly this is always readable,
    // but guard here too in case an old response slips through
    var displayLabel = _normaliseLabelDisplay(label);
    document.getElementById("imgClfLabel").textContent = displayLabel;
    document.getElementById("imgClfScore").textContent = pct + "%";

    var bar     = document.getElementById("imgClfBar");
    var noteEl  = document.getElementById("imgClfNote");
    bar.style.width = pct + "%";

    if (label === "PHISHING") {
        bar.className      = "att-entropy-bar-fill att-entropy-red";
        noteEl.textContent = "\u26a0 Classifier flagged image text as phishing content.";
        noteEl.style.color = "var(--red)";
    } else if (label === "SAFE") {
        bar.className      = "att-entropy-bar-fill att-entropy-green";
        noteEl.textContent = "Classifier found no phishing content in extracted text.";
        noteEl.style.color = "var(--green)";
    } else if (label === "SUSPICIOUS") {
        bar.className      = "att-entropy-bar-fill att-entropy-amber";
        noteEl.textContent = "Classifier returned suspicious confidence level.";
        noteEl.style.color = "var(--amber)";
    } else {
        bar.className      = "att-entropy-bar-fill att-entropy-amber";
        noteEl.textContent = "Insufficient text for confident classification.";
        noteEl.style.color = "var(--text-muted)";
    }

    document.getElementById("imgOcrWords").textContent = (mod.ocr_word_count || 0).toLocaleString();
    document.getElementById("imgFormat").textContent   = mod.image_format || "\u2014";
    document.getElementById("imgFileSize").textContent = formatBytes(mod.file_size || 0);
}

function _normaliseLabelDisplay(label) {
    // Guard against LABEL_0 / LABEL_1 reaching the UI even if backend missed it
    var map = {
        "LABEL_1": "PHISHING",
        "LABEL_0": "SAFE",
        "1":       "PHISHING",
        "0":       "SAFE",
        "INSUFFICIENT_DATA": "Insufficient Text",
        "NO_TEXT":           "No Text",
        "UNKNOWN":           "Unknown",
    };
    return map[label] || label;
}

// ── Detected brand names ──────────────────────────────────────────────────
function renderBrands(mod) {
    var brands  = mod.detected_brands || [];
    var countEl = document.getElementById("imgBrandsCount");
    var listEl  = document.getElementById("imgBrandsList");
    var noteEl  = document.getElementById("imgBrandsNote");
    countEl.textContent = brands.length;
    listEl.innerHTML    = "";

    if (brands.length === 0) {
        listEl.innerHTML     = '<span class="att-empty-note">No known brand names detected.</span>';
        noteEl.style.display = "none";
        return;
    }
    brands.forEach(function (b) {
        var tag = document.createElement("span");
        tag.className   = "att-tag att-tag-warn";
        tag.textContent = b;
        listEl.appendChild(tag);
    });
    noteEl.style.display = "block";
}

// ── Phishing keywords ─────────────────────────────────────────────────────
function renderKeywords(mod) {
    var kws     = mod.phishing_keywords || [];
    var countEl = document.getElementById("imgKwCount");
    var listEl  = document.getElementById("imgKwList");
    countEl.textContent = kws.length;
    listEl.innerHTML    = "";

    if (kws.length === 0) {
        listEl.innerHTML = '<span class="att-empty-note">No phishing keywords detected.</span>';
        return;
    }
    kws.forEach(function (kw) {
        var tag = document.createElement("span");
        tag.className   = "att-tag att-tag-danger";
        tag.textContent = kw;
        listEl.appendChild(tag);
    });
}

// ── OCR text ──────────────────────────────────────────────────────────────
function renderOcrText(mod) {
    var text = mod.ocr_text || "";
    var el   = document.getElementById("imgOcrText");
    el.textContent = (text && text.trim().length > 0)
        ? text
        : "No text extracted from image.";
}


// ════════════════════════════════════════════════════════════════════════════
// RICH EXPLANATION RENDERER  ← NEW: renders structured dict from backend
// ════════════════════════════════════════════════════════════════════════════

function renderExplanation(mod, data) {
    var container = document.getElementById("imgExplanation");
    if (!container) { return; }

    var exp = data.explanation || mod.explanation;

    // ── Fallback: plain string (old response or error) ─────────────────────
    if (!exp || typeof exp === "string") {
        container.innerHTML =
            '<p style="color:#cbd5e1;font-size:0.88rem;">' + _esc(exp || "Analysis complete.") + "</p>";
        return;
    }

    var verdict  = (exp.verdict    || "CLEAN").toUpperCase();
    var score    = exp.risk_score  || 0;
    var summary  = exp.summary     || "";
    var clf      = exp.classifier  || {};
    var brandA   = exp.brand_analysis   || {};
    var kwA      = exp.keyword_analysis || {};
    var qrA      = exp.qr_analysis      || null;
    var stegoA   = exp.stego_analysis   || null;
    var exifA    = exp.exif_analysis    || null;
    var ocrNote  = exp.ocr_note         || null;

    var vColour = { CLEAN: "#22c55e", SUSPICIOUS: "#f59e0b", MALICIOUS: "#ef4444" }[verdict] || "#94a3b8";

    var html = "";

    // ── Header ────────────────────────────────────────────────────────────────
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">';
    html +=   '<span style="font-size:1.05rem;font-weight:700;color:' + vColour + ';">' + verdict + '</span>';
    html +=   '<span style="color:#94a3b8;font-size:0.85rem;">Risk Score: <strong style="color:#e2e8f0;">' + score.toFixed(1) + ' / 100</strong></span>';
    html += '</div>';

    // ── Summary ───────────────────────────────────────────────────────────────
    if (summary) {
        html += '<p style="color:#cbd5e1;font-size:0.88rem;line-height:1.6;margin-bottom:14px;">' + _esc(summary) + '</p>';
    }

    // ── OCR warning ───────────────────────────────────────────────────────────
    if (ocrNote) {
        html += _imgSection("\u26a0 OCR Not Available", "#1e293b", "#f59e0b33", "#f59e0b55",
            '<p style="color:#fcd34d;font-size:0.84rem;">' + _esc(ocrNote) + '</p>');
    }

    // ── Classifier card ───────────────────────────────────────────────────────
    var clfColour = { PHISHING: "#ef4444", SAFE: "#22c55e", SUSPICIOUS: "#f59e0b" }[clf.label] || "#94a3b8";
    var clfIcon   = clf.label === "PHISHING" ? "\ud83d\udea8" : clf.label === "SAFE" ? "\u2705" : "\u26a0";
    var clfDisplay = _normaliseLabelDisplay(clf.label || "UNKNOWN");

    var clfBody = "";
    clfBody += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">';
    clfBody +=   '<span style="font-size:1rem;font-weight:700;color:' + clfColour + ';">' + clfDisplay + '</span>';
    clfBody +=   '<span style="color:#94a3b8;font-size:0.82rem;">' + (clf.score_pct || 0) + '% confidence</span>';
    if (clf.raw_label && clf.raw_label !== clf.label) {
        clfBody += '<span style="font-size:0.72rem;color:#475569;margin-left:auto;">raw: ' + _esc(clf.raw_label) + '</span>';
    }
    clfBody += '</div>';
    clfBody += '<p style="color:#94a3b8;font-size:0.79rem;margin-bottom:6px;"><em>Method: ' + _esc(clf.method || "") + '</em></p>';
    clfBody += '<p style="color:#cbd5e1;font-size:0.85rem;">' + _esc(clf.explanation || "") + '</p>';

    html += _imgSection(clfIcon + " ML Phishing Classifier", "#0f172a", clfColour + "22", clfColour + "55", clfBody);

    // ── Brand analysis card ───────────────────────────────────────────────────
    var brandColour = brandA.count > 0 ? "#f59e0b" : "#22c55e";
    var brandIcon   = brandA.count > 0 ? "\ud83c\udff7" : "\u2705";
    var brandBody   = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (brandA.count ? "10px" : "0") + ';">' + _esc(brandA.explanation || "") + '</p>';
    if (brandA.brands_found && brandA.brands_found.length > 0) {
        brandBody += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';
        brandA.brands_found.forEach(function (b) {
            brandBody += _pill(b, "#422006", "#fbbf24");
        });
        brandBody += '</div>';
    }
    html += _imgSection(brandIcon + " Brand Detection (" + brandA.count + " found)", "#0f172a", brandColour + "22", brandColour + "55", brandBody);

    // ── Keyword analysis card ─────────────────────────────────────────────────
    var kwColour = kwA.count > 0 ? "#ef4444" : "#22c55e";
    var kwIcon   = kwA.count > 0 ? "\u26a1" : "\u2705";
    var kwBody   = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (kwA.count ? "10px" : "0") + ';">' + _esc(kwA.explanation || "") + '</p>';
    if (kwA.keywords_found && kwA.keywords_found.length > 0) {
        kwBody += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';
        kwA.keywords_found.forEach(function (kw) {
            kwBody += _pill(kw, "#450a0a", "#fca5a5");
        });
        kwBody += '</div>';
    }
    html += _imgSection(kwIcon + " Phishing Keyword Analysis (" + kwA.count + " matched)", "#0f172a", kwColour + "22", kwColour + "55", kwBody);

    // ── QR codes card ─────────────────────────────────────────────────────────
    if (qrA) {
        var qrColour = qrA.malicious_urls && qrA.malicious_urls.length ? "#ef4444"
                     : qrA.suspicious_urls && qrA.suspicious_urls.length ? "#f59e0b" : "#22c55e";
        var qrBody = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:6px;">' + _esc(qrA.explanation || "") + '</p>';
        if (qrA.malicious_urls && qrA.malicious_urls.length) {
            qrBody += '<div style="margin-top:6px;"><span style="color:#ef4444;font-size:0.82rem;font-weight:600;">Malicious URLs:</span></div>';
            qrA.malicious_urls.forEach(function (u) {
                qrBody += '<div style="font-family:monospace;font-size:0.78rem;color:#fca5a5;word-break:break-all;margin-top:3px;">' + _esc(u) + '</div>';
            });
        }
        html += _imgSection("\ud83d\udcf7 QR Code Analysis (" + (qrA.code_count || 0) + " code(s))", "#0f172a", qrColour + "22", qrColour + "55", qrBody);
    }

    // ── Steganography card ────────────────────────────────────────────────────
    if (stegoA) {
        var stegoColour = stegoA.suspicious ? "#f97316" : "#22c55e";
        var stegoIcon   = stegoA.suspicious ? "\ud83d\udd75" : "\u2705";
        var stegoBody   = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:' + (stegoA.flags && stegoA.flags.length ? "8px" : "0") + ';">' + _esc(stegoA.explanation || "") + '</p>';
        if (stegoA.flags && stegoA.flags.length) {
            stegoBody += '<ul style="margin:0;padding-left:18px;">';
            stegoA.flags.forEach(function (f) {
                stegoBody += '<li style="color:#fdba74;font-size:0.82rem;margin-bottom:3px;">' + _esc(f) + '</li>';
            });
            stegoBody += '</ul>';
        }
        html += _imgSection(stegoIcon + " Steganography Detection", "#0f172a", stegoColour + "22", stegoColour + "55", stegoBody);
    }

    // ── EXIF card ─────────────────────────────────────────────────────────────
    if (exifA) {
        var exifColour = exifA.flags && exifA.flags.length ? "#f59e0b" : "#22c55e";
        var exifBody   = '<p style="color:#cbd5e1;font-size:0.85rem;margin-bottom:8px;">' + _esc(exifA.explanation || "") + '</p>';
        if (exifA.explanations && exifA.explanations.length) {
            exifBody += '<ul style="margin:0;padding-left:18px;">';
            exifA.explanations.forEach(function (e) {
                exifBody += '<li style="color:#fcd34d;font-size:0.82rem;margin-bottom:3px;">\u26a0 ' + _esc(e) + '</li>';
            });
            exifBody += '</ul>';
        }
        html += _imgSection("\ud83d\udcf0 EXIF Metadata Analysis (" + (exifA.flags ? exifA.flags.length : 0) + " flag(s))", "#0f172a", exifColour + "22", exifColour + "55", exifBody);
    }

    container.innerHTML = html;
}


// ════════════════════════════════════════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistory(data.scans || []);
        })
        .catch(function () {});
}

function renderHistory(scans) {
    historyBody.innerHTML = "";
    if (scans.length === 0) {
        historyBody.innerHTML = '<tr><td colspan="9" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }
    scans.forEach(function (s) {
        var verdict      = (s.verdict || "CLEAN").toUpperCase();
        var verdictClass = { CLEAN: "badge-safe", SUSPICIOUS: "badge-suspicious", MALICIOUS: "badge-malicious" }[verdict] || "badge-safe";
        var dims = (s.image_width || 0) + "\u00d7" + (s.image_height || 0);
        var ts   = (s.scanned_at || "").replace("T", " ").replace("Z", "").slice(0, 19);
        var brands = (s.detected_brands  || []).length;
        var kws    = (s.phishing_keywords || []).length;

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>" +
            "<td class='att-fname'>" + escapeHtml(s.filename) + "</td>" +
            "<td>" + dims + "</td>" +
            "<td>" + (s.ocr_word_count || 0) + "</td>" +
            "<td class='" + (brands > 0 ? "att-cell-amber" : "") + "'>" + brands + "</td>" +
            "<td class='" + (kws    > 0 ? "att-cell-red"   : "") + "'>" + kws    + "</td>" +
            "<td>" + (s.risk_score || 0).toFixed(1) + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" + verdict + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// SHARED HELPERS
// ════════════════════════════════════════════════════════════════════════════

function _imgSection(title, bg, borderBg, borderColour, bodyHtml) {
    return (
        '<div style="background:' + bg + ';border:1px solid ' + borderColour +
        ';border-radius:6px;padding:12px 14px;margin-bottom:10px;">' +
        '<div style="font-size:0.86rem;font-weight:600;color:#e2e8f0;margin-bottom:8px;">' +
        _esc(title) + '</div>' +
        bodyHtml + '</div>'
    );
}

function _pill(text, bg, colour) {
    return (
        '<span style="display:inline-block;padding:2px 8px;border-radius:99px;' +
        'font-size:0.75rem;background:' + (bg || "#1e293b") + ';color:' + (colour || "#94a3b8") +
        ';border:1px solid ' + (colour || "#94a3b8") + '33;">' + _esc(text) + '</span>'
    );
}

function _esc(str) {
    return (str || "").toString()
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function setLoading(on) {
    scanBtn.disabled      = on;
    btnText.style.display = on ? "none"   : "inline";
    spinner.style.display = on ? "inline" : "none";
}

function showError(msg) { imgError.textContent = "\u26a0 " + msg; imgError.style.display = "block"; }
function hideError()    { imgError.style.display = "none"; imgError.textContent = ""; }

function formatBytes(bytes) {
    if (bytes < 1024)    { return bytes + " B"; }
    if (bytes < 1048576) { return (bytes / 1024).toFixed(1) + " KB"; }
    return (bytes / 1048576).toFixed(2) + " MB";
}

function escapeHtml(str) {
    return (str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
setInterval(loadHistory, 5000);