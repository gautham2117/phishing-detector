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
        previewImg.src            = e.target.result;
        previewMeta.textContent   = file.name + "  —  " + formatBytes(file.size);
        previewWrap.style.display = "block";
    };
    reader.readAsDataURL(file);
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
    if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
dropZone.addEventListener("click", function (e) {
    if (e.target.tagName !== "LABEL" && e.target.tagName !== "INPUT") fileInput.click();
});


// ════════════════════════════════════════════════════════════════════════════
// SCAN SUBMISSION
// ════════════════════════════════════════════════════════════════════════════

scanBtn.addEventListener("click", function () {
    if (!_selectedFile) return;
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
            switchExpTab("img-overview");
        })
        .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
}


// ════════════════════════════════════════════════════════════════════════════
// MASTER DISPATCHER
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var mod = (data.module_results || {}).image_analysis || {};
    renderVerdict(mod, data);
    renderClassifier(mod);
    renderBrands(mod);
    renderKeywords(mod);
    renderOcrText(mod);
    renderGeminiDescription(mod);
    renderEla(mod);
    renderExplanationTabs(mod, data);
}


// ── Verdict ───────────────────────────────────────────────────────────────
function renderVerdict(mod, data) {
    var verdict = (mod.verdict || "CLEAN").toUpperCase();
    var badge   = document.getElementById("imgVerdictBadge");
    badge.textContent = verdict;
    badge.className   = "ai-verdict-badge ai-verdict-" + verdict.toLowerCase().replace("_", "-");
    document.getElementById("imgRiskScore").textContent =
        "Risk score: " + (mod.risk_score || 0).toFixed(1) + " / 100";
    var w = mod.image_width || 0, h = mod.image_height || 0;
    document.getElementById("imgDimensions").textContent =
        w + " × " + h + " px  ·  " + (mod.image_format || "—");
    var actionMap = {
        ALLOW:      "✅ Allow",
        WARN:       "⚠ Review carefully",
        QUARANTINE: "🔒 Quarantine",
        BLOCK:      "🚫 Block",
    };
    document.getElementById("imgAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");
}


// ── Classifier card ───────────────────────────────────────────────────────
function renderClassifier(mod) {
    var clf   = mod.classifier_result || {};
    var label = clf.label || "UNKNOWN";
    var score = clf.score || 0.0;
    var pct   = Math.round(score * 100);
    document.getElementById("imgClfLabel").textContent = _normLabel(label);
    document.getElementById("imgClfScore").textContent = pct + "%";
    var bar    = document.getElementById("imgClfBar");
    var noteEl = document.getElementById("imgClfNote");
    bar.style.width = pct + "%";
    if (label === "PHISHING") {
        bar.className      = "att-entropy-bar-fill att-entropy-red";
        noteEl.textContent = "⚠ Classifier flagged image text as phishing content.";
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
    document.getElementById("imgFormat").textContent   = mod.image_format || "—";
    document.getElementById("imgFileSize").textContent = formatBytes(mod.file_size || 0);
}


// ── Brands ────────────────────────────────────────────────────────────────
function renderBrands(mod) {
    var brands = mod.detected_brands || [];
    document.getElementById("imgBrandsCount").textContent = brands.length;
    var listEl = document.getElementById("imgBrandsList");
    var noteEl = document.getElementById("imgBrandsNote");
    listEl.innerHTML = "";
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


// ── Keywords ──────────────────────────────────────────────────────────────
function renderKeywords(mod) {
    var kws = mod.phishing_keywords || [];
    document.getElementById("imgKwCount").textContent = kws.length;
    var listEl = document.getElementById("imgKwList");
    listEl.innerHTML = "";
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
    document.getElementById("imgOcrText").textContent =
        (text && text.trim().length > 0) ? text : "No text extracted from image.";
}


// ════════════════════════════════════════════════════════════════════════════
// GEMINI DESCRIPTION CARD
// ════════════════════════════════════════════════════════════════════════════

function renderGeminiDescription(mod) {
    var card    = document.getElementById("geminiCard");
    var loading = document.getElementById("geminiLoading");
    var errorEl = document.getElementById("geminiError");
    var textEl  = document.getElementById("geminiDescriptionText");
    if (!card) return;

    var gd = mod.gemini_description || {};

    card.style.display = "block";
    if (loading) loading.style.display = "none";
    if (errorEl) errorEl.style.display = "none";
    if (textEl)  textEl.textContent    = "";

    if (gd.available && gd.description) {
        textEl.textContent = gd.description;
    } else if (gd.error) {
        errorEl.textContent   = "⚠ " + gd.error;
        errorEl.style.display = "block";
    } else {
        textEl.textContent = "Gemini description not available for this image.";
        textEl.style.color = "var(--text-muted)";
    }
}


// ════════════════════════════════════════════════════════════════════════════
// ELA CARD
// ════════════════════════════════════════════════════════════════════════════

function renderEla(mod) {
    var card       = document.getElementById("elaCard");
    var grid       = document.getElementById("elaGrid");
    var manipBadge = document.getElementById("elaManipulatedBadge");
    if (!card || !grid) return;

    var ela = mod.ela_analysis || {};

    card.style.display = "block";

    // Bug 4 FIX: guard against missing or empty explanation string.
    // ela.explanation can be "" when ela.available is false and the
    // module returned a default empty dict — always provide a fallback.
    var explanationText = (ela.explanation && ela.explanation.trim())
        ? ela.explanation
        : "ELA is not available for this image format. "
          + "Error Level Analysis only applies to JPEG images — "
          + "it exploits JPEG lossy compression to reveal edited regions.";

    // Not a JPEG — show explanation note, no stats
    if (!ela.available) {
        grid.innerHTML =
            '<p class="ela-not-applicable">' + _esc(explanationText) + '</p>';
        if (manipBadge) manipBadge.style.display = "none";
        return;
    }

    var isManip = ela.is_potentially_manipulated || false;
    if (manipBadge) manipBadge.style.display = isManip ? "inline-flex" : "none";

    var html = "";

    // ELA visualisation image
    if (ela.ela_image_b64) {
        html +=
            '<div class="ela-image-wrap">'
            + '<img src="data:image/png;base64,' + _esc(ela.ela_image_b64)
            + '" alt="ELA difference map">'
            + '<div class="ela-image-label">ELA difference map (10× amplified)</div>'
            + '</div>';
    }

    // Stats + verdict panel
    var statsHtml =
        '<div class="ela-stats-grid">'
        + _elaStat("Mean ELA",  ela.mean_ela != null ? ela.mean_ela.toFixed(3) : "—",
                   (ela.mean_ela || 0) > 8.0)
        + _elaStat("Max ELA",   ela.max_ela  != null ? ela.max_ela.toFixed(3)  : "—", false)
        + _elaStat("Std Dev",   ela.std_ela  != null ? ela.std_ela.toFixed(3)  : "—",
                   (ela.std_ela || 0) > 15.0)
        + _elaStat("Threshold", "8.0 mean / 15.0 std", false)
        + '<div class="ela-verdict-box ' + (isManip ? "manipulated" : "clean") + '">'
        +   (isManip ? "⚠ Potential manipulation detected. " : "✅ ")
        +   _esc(explanationText)
        + '</div>'
        + '</div>';

    html += statsHtml;
    grid.innerHTML = html;
}

function _elaStat(label, value, highlight) {
    return (
        '<div class="ela-stat-box">'
        + '<div class="ela-stat-label">' + _esc(label) + '</div>'
        + '<div class="ela-stat-value" style="color:'
        +   (highlight ? "var(--red)" : "var(--text)") + '">'
        + _esc(String(value)) + '</div>'
        + '</div>'
    );
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

function renderExplanationTabs(mod, data) {
    var exp = (typeof data.explanation === "object" && data.explanation !== null)
              ? data.explanation
              : mod.explanation || {};

    if (!exp || typeof exp === "string") {
        document.getElementById("expOverviewBody").innerHTML =
            '<p class="exp-narrative-para">' + _esc(String(exp || "Analysis complete.")) + '</p>';
        return;
    }

    _renderOverviewTab(mod, data, exp);
    _renderVisualTab(mod, exp);
    _renderSignalsTab(exp);
}


// ── Tab 1: Overview ───────────────────────────────────────────────────────
function _renderOverviewTab(mod, data, exp) {
    var el      = document.getElementById("expOverviewBody");
    var verdict = (exp.verdict || "CLEAN").toUpperCase();
    var score   = exp.risk_score || 0;
    var label   = verdict.toLowerCase();

    var bannerMeta = {
        clean:      { icon: "✅", label: "Clean",      color: "var(--green)" },
        suspicious: { icon: "⚠️",  label: "Suspicious", color: "var(--amber)" },
        malicious:  { icon: "🚨", label: "Phishing",   color: "var(--red)"   },
    };
    var bm = bannerMeta[label] || { icon: "❓", label: verdict, color: "var(--text-muted)" };

    var actionMeta = {
        ALLOW:      { label: "Allow",      cls: "action-allow",      icon: "✅" },
        WARN:       { label: "Review",     cls: "action-warn",       icon: "⚠️" },
        QUARANTINE: { label: "Quarantine", cls: "action-quarantine", icon: "🚨" },
    };
    var am = actionMeta[data.recommended_action || "WARN"] || actionMeta.WARN;

    // Count active signals for badge
    var signalCount = 0;
    if (exp.brand_analysis   && exp.brand_analysis.count   > 0) signalCount++;
    if (exp.keyword_analysis && exp.keyword_analysis.count > 0) signalCount++;
    if (exp.qr_analysis      && exp.qr_analysis.malicious_urls
        && exp.qr_analysis.malicious_urls.length > 0) signalCount++;
    if (exp.stego_analysis   && exp.stego_analysis.suspicious) signalCount++;
    if (exp.ela_analysis     && exp.ela_analysis.is_potentially_manipulated) signalCount++;
    if (exp.exif_analysis    && exp.exif_analysis.flags
        && exp.exif_analysis.flags.length > 0) signalCount++;
    var badge = document.getElementById("expBadgeSignals");
    if (badge) badge.textContent = signalCount || "";

    var gd = exp.gemini_description || {};

    var html =
        '<div class="exp-risk-banner banner-' + label + '">'
        + '<div class="exp-banner-icon">' + bm.icon + '</div>'
        + '<div class="exp-banner-text">'
        +   '<h3 style="color:' + bm.color + '">'
        +     bm.label + ' — Score ' + score.toFixed(1) + '/100'
        +   '</h3>'
        +   '<p>' + _esc(exp.summary || "") + '</p>'
        + '</div>'
        + '</div>';

    // Gemini summary in overview
    if (gd.available && gd.description) {
        html +=
            '<div class="exp-section">'
            + '<div class="exp-section-label">✨ Gemini AI — What this image shows</div>'
            + '<div class="img-gemini-inline">'
            +   '<p class="img-gemini-inline-text">' + _esc(gd.description) + '</p>'
            + '</div>'
            + '</div>';
    }

    // Narrative sentences
    var narratives = _buildOverviewNarrative(exp, mod);
    html +=
        '<div class="exp-section">'
        + '<div class="exp-section-label">Analysis Summary</div>'
        + narratives.map(function (n) {
            return '<p class="exp-narrative-para">' + _esc(n) + '</p>';
          }).join("")
        + '</div>';

    // OCR warning
    if (exp.ocr_note) {
        html +=
            '<div style="background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.25);'
            + 'border-radius:6px;padding:10px 14px;margin-bottom:14px;">'
            + '<p style="font-size:12px;color:var(--amber);margin:0">⚠ '
            + _esc(exp.ocr_note) + '</p>'
            + '</div>';
    }

    // Recommended action
    html +=
        '<div class="exp-section">'
        + '<div class="exp-section-label">Recommended Action</div>'
        + '<span class="exp-action-pill ' + am.cls + '">' + am.icon + ' ' + am.label + '</span>'
        + '</div>';

    el.innerHTML = html;
}

function _buildOverviewNarrative(exp, mod) {
    var parts   = [];
    var verdict = (exp.verdict || "CLEAN").toUpperCase();
    var score   = exp.risk_score || 0;
    var brands  = (exp.brand_analysis   || {}).brands_found   || [];
    var kws     = (exp.keyword_analysis || {}).keywords_found || [];
    var clf     = exp.classifier || {};

    // Verdict sentence
    if (verdict === "MALICIOUS") {
        parts.push(
            "The image scored " + score.toFixed(1) + "/100 — strong phishing indicators were found. "
            + "This image should not be trusted and the source should be investigated."
        );
    } else if (verdict === "SUSPICIOUS") {
        parts.push(
            "The image scored " + score.toFixed(1) + "/100 — suspicious signals were detected. "
            + "Manual review is recommended before acting on any content shown in this image."
        );
    } else {
        parts.push(
            "The image scored " + score.toFixed(1) + "/100. "
            + "No significant phishing indicators were found. "
            + "The image appears to be clean based on all analysis layers."
        );
    }

    // Classifier
    if (clf.label === "PHISHING") {
        parts.push(
            "The DistilBERT phishing classifier analysed the OCR-extracted text and returned "
            + "PHISHING with " + (clf.score_pct || 0) + "% confidence."
        );
    } else if (clf.label === "SAFE") {
        parts.push("The phishing classifier found no phishing content in the extracted text.");
    } else {
        parts.push(
            "The classifier could not produce a reliable result — too little text was "
            + "extracted by OCR. The verdict is based on brand detection, keyword "
            + "matching, and structural analysis."
        );
    }

    // Brands + keywords combined
    if (brands.length > 0 && kws.length > 0) {
        parts.push(
            brands.length + " known brand name(s) (" + brands.slice(0, 3).join(", ") + ") "
            + "and " + kws.length + " phishing keyword phrase(s) were detected in the image. "
            + "The combination of brand impersonation and urgency language is a "
            + "primary phishing technique."
        );
    } else if (brands.length > 0) {
        parts.push(
            brands.length + " brand name(s) detected: " + brands.join(", ") + ". "
            + "Verify the image source — brand names alone do not confirm phishing."
        );
    } else if (kws.length > 0) {
        parts.push(
            kws.length + " phishing keyword phrase(s) were matched in the image text. "
            + "Common patterns: urgency language, credential requests, account warnings."
        );
    }

    // ELA
    var ela = exp.ela_analysis;
    if (ela && ela.available && ela.is_potentially_manipulated) {
        parts.push(
            "Error Level Analysis detected potential image manipulation "
            + "(mean ELA: " + (ela.mean_ela || 0).toFixed(2) + "). "
            + "This image may contain inserted or edited regions — a technique "
            + "used to forge phishing screenshots."
        );
    }

    return parts;
}


// ── Tab 2: Visual Analysis ────────────────────────────────────────────────
function _renderVisualTab(mod, exp) {
    var el  = document.getElementById("expVisualBody");
    var gd  = exp.gemini_description || {};
    var ela = exp.ela_analysis || {};

    var html = "";

    // Gemini description
    html += '<div class="exp-section"><div class="exp-section-label">✨ Gemini 1.5 Pro — Full Image Description</div>';
    if (gd.available && gd.description) {
        html +=
            '<div class="img-gemini-inline">'
            + '<p class="img-gemini-inline-text">' + _esc(gd.description) + '</p>'
            + '</div>'
            + '<p style="font-size:11px;color:var(--text-muted);margin-top:6px">'
            + 'Model: ' + _esc(gd.model || "gemini-1.5-pro")
            + ' · Describes scene content, visible text, layout, and security-relevant observations.'
            + '</p>';
    } else {
        html +=
            '<div style="background:var(--bg3);border:1px solid var(--border);'
            + 'border-radius:6px;padding:12px 14px;color:var(--text-muted);font-size:13px;">'
            + _esc(gd.error || "Gemini description not available.") + '</div>';
    }
    html += '</div>';

    // ELA visualisation
    // Bug 4 FIX: use same fallback logic as renderEla() — never render empty text
    var elaExplanationText = (ela.explanation && ela.explanation.trim())
        ? ela.explanation
        : "ELA is not available for this image format. "
          + "Error Level Analysis only applies to JPEG images.";

    html += '<div class="exp-section"><div class="exp-section-label">🔬 Error Level Analysis (ELA)</div>';
    if (ela.available) {
        html += '<div class="img-ela-inline-wrap">';
        if (ela.ela_image_b64) {
            html +=
                '<img class="img-ela-inline-img" '
                + 'src="data:image/png;base64,' + _esc(ela.ela_image_b64)
                + '" alt="ELA difference map">';
        }
        html +=
            '<p style="font-size:13px;color:'
            + (ela.is_potentially_manipulated ? "var(--red)" : "var(--green)")
            + ';margin:0">'
            + (ela.is_potentially_manipulated ? "⚠ " : "✅ ")
            + _esc(elaExplanationText) + '</p>'
            + '<p style="font-size:11px;color:var(--text-muted);margin-top:8px">'
            + 'Mean: '  + (ela.mean_ela || 0).toFixed(3)
            + ' · Max: ' + (ela.max_ela  || 0).toFixed(3)
            + ' · Std: ' + (ela.std_ela  || 0).toFixed(3)
            + '</p>';
        html += '</div>';
    } else {
        html +=
            '<p style="font-size:13px;color:var(--text-muted);">'
            + _esc(elaExplanationText) + '</p>';
    }
    html += '</div>';

    // Face + logo detection
    var fl = mod.face_logo || {};
    if (fl.available) {
        html +=
            '<div class="exp-section">'
            + '<div class="exp-section-label">👤 Face &amp; Logo Detection</div>'
            + '<p style="font-size:13px;color:var(--text-muted);">'
            + 'Faces detected: <strong style="color:var(--text)">'
            + (fl.face_count || 0) + '</strong>'
            + ' · Logo candidate regions: <strong style="color:var(--text)">'
            + (fl.logo_regions ? fl.logo_regions.length : 0) + '</strong>'
            + '</p>'
            + '</div>';
    }

    // EXIF section
    var exifA = exp.exif_analysis;
    if (exifA) {
        html +=
            '<div class="exp-section">'
            + '<div class="exp-section-label">📷 EXIF Metadata</div>'
            + '<p style="font-size:13px;color:var(--text-muted);margin-bottom:8px">'
            + _esc(exifA.explanation || "") + '</p>';
        if (exifA.explanations && exifA.explanations.length) {
            html += '<ul style="margin:0;padding-left:18px;">';
            exifA.explanations.forEach(function (e) {
                html += '<li style="color:var(--amber);font-size:12px;margin-bottom:4px">⚠ '
                      + _esc(e) + '</li>';
            });
            html += '</ul>';
        }
        if (exifA.gps) {
            html +=
                '<p style="font-size:12px;color:var(--text-muted);margin-top:6px">'
                + '📍 GPS: ' + exifA.gps.lat + ', ' + exifA.gps.lon + '</p>';
        }
        html += '</div>';
    }

    el.innerHTML = html;
}


// ── Tab 3: Signals & ML ───────────────────────────────────────────────────
function _renderSignalsTab(exp) {
    var el   = document.getElementById("expSignalsBody");
    var html = "";

    // Classifier
    var clf    = exp.classifier || {};
    var clfClr = clf.label === "PHISHING" ? "danger"
               : clf.label === "SAFE"     ? "ok" : "warn";
    html += _sigCard(
        "🤖 ML Phishing Classifier",
        _normLabel(clf.label || "UNKNOWN"),
        clfClr,
        '<p style="font-size:13px;color:var(--text-muted);margin-bottom:6px">'
        + '<em>' + _esc(clf.method || "") + '</em></p>'
        + '<p style="font-size:13px;color:var(--text)">'
        + _esc(clf.explanation || "") + '</p>'
    );

    // Brands
    var brandA = exp.brand_analysis || {};
    html += _sigCard(
        "🏷 Brand Detection",
        brandA.count + " found",
        brandA.count > 0 ? "warn" : "ok",
        '<p style="font-size:13px;color:var(--text-muted);margin-bottom:'
        + (brandA.count ? "8px" : "0") + '">'
        + _esc(brandA.explanation || "") + '</p>'
        + (brandA.brands_found && brandA.brands_found.length
            ? '<div class="sig-tag-list">'
              + brandA.brands_found.map(function (b) {
                  return '<span class="sig-tag warn">' + _esc(b) + '</span>';
                }).join("") + '</div>'
            : "")
    );

    // Keywords
    var kwA = exp.keyword_analysis || {};
    html += _sigCard(
        "🔍 Phishing Keyword Analysis",
        kwA.count + " matched",
        kwA.count > 0 ? "danger" : "ok",
        '<p style="font-size:13px;color:var(--text-muted);margin-bottom:'
        + (kwA.count ? "8px" : "0") + '">'
        + _esc(kwA.explanation || "") + '</p>'
        + (kwA.keywords_found && kwA.keywords_found.length
            ? '<div class="sig-tag-list">'
              + kwA.keywords_found.map(function (kw) {
                  return '<span class="sig-tag danger">' + _esc(kw) + '</span>';
                }).join("") + '</div>'
            : "")
    );

    // QR
    var qrA = exp.qr_analysis;
    if (qrA) {
        var qrSev = (qrA.malicious_urls  && qrA.malicious_urls.length)  ? "danger"
                  : (qrA.suspicious_urls && qrA.suspicious_urls.length) ? "warn" : "ok";
        var qrBody = '<p style="font-size:13px;color:var(--text-muted)">'
                   + _esc(qrA.explanation || "") + '</p>';
        if (qrA.malicious_urls && qrA.malicious_urls.length) {
            qrBody += '<div style="margin-top:6px">';
            qrA.malicious_urls.forEach(function (u) {
                qrBody += '<div style="font-family:monospace;font-size:11px;'
                        + 'color:var(--red);word-break:break-all">' + _esc(u) + '</div>';
            });
            qrBody += '</div>';
        }
        html += _sigCard("📷 QR Code Analysis", qrA.code_count + " code(s)", qrSev, qrBody);
    }

    // Stego
    var stegoA = exp.stego_analysis;
    if (stegoA) {
        var stegoSev = stegoA.suspicious ? "warn" : "ok";
        html += _sigCard(
            "🕵 Steganography Detection",
            stegoA.suspicious
                ? "Suspicious (" + stegoA.confidence + " confidence)"
                : "Clean",
            stegoSev,
            '<p style="font-size:13px;color:var(--text-muted);margin-bottom:'
            + (stegoA.flags && stegoA.flags.length ? "8px" : "0") + '">'
            + _esc(stegoA.explanation || "") + '</p>'
            + (stegoA.flags && stegoA.flags.length
                ? '<div class="sig-tag-list">'
                  + stegoA.flags.map(function (f) {
                      return '<span class="sig-tag warn">' + _esc(f) + '</span>';
                    }).join("") + '</div>'
                : "")
        );
    }

    el.innerHTML = html;
}

function _sigCard(title, badge, severity, bodyHtml) {
    return (
        '<div class="sig-card">'
        + '<div class="sig-card-header">'
        +   '<span class="sig-card-title">'  + _esc(title) + '</span>'
        +   '<span class="sig-card-badge sig-badge-' + severity + '">'
        +     _esc(badge) + '</span>'
        + '</div>'
        + '<div class="sig-card-body">' + bodyHtml + '</div>'
        + '</div>'
    );
}


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
    if (!scans.length) {
        historyBody.innerHTML = '<tr><td colspan="9" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }
    scans.forEach(function (s) {
        var verdict      = (s.verdict || "CLEAN").toUpperCase();
        var verdictClass = {
            CLEAN:      "badge-safe",
            SUSPICIOUS: "badge-suspicious",
            MALICIOUS:  "badge-malicious",
        }[verdict] || "badge-safe";
        var dims   = (s.image_width || 0) + "×" + (s.image_height || 0);
        var ts     = (s.scanned_at || "").replace("T", " ").replace("Z", "").slice(0, 19);
        var brands = (s.detected_brands   || []).length;
        var kws    = (s.phishing_keywords || []).length;
        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>"
            + "<td class='att-fname'>" + escapeHtml(s.filename || "—") + "</td>"
            + "<td>" + dims + "</td>"
            + "<td>" + (s.ocr_word_count || 0) + "</td>"
            + "<td class='" + (brands > 0 ? "att-cell-amber" : "") + "'>" + brands + "</td>"
            + "<td class='" + (kws    > 0 ? "att-cell-red"   : "") + "'>" + kws    + "</td>"
            + "<td>" + (s.risk_score || 0).toFixed(1) + "</td>"
            + "<td><span class='badge " + verdictClass + "'>" + verdict + "</span></td>"
            + "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════════════════════

// Bug 2 FIX: _normLabel was defined twice — once inside renderClassifier
// and once inside _renderSignalsTab. Both definitions were identical.
// Consolidated here as a single top-level function used by both callers.
function _normLabel(label) {
    var map = {
        "LABEL_1":          "PHISHING",
        "1":                "PHISHING",
        "LABEL_0":          "SAFE",
        "0":                "SAFE",
        "INSUFFICIENT_DATA":"Insufficient Text",
        "NO_TEXT":          "No Text",
        "UNKNOWN":          "Unknown",
    };
    return map[label] || label;
}

function _esc(str) {
    return (str || "").toString()
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#039;");
}

function setLoading(on) {
    scanBtn.disabled      = on;
    btnText.style.display = on ? "none"   : "inline";
    spinner.style.display = on ? "inline" : "none";
}

function showError(msg) { imgError.textContent = "⚠ " + msg; imgError.style.display = "block"; }
function hideError()    { imgError.style.display = "none"; imgError.textContent = ""; }

function formatBytes(bytes) {
    if (bytes < 1024)    return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(2) + " MB";
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
setInterval(loadHistory, 5000);