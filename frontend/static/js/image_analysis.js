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
    _selectedFile = file;
    scanBtn.disabled = false;
    hideError();

    // Show local preview immediately
    var reader = new FileReader();
    reader.onload = function (e) {
        previewImg.src = e.target.result;
        previewMeta.textContent =
            file.name + "  —  " + formatBytes(file.size);
        previewWrap.style.display = "block";
    };
    reader.readAsDataURL(file);
}

fileInput.addEventListener("change", function () {
    if (this.files && this.files[0]) { setFile(this.files[0]); }
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
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        setFile(e.dataTransfer.files[0]);
    }
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
            if (data.status === "error") {
                showError(data.message || "Analysis failed.");
                return;
            }
            renderResults(data);
            resultsPanel.style.display = "block";
            resultsPanel.scrollIntoView({ behavior: "smooth" });
        })
        .catch(function (err) {
            setLoading(false);
            showError("Request failed: " + err.message);
        });
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
    document.getElementById("imgExplanation").textContent =
        data.explanation || mod.explanation || "Analysis complete.";
}

function renderVerdict(mod, data) {
    var verdict = mod.verdict || "CLEAN";
    var badge   = document.getElementById("imgVerdictBadge");
    badge.textContent = verdict;
    badge.className   = "ai-verdict-badge ai-verdict-" +
        verdict.toLowerCase().replace("_", "-");

    document.getElementById("imgRiskScore").textContent =
        "Risk score: " + (mod.risk_score || 0).toFixed(1) + " / 100";

    var w = mod.image_width || 0;
    var h = mod.image_height || 0;
    var fmt = mod.image_format || "—";
    document.getElementById("imgDimensions").textContent =
        w + " × " + h + " px  ·  " + fmt;

    var actionMap = {
        ALLOW: "✅ Allow", WARN: "⚠ Review carefully",
        QUARANTINE: "🔒 Quarantine", BLOCK: "🚫 Block"
    };
    document.getElementById("imgAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");
}

function renderClassifier(mod) {
    var clf   = mod.classifier_result || {};
    var label = clf.label || "UNKNOWN";
    var score = clf.score || 0.0;
    var pct   = Math.round(score * 100);

    document.getElementById("imgClfLabel").textContent = label;
    document.getElementById("imgClfScore").textContent = pct + "%";

    var bar = document.getElementById("imgClfBar");
    bar.style.width = pct + "%";
    if (label === "PHISHING") {
        bar.className = "att-entropy-bar-fill att-entropy-red";
        document.getElementById("imgClfNote").textContent =
            "⚠ Classifier flagged image text as phishing content.";
        document.getElementById("imgClfNote").style.color = "var(--red)";
    } else if (label === "SAFE") {
        bar.className = "att-entropy-bar-fill att-entropy-green";
        document.getElementById("imgClfNote").textContent =
            "Classifier found no phishing content in extracted text.";
        document.getElementById("imgClfNote").style.color = "var(--green)";
    } else {
        bar.className = "att-entropy-bar-fill att-entropy-amber";
        document.getElementById("imgClfNote").textContent =
            "Insufficient text for confident classification.";
        document.getElementById("imgClfNote").style.color = "var(--text-muted)";
    }

    document.getElementById("imgOcrWords").textContent =
        (mod.ocr_word_count || 0).toLocaleString();
    document.getElementById("imgFormat").textContent =
        mod.image_format || "—";
    document.getElementById("imgFileSize").textContent =
        formatBytes(mod.file_size || 0);
}

function renderBrands(mod) {
    var brands    = mod.detected_brands || [];
    var countEl   = document.getElementById("imgBrandsCount");
    var listEl    = document.getElementById("imgBrandsList");
    var noteEl    = document.getElementById("imgBrandsNote");
    countEl.textContent = brands.length;
    listEl.innerHTML    = "";

    if (brands.length === 0) {
        listEl.innerHTML = '<span class="att-empty-note">No known brand names detected.</span>';
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

function renderOcrText(mod) {
    var text = mod.ocr_text || "";
    var el   = document.getElementById("imgOcrText");
    if (!text || text.trim().length === 0) {
        el.textContent = "No text extracted from image.";
        return;
    }
    el.textContent = text;
}


// ════════════════════════════════════════════════════════════════════════════
// HISTORY POLLING
// ════════════════════════════════════════════════════════════════════════════

function loadHistory() {
    fetch(HISTORY_URL + "?limit=20")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderHistory(data.scans || []);
        })
        .catch(function () {/* silent */});
}

function renderHistory(scans) {
    historyBody.innerHTML = "";
    if (scans.length === 0) {
        historyBody.innerHTML =
            '<tr><td colspan="9" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }
    scans.forEach(function (s) {
        var verdictClass = {
            CLEAN:     "badge-safe",
            SUSPICIOUS:"badge-suspicious",
            MALICIOUS: "badge-malicious",
        }[s.verdict] || "badge-safe";

        var dims = s.image_width + "×" + s.image_height;
        var ts   = (s.scanned_at || "").replace("T"," ").replace("Z","").slice(0, 19);
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
            "<td><span class='badge " + verdictClass + "'>" + (s.verdict || "—") + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function setLoading(on) {
    scanBtn.disabled      = on;
    btnText.style.display = on ? "none"   : "inline";
    spinner.style.display = on ? "inline" : "none";
}

function showError(msg) {
    imgError.textContent   = "⚠ " + msg;
    imgError.style.display = "block";
}
function hideError() {
    imgError.style.display = "none";
    imgError.textContent   = "";
}

function formatBytes(bytes) {
    if (bytes < 1024)    { return bytes + " B"; }
    if (bytes < 1048576) { return (bytes / 1024).toFixed(1) + " KB"; }
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