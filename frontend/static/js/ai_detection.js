"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd          = document.getElementById("page-data");
var TEXT_URL     = _pd.dataset.textUrl;
var URL_URL      = _pd.dataset.urlUrl;
var FILE_URL     = _pd.dataset.fileUrl;
var HISTORY_URL  = _pd.dataset.historyUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var scanBtn      = document.getElementById("aiScanBtn");
var spinner      = document.getElementById("aiSpinner");
var btnText      = document.querySelector(".ai-btn-text");
var aiError      = document.getElementById("aiError");
var resultsPanel = document.getElementById("aiResultsPanel");
var historyBody  = document.getElementById("aiHistoryBody");
var charCount    = document.getElementById("charCount");
var textInput    = document.getElementById("textInput");

var _activeTab   = "text";
var _selectedFile= null;


// ════════════════════════════════════════════════════════════════════════════
// TABS
// ════════════════════════════════════════════════════════════════════════════

document.querySelectorAll(".ai-tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
        document.querySelectorAll(".ai-tab").forEach(function (b) {
            b.classList.remove("active");
        });
        document.querySelectorAll(".ai-tab-panel").forEach(function (p) {
            p.classList.remove("active");
        });
        btn.classList.add("active");
        _activeTab = btn.dataset.tab;
        document.getElementById("panel-" + _activeTab).classList.add("active");
        hideError();
    });
});


// ════════════════════════════════════════════════════════════════════════════
// CHARACTER COUNTER
// ════════════════════════════════════════════════════════════════════════════

textInput.addEventListener("input", function () {
    var len = textInput.value.length;
    charCount.textContent = len;
    charCount.style.color = len > 7500 ? "var(--amber)" : "var(--text-muted)";
});


// ════════════════════════════════════════════════════════════════════════════
// FILE DROP ZONE
// ════════════════════════════════════════════════════════════════════════════

var dropZone  = document.getElementById("aiDropZone");
var fileInput = document.getElementById("aiFileInput");

function setFile(file) {
    _selectedFile = file;
    document.getElementById("aiSelectedName").textContent = file.name;
    document.getElementById("aiSelectedSize").textContent =
        "(" + formatBytes(file.size) + ")";
    document.getElementById("aiSelectedInfo").style.display = "flex";
    hideError();
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

scanBtn.addEventListener("click", function () { submitScan(); });

function submitScan() {
    hideError();
    setLoading(true);
    resultsPanel.style.display = "none";

    if (_activeTab === "text") {
        var text = textInput.value.trim();
        if (!text) { setLoading(false); showError("Please paste some text first."); return; }
        postJSON(TEXT_URL, { text: text, source_ref: "" });

    } else if (_activeTab === "url") {
        var url = document.getElementById("urlInput").value.trim();
        if (!url) { setLoading(false); showError("Please enter a URL."); return; }
        postJSON(URL_URL, { url: url });

    } else if (_activeTab === "file") {
        if (!_selectedFile) { setLoading(false); showError("Please select a file first."); return; }
        var fd = new FormData();
        fd.append("file", _selectedFile);
        fetch(FILE_URL, { method: "POST", body: fd })
            .then(function (r) { return r.json(); })
            .then(handleResult)
            .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
    }
}

function postJSON(url, payload) {
    fetch(url, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
    })
    .then(function (r) { return r.json(); })
    .then(handleResult)
    .catch(function (err) { setLoading(false); showError("Request failed: " + err.message); });
}

function handleResult(data) {
    setLoading(false);
    if (data.status === "error") {
        showError(data.message || data.explanation || "Analysis failed.");
        return;
    }
    renderResults(data);
    resultsPanel.style.display = "block";
    resultsPanel.scrollIntoView({ behavior: "smooth" });
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var mod = (data.module_results || {}).ai_detection || {};

    renderVerdict(mod, data);
    renderMeter(mod);
    renderExplanation(data, mod);
    renderHeatmap(mod);
}

// ── Verdict card ──
function renderVerdict(mod, data) {
    var verdict = mod.verdict || "HUMAN";
    var badge   = document.getElementById("aiVerdictBadge");
    badge.textContent = verdict.replace("_", " ");
    badge.className   = "ai-verdict-badge ai-verdict-" + verdict.toLowerCase().replace("_", "-");

    var pct = Math.round((mod.ai_probability || 0) * 100);
    document.getElementById("aiVerdictProb").textContent  = pct + "% AI probability";
    document.getElementById("aiVerdictMeta").textContent  =
        (mod.sentence_count || 0) + " sentence(s) · " +
        (mod.char_count     || 0) + " characters";

    var actionMap = {
        ALLOW: "✅ Allow", WARN: "⚠ Review carefully",
        QUARANTINE: "🔒 Quarantine", BLOCK: "🚫 Block"
    };
    document.getElementById("aiVerdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");
}

// ── Probability meter ──
function renderMeter(mod) {
    var prob = mod.ai_probability || 0;
    var pct  = Math.round(prob * 100);

    document.getElementById("aiMeterValue").textContent = pct + "%";

    var fill = document.getElementById("aiMeterFill");
    fill.style.width = pct + "%";

    if (pct >= 75) {
        fill.className = "ai-meter-fill ai-fill-ai";
    } else if (pct >= 45) {
        fill.className = "ai-meter-fill ai-fill-mixed";
    } else {
        fill.className = "ai-meter-fill ai-fill-human";
    }

    document.getElementById("statChars").textContent     = (mod.char_count     || 0).toLocaleString();
    document.getElementById("statSentences").textContent = mod.sentence_count  || 0;
    document.getElementById("statType").textContent      = mod.input_type      || "text";
}

// ── Explanation ──
function renderExplanation(data, mod) {
    document.getElementById("aiExplanation").textContent =
        data.explanation || mod.explanation || "Analysis complete.";
}

// ── Sentence heatmap ──
function renderHeatmap(mod) {
    var sentences = mod.sentence_scores || [];
    var heatmap   = document.getElementById("aiHeatmap");
    heatmap.innerHTML = "";

    var card = document.getElementById("aiHeatmapCard");
    if (sentences.length === 0) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";

    sentences.forEach(function (item) {
        var div = document.createElement("div");
        div.className = "ai-sentence ai-sentence-" +
            item.label.toLowerCase().replace("_", "-");

        var pct   = Math.round((item.ai_prob || 0) * 100);
        var badge = document.createElement("span");
        badge.className   = "ai-sentence-pct";
        badge.textContent = pct + "%";

        var text = document.createElement("span");
        text.className   = "ai-sentence-text";
        text.textContent = item.sentence;

        div.appendChild(badge);
        div.appendChild(text);
        heatmap.appendChild(div);
    });
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
            '<tr><td colspan="7" class="att-empty-row">No detections yet.</td></tr>';
        return;
    }
    scans.forEach(function (s) {
        var verdictClass = {
            HUMAN:        "badge-safe",
            MIXED:        "badge-suspicious",
            AI_GENERATED: "badge-malicious",
        }[s.verdict] || "badge-safe";

        var pct      = Math.round((s.ai_probability || 0) * 100);
        var preview  = (s.source_ref || s.input_preview || "—").slice(0, 50);
        var ts       = (s.scanned_at || "").replace("T", " ").replace("Z", "").slice(0, 19);
        var typeIcon = { text: "✏", url: "🔗", file: "📎" }[s.input_type] || "?";

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>" +
            "<td>" + typeIcon + " " + escapeHtml(s.input_type || "") + "</td>" +
            "<td class='ai-preview-cell'>" + escapeHtml(preview) + "</td>" +
            "<td>" + (s.sentence_count || 0) + "</td>" +
            "<td class='" + probClass(pct) + "'>" + pct + "%</td>" +
            "<td><span class='badge " + verdictClass + "'>" +
                (s.verdict || "—").replace("_", " ") +
            "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}

function probClass(pct) {
    if (pct >= 75) { return "att-cell-red"; }
    if (pct >= 45) { return "att-cell-amber"; }
    return "";
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function setLoading(on) {
    scanBtn.disabled       = on;
    btnText.style.display  = on ? "none"   : "inline";
    spinner.style.display  = on ? "inline" : "none";
}

function showError(msg) {
    aiError.textContent    = "⚠ " + msg;
    aiError.style.display  = "block";
}
function hideError() {
    aiError.style.display  = "none";
    aiError.textContent    = "";
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