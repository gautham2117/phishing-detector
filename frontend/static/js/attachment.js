"use strict";

// ── Bootstrap — read URLs from data island ─────────────────────────────────
var _pd          = document.getElementById("page-data");
var SCAN_URL     = _pd.dataset.scanUrl;
var HISTORY_URL  = _pd.dataset.historyUrl;
var DETAIL_URL   = _pd.dataset.detailUrl;

// ── DOM handles ────────────────────────────────────────────────────────────
var dropZone      = document.getElementById("dropZone");
var fileInput     = document.getElementById("fileInput");
var scanBtn       = document.getElementById("scanBtn");
var btnSpinner    = document.getElementById("btnSpinner");
var uploadError   = document.getElementById("uploadError");
var selectedInfo  = document.getElementById("selectedInfo");
var selectedName  = document.getElementById("selectedName");
var selectedSize  = document.getElementById("selectedSize");
var resultsPanel  = document.getElementById("resultsPanel");
var historyBody   = document.getElementById("historyBody");

var _selectedFile = null;
var _pollTimer    = null;


// ════════════════════════════════════════════════════════════════════════════
// FILE SELECTION
// ════════════════════════════════════════════════════════════════════════════

function setFile(file) {
    _selectedFile = file;
    selectedName.textContent = file.name;
    selectedSize.textContent = "(" + formatBytes(file.size) + ")";
    selectedInfo.style.display = "flex";
    scanBtn.disabled = false;
    hideError();
}

function formatBytes(bytes) {
    if (bytes < 1024)       return bytes + " B";
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(2) + " MB";
}

// Input change
fileInput.addEventListener("change", function () {
    if (this.files && this.files[0]) {
        setFile(this.files[0]);
    }
});

// Drag and drop
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
    if (files && files[0]) {
        setFile(files[0]);
    }
});

// Click on drop zone (but not on the label — that already triggers input)
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
    submitScan(_selectedFile);
});

function submitScan(file) {
    hideError();
    setScanLoading(true);
    resultsPanel.style.display = "none";

    var emailId = document.getElementById("emailScanId").value.trim();
    var fd = new FormData();
    fd.append("file", file);
    if (emailId) { fd.append("email_scan_id", emailId); }

    fetch(SCAN_URL, { method: "POST", body: fd })
        .then(function (r) {
            if (!r.ok) { throw new Error("Server responded " + r.status); }
            return r.json();
        })
        .then(function (data) {
            setScanLoading(false);
            if (data.status === "error") {
                showError(data.message || "Analysis failed.");
            } else {
                renderResults(data);
                resultsPanel.style.display = "block";
                resultsPanel.scrollIntoView({ behavior: "smooth" });
            }
        })
        .catch(function (err) {
            setScanLoading(false);
            showError("Request failed: " + err.message);
        });
}

function setScanLoading(on) {
    scanBtn.disabled = on;
    document.querySelector(".btn-text").style.display = on ? "none" : "inline";
    btnSpinner.style.display = on ? "inline" : "none";
}


// ════════════════════════════════════════════════════════════════════════════
// RESULT RENDERING
// ════════════════════════════════════════════════════════════════════════════

function renderResults(data) {
    var mod = data.module_results || {};

    renderVerdict(mod, data);
    renderHashes(mod);
    renderEntropy(mod);
    renderYara(mod);
    renderStrings(mod);
    renderDeepFindings(mod);
    renderPdfUrls(mod);
    renderExplanation(data, mod);
}

// ── Verdict ──
function renderVerdict(mod, data) {
    var verdict = mod.verdict || data.label || "CLEAN";
    var badge   = document.getElementById("verdictBadge");
    badge.textContent = verdict;
    badge.className   = "att-verdict-badge att-verdict-" + verdict.toLowerCase();

    document.getElementById("verdictFilename").textContent = mod.filename || "";
    document.getElementById("verdictType").textContent     = "Type: " + (mod.file_type || "unknown");
    document.getElementById("verdictSize").textContent     = "Size: " + formatBytes(mod.file_size || 0);

    var actionMap = { ALLOW: "✅ Allow", WARN: "⚠ Warn", QUARANTINE: "🔒 Quarantine", BLOCK: "🚫 Block" };
    document.getElementById("verdictAction").textContent =
        "Action: " + (actionMap[data.recommended_action] || data.recommended_action || "—");
}

// ── Hashes ──
function renderHashes(mod) {
    var h = mod.hashes || {};
    document.getElementById("hashMd5").textContent    = h.md5    || "—";
    document.getElementById("hashSha256").textContent = h.sha256 || "—";

    var knownBad = document.getElementById("knownBadBadge");
    knownBad.style.display = mod.known_bad ? "inline-flex" : "none";
}

// ── Entropy gauge ──
function renderEntropy(mod) {
    var entropy = parseFloat(mod.entropy) || 0.0;
    document.getElementById("entropyValue").textContent = entropy.toFixed(4);

    var pct  = Math.min((entropy / 8.0) * 100, 100);
    var fill = document.getElementById("entropyFill");
    fill.style.width = pct + "%";

    // Colour coding
    if (entropy > 7.2) {
        fill.className = "att-entropy-bar-fill att-entropy-red";
        document.getElementById("entropyNote").textContent =
            "⚠ High entropy — file may be packed or encrypted";
        document.getElementById("entropyNote").style.color = "var(--red)";
    } else if (entropy > 6.0) {
        fill.className = "att-entropy-bar-fill att-entropy-amber";
        document.getElementById("entropyNote").textContent = "Moderately elevated entropy";
        document.getElementById("entropyNote").style.color = "var(--amber)";
    } else {
        fill.className = "att-entropy-bar-fill att-entropy-green";
        document.getElementById("entropyNote").textContent = "Normal entropy range";
        document.getElementById("entropyNote").style.color = "var(--green)";
    }
}

// ── YARA matches ──
function renderYara(mod) {
    var matches = mod.yara_matches || [];
    var count   = matches.length;
    document.getElementById("yaraCount").textContent = count;
    var list    = document.getElementById("yaraList");
    list.innerHTML = "";

    if (count === 0) {
        list.innerHTML = '<span class="att-empty-note">No YARA rules matched.</span>';
        return;
    }
    matches.forEach(function (rule) {
        var tag = document.createElement("span");
        tag.className   = "att-tag att-tag-danger";
        tag.textContent = rule;
        list.appendChild(tag);
    });
}

// ── Suspicious strings ──
function renderStrings(mod) {
    var sus   = mod.suspicious_strings || [];
    var count = sus.length;
    document.getElementById("stringsCount").textContent = count;
    var list  = document.getElementById("stringsList");
    list.innerHTML = "";

    if (count === 0) {
        list.innerHTML = '<span class="att-empty-note">No suspicious strings found.</span>';
        return;
    }
    sus.forEach(function (s) {
        var tag = document.createElement("span");
        tag.className   = "att-tag att-tag-warn";
        tag.textContent = s;
        list.appendChild(tag);
    });
}

// ── Format-specific deep findings ──
function renderDeepFindings(mod) {
    var allFindings = [];

    (mod.html_analysis  && mod.html_analysis.html_findings  || []).forEach(function (f) {
        allFindings.push({ icon: "🌐", text: f, sev: "danger" });
    });
    (mod.pdf_analysis   && mod.pdf_analysis.pdf_findings    || []).forEach(function (f) {
        allFindings.push({ icon: "📄", text: f, sev: f.indexOf("error") !== -1 ? "info" : "warn" });
    });
    (mod.macro_analysis && mod.macro_analysis.macro_findings || []).forEach(function (f) {
        allFindings.push({ icon: "📝", text: f, sev: f.indexOf("detected") !== -1 ? "danger" : "info" });
    });
    (mod.zip_analysis   && mod.zip_analysis.zip_findings    || []).forEach(function (f) {
        allFindings.push({ icon: "🗜", text: f, sev: "warn" });
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
        row.className = "att-finding-row att-finding-" + item.sev;
        row.textContent = item.icon + " " + item.text;
        list.appendChild(row);
    });
}

// ── PDF embedded URLs ──
function renderPdfUrls(mod) {
    var urls = mod.pdf_analysis && mod.pdf_analysis.embedded_urls || [];
    var card = document.getElementById("pdfUrlsCard");
    var list = document.getElementById("pdfUrlList");
    list.innerHTML = "";

    if (!urls || urls.length === 0) {
        card.style.display = "none";
        return;
    }
    card.style.display = "block";
    urls.forEach(function (url) {
        var li = document.createElement("li");
        li.className = "att-url-item";
        li.textContent = url;
        list.appendChild(li);
    });
}

// ── Explanation & email link ──
function renderExplanation(data, mod) {
    document.getElementById("explanationText").textContent =
        data.explanation || "Analysis complete.";

    var emailId  = mod.email_scan_id;
    var linkRow  = document.getElementById("emailLinkRow");
    var linkEl   = document.getElementById("emailScanLink");
    if (emailId) {
        linkEl.textContent = "#" + emailId;
        linkEl.href        = "/email_scan/detail/" + emailId;
        linkRow.style.display = "block";
    } else {
        linkRow.style.display = "none";
    }
}


// ════════════════════════════════════════════════════════════════════════════
// COPY BUTTONS
// ════════════════════════════════════════════════════════════════════════════

document.addEventListener("click", function (e) {
    if (!e.target.classList.contains("att-copy-btn")) { return; }
    var targetId = e.target.dataset.target;
    var el       = document.getElementById(targetId);
    if (!el) { return; }
    var text = el.textContent;
    if (!text || text === "—") { return; }

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
// HISTORY POLLING (every 5 s)
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
            '<tr><td colspan="8" class="att-empty-row">No scans yet.</td></tr>';
        return;
    }

    scans.forEach(function (s) {
        var verdictClass = ({
            CLEAN:     "badge-safe",
            SUSPICIOUS:"badge-suspicious",
            MALICIOUS: "badge-malicious",
        })[s.verdict] || "badge-safe";

        var ts = s.scanned_at ? s.scanned_at.replace("T", " ").replace("Z", "") : "—";

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>" +
            "<td class='att-fname'>" + escapeHtml(s.filename) + "</td>" +
            "<td class='att-type'>" + escapeHtml(s.file_type || "—") + "</td>" +
            "<td>" + formatBytes(s.file_size || 0) + "</td>" +
            "<td class='" + entropyClass(s.entropy) + "'>" + (s.entropy || 0).toFixed(2) + "</td>" +
            "<td>" + (s.yara_matches || []).length + "</td>" +
            "<td><span class='badge " + verdictClass + "'>" + (s.verdict || "—") + "</span></td>" +
            "<td class='att-ts'>" + ts + "</td>";
        historyBody.appendChild(tr);
    });
}

function entropyClass(e) {
    if (!e) { return ""; }
    if (e > 7.2) { return "att-cell-red"; }
    if (e > 6.0) { return "att-cell-amber"; }
    return "";
}

function escapeHtml(str) {
    if (!str) { return ""; }
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// ERROR HELPERS
// ════════════════════════════════════════════════════════════════════════════

function showError(msg) {
    uploadError.textContent = "⚠ " + msg;
    uploadError.style.display = "block";
}
function hideError() {
    uploadError.style.display = "none";
    uploadError.textContent = "";
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadHistory();
_pollTimer = setInterval(loadHistory, 5000);