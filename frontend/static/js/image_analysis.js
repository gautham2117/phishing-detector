// image_analysis.js
// Client-side logic for the Image Analysis dashboard page.
"use strict";


// ─── Drag and drop ────────────────────────────────────────────────────────────

var dropZone = document.getElementById("drop-zone");
if (dropZone) {
    dropZone.addEventListener("dragover", function(e) {
        e.preventDefault();
        dropZone.classList.add("drag-over");
    });
    dropZone.addEventListener("dragleave", function() {
        dropZone.classList.remove("drag-over");
    });
    dropZone.addEventListener("drop", function(e) {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        var file = e.dataTransfer.files[0];
        if (file) processImageFile(file);
    });
}


// ─── File input handler ───────────────────────────────────────────────────────

function handleImageSelect(input) {
    var file = input.files[0];
    if (!file) return;
    processImageFile(file);
}


// ─── Process selected image ───────────────────────────────────────────────────

function processImageFile(file) {
    // Show preview before uploading
    var reader  = new FileReader();
    var preview = document.getElementById("image-preview");
    var previewContainer = document.getElementById("preview-container");

    reader.onload = function(e) {
        if (preview) preview.src = e.target.result;
        if (previewContainer) previewContainer.style.display = "block";
    };
    reader.readAsDataURL(file);

    // Upload and analyze
    uploadImage(file);
}


// ─── Upload image to Flask proxy ─────────────────────────────────────────────

async function uploadImage(file) {
    showSpinner(true, "Running OCR + DistilBERT + OpenCV + ViT...");
    hideResultCard();

    var formData = new FormData();
    formData.append("file", file);

    try {
        var resp = await fetch("/image/submit", {
            method: "POST",
            body:   formData
        });

        var data = await resp.json();

        if (!resp.ok) {
            alert("Error: " + (data.error || resp.statusText));
            return;
        }

        renderResult(data);

    } catch (err) {
        alert("Network error: " + err.message);
    } finally {
        showSpinner(false);
    }
}


// ─── Render result ────────────────────────────────────────────────────────────

function renderResult(data) {
    /*
     * data.module_results.image_analysis contains:
     * {
     *   filename, image_info: {width, height, file_size},
     *   ocr_result:        {text, word_count, confidence, error},
     *   distilbert_result: {label, score},
     *   opencv_result:     {input_fields_detected, buttons_detected,
     *                       is_likely_login_page, has_password_region,
     *                       total_rectangles},
     *   vit_result:        {top_predictions, brand_detected,
     *                       brand_confidence, is_impersonation, available},
     *   risk_score, verdict, flags, explanation
     * }
     */
    var ia = (data.module_results && data.module_results.image_analysis)
        ? data.module_results.image_analysis
        : {};

    // ── Header ──
    _setText("res-filename", ia.filename || "—");
    var info = ia.image_info || {};
    _setText("res-dimensions",
        info.width
            ? info.width + " × " + info.height + " px · "
              + _formatBytes(info.file_size)
            : "—"
    );

    // ── Verdict badge ──
    var verdict = ia.verdict || "Unknown";
    var badge   = document.getElementById("verdict-badge");
    if (badge) {
        badge.textContent = verdict;
        badge.className   = "risk-badge badge-" + (
            verdict === "Clean"     ? "safe"       :
            verdict === "Malicious" ? "malicious"  : "suspicious"
        );
    }

    // ── Score bar ──
    var score = data.risk_score || 0;
    var bar   = document.getElementById("score-bar");
    if (bar) {
        bar.style.width = score + "%";
        bar.className   = "score-bar-fill " + (
            score < 30 ? "fill-safe"
            : score < 70 ? "fill-suspicious"
            : "fill-malicious"
        );
    }
    _setText("score-num", score.toFixed(1));

    // ── Flags row ──
    var flagsRow = document.getElementById("flags-row");
    if (flagsRow) {
        var flags = ia.flags || [];
        flagsRow.innerHTML = flags.length === 0
            ? ""
            : flags.map(function(f) {
                return '<span class="flag-pill">' + _esc(f) + '</span>';
              }).join("");
    }

    // ── OCR panel ──
    var ocr = ia.ocr_result || {};
    _setText("ocr-words", ocr.word_count != null ? ocr.word_count : "—");
    _setText("ocr-conf",
        ocr.confidence != null ? ocr.confidence + "%" : "—"
    );

    var ocrStatus = document.getElementById("ocr-status");
    if (ocrStatus) {
        if (ocr.error) {
            ocrStatus.innerHTML =
                '<span class="auth-pill auth-fail">Error</span>';
            ocrStatus.title = ocr.error;
        } else {
            ocrStatus.innerHTML =
                '<span class="auth-pill auth-pass">OK</span>';
        }
    }

    var ocrBox = document.getElementById("ocr-text-box");
    if (ocrBox) {
        ocrBox.textContent = ocr.text
            ? _trunc(ocr.text, 500)
            : "(no text extracted)";
    }

    // ── DistilBERT panel ──
    var dist      = ia.distilbert_result || {};
    var distVerdict = document.getElementById("distilbert-verdict");
    if (distVerdict) {
        distVerdict.textContent = dist.label || "—";
        distVerdict.style.color =
            dist.label === "PHISHING" ? "var(--red)"  :
            dist.label === "SAFE"     ? "var(--green)" :
            "var(--text-muted)";
    }

    var distScore = Math.round((dist.score || 0) * 100);
    var distBar   = document.getElementById("distilbert-bar");
    if (distBar) {
        distBar.style.width = distScore + "%";
        distBar.className   = "confidence-bar-fill " + (
            distScore >= 50 ? "fill-malicious" : "fill-safe"
        );
    }
    _setText("distilbert-conf", distScore + "% confidence");

    // ── OpenCV panel ──
    var cv = ia.opencv_result || {};
    _setText("cv-inputs",   cv.input_fields_detected != null ? cv.input_fields_detected : "—");
    _setText("cv-buttons",  cv.buttons_detected      != null ? cv.buttons_detected      : "—");
    _setText("cv-total",    cv.total_rectangles       != null ? cv.total_rectangles      : "—");

    var cvLogin = document.getElementById("cv-login");
    if (cvLogin) {
        cvLogin.innerHTML = cv.is_likely_login_page
            ? '<span class="auth-pill auth-fail">Yes — login form detected</span>'
            : '<span class="auth-pill auth-pass">No</span>';
    }

    var cvPwd = document.getElementById("cv-password");
    if (cvPwd) {
        cvPwd.innerHTML = cv.has_password_region
            ? '<span class="auth-pill auth-fail">Likely</span>'
            : '<span class="auth-pill auth-none">Not detected</span>';
    }

    // ── ViT panel ──
    var vit = ia.vit_result || {};
    var vitVerdict = document.getElementById("vit-verdict");
    if (vitVerdict) {
        if (!vit.available) {
            vitVerdict.textContent = "Model not loaded";
            vitVerdict.style.color = "var(--text-muted)";
        } else if (vit.is_impersonation) {
            vitVerdict.textContent =
                "Brand impersonation: " + (vit.brand_detected || "unknown");
            vitVerdict.style.color = "var(--red)";
        } else if (vit.brand_detected) {
            vitVerdict.textContent = "Brand element: " + vit.brand_detected;
            vitVerdict.style.color = "var(--amber)";
        } else {
            vitVerdict.textContent = "No brand impersonation detected";
            vitVerdict.style.color = "var(--green)";
        }
    }

    var predContainer = document.getElementById("vit-predictions");
    if (predContainer) {
        var preds = vit.top_predictions || [];
        if (!vit.available) {
            predContainer.innerHTML =
                '<p class="model-unavailable">ViT model not loaded</p>';
        } else if (preds.length === 0) {
            predContainer.innerHTML =
                '<p class="empty-state">No predictions available</p>';
        } else {
            predContainer.innerHTML = preds.map(function(p) {
                var pct = Math.round(p.score * 100);
                return '<div class="feature-row">'
                    + '<span class="feature-name">'
                    + _esc(_trunc(p.label, 28)) + '</span>'
                    + '<div class="feature-bar-track">'
                    + '<div class="feature-bar-fill" style="width:' + Math.min(pct*4, 100) + '%"></div>'
                    + '</div>'
                    + '<span class="feature-val">' + pct + '%</span>'
                    + '</div>';
            }).join("");
        }
    }

    // ── Explanation ──
    _setText("explanation-text", data.explanation || ia.explanation || "—");

    // ── Show result card ──
    var card = document.getElementById("result-card");
    if (card) {
        card.style.display = "block";
        card.scrollIntoView({ behavior: "smooth" });
    }
    _setText("update-time", new Date().toLocaleTimeString());
}


// ─── Helpers ─────────────────────────────────────────────────────────────────

function showSpinner(show, msg) {
    var el = document.getElementById("spinner");
    if (!el) return;
    el.style.display = show ? "flex" : "none";
    if (msg) {
        var msgEl = document.getElementById("spinner-msg");
        if (msgEl) msgEl.textContent = msg;
    }
}

function hideResultCard() {
    var el = document.getElementById("result-card");
    if (el) el.style.display = "none";
}

function _setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? val : "—";
}

function _esc(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function _trunc(str, max) {
    if (!str) return "";
    return str.length > max ? str.slice(0, max - 3) + "..." : str;
}

function _formatBytes(bytes) {
    if (!bytes) return "—";
    if (bytes < 1024)        return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}