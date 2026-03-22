// ml_classifier.js
// Client-side logic for the ML Classifier dashboard page.
//
// CHANGES:
//   1. Old single explanation card replaced by 3-tab panel:
//        Tab 1 — Overview:        verdict narrative, score meaning, action
//        Tab 2 — Model Details:   RF vs BERT side-by-side, agree/disagree
//                                 analysis, confidence explained, trusted
//                                 domain override note
//        Tab 3 — Feature Analysis: plain-English meaning of each top
//                                 contributing feature, collapsible rows
//   2. All existing logic unchanged (weight sliders, RF bars, BERT card,
//      ensemble chart, feature contribution bars in the RF card).

"use strict";

let _ensembleChart = null;


// ─── Weight slider sync ───────────────────────────────────────────────────────

function syncWeights(changed) {
    var rfSlider   = document.getElementById("rf-weight");
    var bertSlider = document.getElementById("bert-weight");
    var rfVal      = document.getElementById("rf-weight-val");
    var bertVal    = document.getElementById("bert-weight-val");

    if (!rfSlider || !bertSlider) return;

    var rf   = parseInt(rfSlider.value, 10);
    var bert = parseInt(bertSlider.value, 10);

    if (changed === "rf") {
        bert = 100 - rf;
        bertSlider.value = bert;
    } else {
        rf = 100 - bert;
        rfSlider.value = rf;
    }

    if (rfVal)   rfVal.textContent   = (rf   / 100).toFixed(2);
    if (bertVal) bertVal.textContent = (bert / 100).toFixed(2);
}


// ─── Run classifier ───────────────────────────────────────────────────────────

async function runClassifier() {
    var urlInput = document.getElementById("url-input");
    var url      = urlInput ? urlInput.value.trim() : "";

    if (!url) { alert("Please enter a URL to classify."); return; }

    var rfWeight   = parseInt(document.getElementById("rf-weight").value,   10) / 100;
    var bertWeight = parseInt(document.getElementById("bert-weight").value, 10) / 100;

    showSpinner(true);
    hideResultCard();

    try {
        var resp = await fetch("/ml/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url, rf_weight: rfWeight, bert_weight: bertWeight })
        });

        var data = await resp.json();
        if (!resp.ok) { alert("Error: " + (data.error || resp.statusText)); return; }
        renderResult(data);

    } catch (err) {
        alert("Network error: " + err.message);
    } finally {
        showSpinner(false);
    }
}


// ─── Render result ────────────────────────────────────────────────────────────

function renderResult(data) {
    var mc   = (data.module_results && data.module_results.ml_classifier)
               ? data.module_results.ml_classifier : {};
    var rf   = mc.rf_result   || {};
    var bert = mc.bert_result || {};

    // ── URL + ensemble verdict ──────────────────────────────────────────────
    _setText("res-url", mc.url || "—");

    var label = data.label || "UNKNOWN";
    var score = data.risk_score || 0;
    var badge = document.getElementById("ensemble-badge");
    if (badge) {
        badge.textContent = label;
        badge.className   = "risk-badge badge-" + label.toLowerCase();
    }

    var bar = document.getElementById("ensemble-bar");
    if (bar) {
        bar.style.width = score + "%";
        bar.className   = "score-bar-fill " + (
            score < 30 ? "fill-safe" : score < 70 ? "fill-suspicious" : "fill-malicious"
        );
    }
    _setText("ensemble-score-num", score.toFixed(1));

    var actionPill = document.getElementById("action-pill");
    if (actionPill) {
        var action = data.recommended_action || "WARN";
        actionPill.textContent = "Recommended: " + action;
        actionPill.className   = "action-pill action-" + action.toLowerCase();
    }

    var confPct = Math.round((mc.ensemble_confidence || 0) * 100);
    _setText("confidence-pill", "Confidence: " + confPct + "%");

    // ── RF result ───────────────────────────────────────────────────────────
    var rfVerdictEl = document.getElementById("rf-verdict");
    if (rfVerdictEl) {
        rfVerdictEl.textContent = rf.available ? (rf.label || "—") : "Model not trained";
        rfVerdictEl.style.color = !rf.available ? "var(--text-muted)"
            : rf.label === "PHISHING"           ? "var(--red)" : "var(--green)";
    }

    var rfScore = Math.round((rf.score || 0) * 100);
    var rfBar   = document.getElementById("rf-bar");
    if (rfBar) {
        rfBar.style.width = rfScore + "%";
        rfBar.className   = "confidence-bar-fill " + (rfScore >= 50 ? "fill-malicious" : "fill-safe");
    }
    _setText("rf-score-label", rfScore + "% phishing probability");
    _renderFeatureContributions(rf);

    // ── BERT result ─────────────────────────────────────────────────────────
    var bertVerdictEl = document.getElementById("bert-verdict");
    if (bertVerdictEl) {
        bertVerdictEl.textContent = bert.available ? (bert.label || "—") : "Model not loaded";
        bertVerdictEl.style.color = !bert.available ? "var(--text-muted)"
            : bert.label === "PHISHING"             ? "var(--red)" : "var(--green)";
    }

    var bertScore = Math.round((bert.score || 0) * 100);
    var bertBar   = document.getElementById("bert-bar");
    if (bertBar) {
        bertBar.style.width = bertScore + "%";
        bertBar.className   = "confidence-bar-fill " + (bertScore >= 50 ? "fill-malicious" : "fill-safe");
    }
    _setText("bert-score-label", bertScore + "% phishing probability");

    var bertStatus = document.getElementById("bert-status");
    if (bertStatus) {
        bertStatus.innerHTML = bert.available
            ? '<span class="model-available">Model loaded and active</span>'
            : '<span class="model-unavailable">' + _esc(bert.note || bert.error || "Model unavailable") + '</span>';
    }

    // ── Ensemble breakdown chart ────────────────────────────────────────────
    _renderEnsembleChart(rf, bert, mc);

    // ── 3-tab explanation panel ─────────────────────────────────────────────
    renderExplanationTabs(mc, data);

    // ── Show card ───────────────────────────────────────────────────────────
    var card = document.getElementById("result-card");
    if (card) { card.style.display = "block"; card.scrollIntoView({ behavior: "smooth" }); }
    _setText("update-time", new Date().toLocaleTimeString());

    // Reset to Overview tab on each new scan
    switchExpTab("overview");
}


// ═══════════════════════════════════════════════════════════════════════════════
// 3-TAB EXPLANATION PANEL
// ═══════════════════════════════════════════════════════════════════════════════

function switchExpTab(tabName) {
    document.querySelectorAll(".exp-tab").forEach(function (btn) {
        btn.classList.toggle("active", btn.dataset.tab === tabName);
    });
    document.querySelectorAll(".exp-tab-content").forEach(function (panel) {
        panel.classList.toggle("active", panel.id === "exp-tab-" + tabName);
    });
}

function renderExplanationTabs(mc, data) {
    _renderOverviewTab(mc, data);
    _renderModelDetailsTab(mc, data);
    _renderFeatureAnalysisTab(mc);
}


// ─── Tab 1: Overview ──────────────────────────────────────────────────────────

function _renderOverviewTab(mc, data) {
    var el    = document.getElementById("exp-overview-body");
    var label = (data.label || "UNKNOWN").toLowerCase();
    var score = data.risk_score || 0;
    var rf    = mc.rf_result   || {};
    var bert  = mc.bert_result || {};

    var bannerMeta = {
        safe:       { icon: "✅", label: "Legitimate",  color: "var(--green)", cls: "banner-safe" },
        suspicious: { icon: "⚠️",  label: "Suspicious",  color: "var(--amber)", cls: "banner-suspicious" },
        malicious:  { icon: "🚨", label: "Phishing",    color: "var(--red)",   cls: "banner-malicious" },
        unknown:    { icon: "❓", label: "Unknown",     color: "var(--text-muted)", cls: "banner-unknown" },
    };
    var bm = bannerMeta[label] || bannerMeta.unknown;

    var actionMeta = {
        ALLOW:      { label: "Allow",      cls: "action-allow",      icon: "✅" },
        WARN:       { label: "Review",     cls: "action-warn",       icon: "⚠️" },
        QUARANTINE: { label: "Quarantine", cls: "action-quarantine", icon: "🚨" },
    };
    var am = actionMeta[data.recommended_action || "WARN"] || actionMeta.WARN;

    var narratives = _buildOverviewNarrative(mc, data, label, score, rf, bert);

    var isTrusted = !!(rf.note && rf.note.indexOf("Trusted") !== -1);

    el.innerHTML =
        '<div class="exp-risk-banner ' + bm.cls + '">'
        + '<div class="exp-banner-icon">' + bm.icon + '</div>'
        + '<div class="exp-banner-text">'
        +   '<h3 style="color:' + bm.color + '">' + _esc(mc.url || "URL") + ' — ' + bm.label + '</h3>'
        +   '<p>Ensemble score ' + score.toFixed(1) + '/100'
        +      ' · RF: ' + Math.round((rf.score || 0) * 100) + '%'
        +      ' · BERT: ' + Math.round((bert.score || 0) * 100) + '%'
        +      (isTrusted ? ' · 🛡 Trusted domain' : '') + '</p>'
        + '</div>'
        + '</div>'

        + '<div class="exp-section">'
        +   '<div class="exp-section-label">Analysis Narrative</div>'
        +   narratives.map(function (n) {
                return '<p class="exp-narrative-para">' + _esc(n) + '</p>';
            }).join("")
        + '</div>'

        + '<hr class="exp-divider">'

        + '<div class="exp-section">'
        +   '<div class="exp-section-label">Recommended Action</div>'
        +   '<span class="exp-action-pill ' + am.cls + '">' + am.icon + ' ' + am.label + '</span>'
        +   (label === "malicious"
            ? '<p class="exp-narrative-para" style="margin-top:10px;color:var(--red)">'
              + 'Do not visit this URL or submit any credentials. '
              + 'Quarantine any emails containing this link and report to your security team.'
              + '</p>'
            : label === "suspicious"
            ? '<p class="exp-narrative-para" style="margin-top:10px">'
              + 'The two models disagree or confidence is moderate. '
              + 'Cross-reference with URL Intelligence before clicking.'
              + '</p>'
            : "")
        + '</div>';
}

function _buildOverviewNarrative(mc, data, label, score, rf, bert) {
    var parts    = [];
    var url      = mc.url || "the URL";
    var rfScore  = Math.round((rf.score  || 0) * 100);
    var bertScore= Math.round((bert.score|| 0) * 100);
    var ensScore = Math.round((mc.ensemble_score || 0) * 100);
    var isTrusted = !!(rf.note && rf.note.indexOf("Trusted") !== -1);
    var agree     = rf.available && bert.available && rf.label === bert.label;
    var weights   = mc.weights_used || { rf: 0.45, bert: 0.55 };

    // Sentence 1 — trusted domain override
    if (isTrusted) {
        parts.push(
            "This domain is on the trusted allowlist of well-known legitimate platforms. "
            + "Both ML model scores were overridden to prevent false positives — "
            + "phishing classifiers frequently misclassify short, common URLs like "
            + "social networks and productivity platforms."
        );
        return parts;
    }

    // Sentence 1 — overall verdict
    if (label === "malicious") {
        parts.push(
            "The ensemble classified " + url + " as PHISHING with a score of "
            + ensScore + "/100. Both structural features and semantic analysis "
            + "indicate this URL is likely malicious."
        );
    } else if (label === "suspicious") {
        parts.push(
            "The ensemble returned a SUSPICIOUS score of " + ensScore + "/100 for "
            + url + ". This puts it in a grey zone — above the safe threshold "
            + "but below the high-confidence phishing threshold."
        );
    } else if (label === "safe") {
        parts.push(
            "The ensemble classified " + url + " as LEGITIMATE with a score of "
            + ensScore + "/100. No strong phishing indicators were detected by "
            + "either classifier."
        );
    } else {
        parts.push("Ensemble score for " + url + ": " + ensScore + "/100 (" + label.toUpperCase() + ").");
    }

    // Sentence 2 — model agreement
    if (rf.available && bert.available) {
        if (agree) {
            parts.push(
                "Both the Random Forest (RF: " + rfScore + "%) and BERT (BERT: " + bertScore + "%) "
                + "classifiers agree — " + (rf.label === "PHISHING" ? "both flag this as phishing." : "both classify this as legitimate.")
                + " Agreement between two independent models substantially increases confidence in the result."
            );
        } else {
            parts.push(
                "The two classifiers disagree: Random Forest says " + rf.label
                + " (" + rfScore + "%) while BERT says " + bert.label
                + " (" + bertScore + "%). The ensemble resolves this using weighted averaging — "
                + "BERT carries " + Math.round(weights.bert * 100) + "% weight and RF carries "
                + Math.round(weights.rf * 100) + "%, so "
                + (weights.bert > weights.rf ? "BERT's verdict has more influence." : "RF's verdict has more influence.")
            );
        }
    } else if (!rf.available) {
        parts.push(
            "The Random Forest model is not yet trained — classification relies on BERT alone. "
            + "Train the RF model for a more reliable ensemble result: "
            + "python -m backend.ml.train_url_classifier"
        );
    }

    // Sentence 3 — confidence interpretation
    var confPct = Math.round((mc.ensemble_confidence || 0) * 100);
    if (confPct >= 70) {
        parts.push(
            "Confidence is HIGH (" + confPct + "%) — the ensemble score is far from the "
            + "0.5 decision boundary, indicating a strong and reliable prediction."
        );
    } else if (confPct >= 35) {
        parts.push(
            "Confidence is MODERATE (" + confPct + "%) — the score is reasonably far from "
            + "the 0.5 decision boundary but not conclusive. Check the Feature Analysis tab "
            + "for the specific signals driving this result."
        );
    } else {
        parts.push(
            "Confidence is LOW (" + confPct + "%) — the ensemble score is close to the "
            + "0.5 decision boundary. This URL is genuinely ambiguous. "
            + "Use URL Intelligence for WHOIS, SSL, and redirect chain verification."
        );
    }

    return parts;
}


// ─── Tab 2: Model Details ─────────────────────────────────────────────────────

function _renderModelDetailsTab(mc, data) {
    var el    = document.getElementById("exp-modeldetails-body");
    var rf    = mc.rf_result   || {};
    var bert  = mc.bert_result || {};
    var weights = mc.weights_used || { rf: 0.45, bert: 0.55 };

    var rfScore   = Math.round((rf.score   || 0) * 100);
    var bertScore = Math.round((bert.score || 0) * 100);
    var ensScore  = Math.round((mc.ensemble_score || 0) * 100);
    var confPct   = Math.round((mc.ensemble_confidence || 0) * 100);

    var isTrusted  = !!(rf.note && rf.note.indexOf("Trusted") !== -1);
    var rfLabel    = rf.available   ? (rf.label   || "UNKNOWN") : "UNAVAILABLE";
    var bertLabel  = bert.available ? (bert.label || "UNKNOWN") : "UNAVAILABLE";
    var agree      = rf.available && bert.available && rf.label === bert.label;

    // Card border class
    var rfCardCls   = rfLabel   === "PHISHING"    ? "card-phishing"
                    : rfLabel   === "LEGITIMATE"  ? "card-legit"
                    : isTrusted                   ? "card-trusted"
                    : "card-unknown";
    var bertCardCls = bertLabel === "PHISHING"    ? "card-phishing"
                    : bertLabel === "LEGITIMATE"  ? "card-legit"
                    : "card-unknown";

    var rfColor   = rfLabel   === "PHISHING" ? "var(--red)"   : rfLabel   === "LEGITIMATE" ? "var(--green)" : "var(--text-muted)";
    var bertColor = bertLabel === "PHISHING" ? "var(--red)"   : bertLabel === "LEGITIMATE" ? "var(--green)" : "var(--text-muted)";

    // Agreement / disagreement note
    var noteText = "";
    var noteCls  = "";
    if (isTrusted) {
        noteText = "Trusted domain override: both model scores were set to 0.05 (LEGITIMATE) "
                 + "regardless of raw model output. This prevents known false positives on "
                 + "well-known platforms like LinkedIn, Google, and GitHub.";
        noteCls = "note-trusted";
    } else if (!rf.available && !bert.available) {
        noteText = "Both models are unavailable. Train the RF model and ensure BERT is loaded.";
        noteCls  = "";
    } else if (!rf.available) {
        noteText = "Random Forest is not trained — only BERT contributes to the ensemble. "
                 + "The result may be less reliable. Run: python -m backend.ml.train_url_classifier";
        noteCls  = "note-disagree";
    } else if (!bert.available) {
        noteText = "BERT model is not loaded — only RF contributes to the ensemble. "
                 + "The result relies solely on structural URL features.";
        noteCls  = "note-disagree";
    } else if (agree) {
        noteText = "Both classifiers agree (" + rfLabel + "). When two independent models "
                 + "reach the same conclusion through different methods (structural features vs "
                 + "semantic understanding), the prediction is substantially more reliable than "
                 + "either model alone.";
        noteCls = "note-agree";
    } else {
        noteText = "The classifiers disagree. Random Forest uses structural URL features "
                 + "(length, entropy, character ratios, TLD risk) — a deterministic, "
                 + "interpretable method. BERT uses deep learning on the raw URL string "
                 + "to understand semantic patterns. Disagreement often occurs on ambiguous "
                 + "URLs that have clean structure but suspicious semantics, or vice versa. "
                 + "The ensemble resolves this by weighted averaging.";
        noteCls = "note-disagree";
    }

    // Confidence classification
    var confClass = confPct >= 70 ? "chip-high" : confPct >= 35 ? "chip-medium" : "chip-low";
    var confLabel = confPct >= 70 ? "High confidence" : confPct >= 35 ? "Moderate confidence" : "Low confidence";

    var confExplanation = confPct >= 70
        ? "The ensemble score (" + ensScore + "%) is far from the 50% decision boundary. "
          + "The model is certain in its classification."
        : confPct >= 35
        ? "The ensemble score (" + ensScore + "%) is a reasonable distance from 50%. "
          + "The result is fairly reliable but not conclusive."
        : "The ensemble score (" + ensScore + "%) is close to the 50% boundary. "
          + "This URL is genuinely ambiguous — small changes in URL structure could flip the verdict. "
          + "Manual verification is strongly recommended.";

    // How ensemble was computed
    var ensembleFormula = "";
    if (rf.available && bert.available) {
        var rfW   = Math.round(weights.rf   * 100);
        var bertW = Math.round(weights.bert * 100);
        ensembleFormula =
            '<div class="exp-section">'
            + '<div class="exp-section-label">Ensemble Calculation</div>'
            + '<div style="background:var(--bg3);border-radius:var(--radius);padding:12px 16px;'
            +      'font-family:monospace;font-size:13px;border:1px solid var(--border);">'
            +   'score = (' + rfW + '% × ' + rfScore + '%) + (' + bertW + '% × ' + bertScore + '%)<br>'
            +   '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= ' + Math.round(rfW * rfScore / 100) + ' + '
            +                                             Math.round(bertW * bertScore / 100) + '<br>'
            +   '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= <strong>' + ensScore + '%</strong>'
            +   (isTrusted ? ' → overridden to <strong>5%</strong> (trusted domain)' : '')
            + '</div>'
            + '</div>';
    }

    el.innerHTML =
        // Side-by-side model cards
        '<div class="model-compare-grid">'

        // RF card
        + '<div class="model-compare-card ' + rfCardCls + '">'
        +   '<div class="model-compare-name">Random Forest</div>'
        +   '<div class="model-compare-verdict" style="color:' + rfColor + '">'
        +     _esc(rfLabel) + '</div>'
        +   '<div class="model-compare-score">'
        +     (rf.available
               ? rfScore + '% phishing probability · weight ' + Math.round(weights.rf * 100) + '%'
               : 'Not trained — run train_url_classifier.py')
        +   '</div>'
        +   (rf.available
             ? '<div class="model-mini-bar-track"><div class="model-mini-bar-fill" style="width:'
               + rfScore + '%;background:' + (rfScore >= 50 ? 'var(--red)' : 'var(--green)') + '"></div></div>'
             : '')
        +   (rf.note
             ? '<p style="font-size:11px;color:var(--blue);margin-top:6px">ℹ ' + _esc(rf.note) + '</p>'
             : '')
        +   '<p style="font-size:11px;color:var(--text-muted);margin-top:8px;line-height:1.5">'
        +     'Analyses 24 structural URL features (length, entropy, digit ratios, TLD, etc.). '
        +     'Fast, interpretable, and consistent.'
        +   '</p>'
        + '</div>'

        // BERT card
        + '<div class="model-compare-card ' + bertCardCls + '">'
        +   '<div class="model-compare-name">BERT (ealvaradob/bert-finetuned-phishing)</div>'
        +   '<div class="model-compare-verdict" style="color:' + bertColor + '">'
        +     _esc(bertLabel) + '</div>'
        +   '<div class="model-compare-score">'
        +     (bert.available
               ? bertScore + '% phishing probability · weight ' + Math.round(weights.bert * 100) + '%'
               : 'Not loaded')
        +   '</div>'
        +   (bert.available
             ? '<div class="model-mini-bar-track"><div class="model-mini-bar-fill" style="width:'
               + bertScore + '%;background:' + (bertScore >= 50 ? 'var(--red)' : 'var(--green)') + '"></div></div>'
             : '')
        +   (bert.note
             ? '<p style="font-size:11px;color:var(--blue);margin-top:6px">ℹ ' + _esc(bert.note) + '</p>'
             : '')
        +   '<p style="font-size:11px;color:var(--text-muted);margin-top:8px;line-height:1.5">'
        +     'Fine-tuned transformer that understands URL semantics. '
        +     'Trained on phishing URL datasets. Slower but captures context.'
        +   '</p>'
        + '</div>'
        + '</div>'

        // Agreement / disagreement note
        + '<div class="model-note-box ' + noteCls + '">' + _esc(noteText) + '</div>'

        // Confidence detail
        + '<div class="exp-section" style="margin-top:16px">'
        +   '<div class="exp-section-label">Ensemble Confidence</div>'
        +   '<div class="conf-detail-row">'
        +     '<span class="conf-detail-chip ' + confClass + '">' + confLabel + ' (' + confPct + '%)</span>'
        +   '</div>'
        +   '<p class="exp-narrative-para" style="margin-top:10px">' + _esc(confExplanation) + '</p>'
        + '</div>'

        // Ensemble formula
        + ensembleFormula;
}


// ─── Tab 3: Feature Analysis ──────────────────────────────────────────────────

function _renderFeatureAnalysisTab(mc) {
    var el     = document.getElementById("exp-featureanalysis-body");
    var rf     = mc.rf_result || {};
    var badge  = document.getElementById("exp-badge-features");

    if (!rf.available) {
        el.innerHTML =
            '<div class="feat-no-model">'
            + '<div style="font-size:32px;margin-bottom:10px">🌲</div>'
            + '<p>Random Forest model is not trained.<br>'
            + '<code style="font-size:12px">python -m backend.ml.train_url_classifier</code></p>'
            + '</div>';
        if (badge) badge.textContent = "";
        return;
    }

    var contribs = rf.feature_contributions || [];
    var top10    = contribs.slice(0, 10);

    if (badge) badge.textContent = top10.length || "";

    if (!top10.length) {
        el.innerHTML = '<p class="exp-placeholder">No feature contributions available for this prediction.</p>';
        return;
    }

    var html = '<div class="exp-section">'
             + '<div class="exp-section-label">Top ' + top10.length + ' features by contribution — click to expand explanation</div>'
             + '</div>';

    top10.forEach(function (c, idx) {
        var isRisk    = c.direction === "increases_risk";
        var dirCls    = isRisk ? "pill-risk" : "pill-safe";
        var dirLabel  = isRisk ? "↑ risk" : "↓ risk";
        var contribStr= (isRisk ? "+" : "−") + Math.abs(c.contribution).toFixed(4);
        var valDisplay= _formatFeatureValue(c.feature, c.value);
        var expl      = _featurePlainEnglish(c.feature, c.value, c.direction, c.contribution);

        html += '<div class="feat-item">'
              + '<div class="feat-item-header" onclick="toggleFeatItem(' + idx + ')">'
              +   '<span class="feat-name-mono">' + _esc(c.feature) + '</span>'
              +   '<span class="feat-val-tag">' + _esc(valDisplay) + '</span>'
              +   '<span class="feat-dir-pill ' + dirCls + '">' + dirLabel + '</span>'
              +   '<span class="feat-contrib" style="color:' + (isRisk ? 'var(--red)' : 'var(--green)') + '">'
              +     _esc(contribStr)
              +   '</span>'
              +   '<span class="feat-chevron" id="feat-chv-' + idx + '">▶</span>'
              + '</div>'
              + '<div class="feat-item-body" id="feat-body-' + idx + '">'
              +   _esc(expl)
              + '</div>'
              + '</div>';
    });

    html += '<p style="font-size:10px;color:var(--text-muted);margin-top:12px;line-height:1.5">'
          + 'Contribution = change in phishing probability when this feature is replaced '
          + 'with a neutral baseline value. Positive = pushes toward phishing. '
          + 'Negative = pushes toward legitimate.'
          + '</p>';

    el.innerHTML = html;
}

function toggleFeatItem(idx) {
    var body    = document.getElementById("feat-body-" + idx);
    var chevron = document.getElementById("feat-chv-"  + idx);
    if (!body) return;
    var isOpen = body.classList.contains("open");
    body.classList.toggle("open", !isOpen);
    if (chevron) chevron.classList.toggle("open", !isOpen);
}

// Plain-English explanation for each feature in context
function _featurePlainEnglish(feature, value, direction, contribution) {
    var isRisk = direction === "increases_risk";
    var val    = parseFloat(value) || 0;

    var explanations = {
        "url_length": isRisk
            ? "This URL is " + Math.round(val) + " characters long. Excessively long URLs are used "
              + "to hide the real destination domain — phishing URLs often embed brand keywords "
              + "or fake paths to appear legitimate while burying the actual domain deep in the string."
            : "At " + Math.round(val) + " characters, this URL is short and typical of a legitimate "
              + "link. Phishing URLs tend to be substantially longer to obscure the real domain.",

        "domain_length": isRisk
            ? "The domain is " + Math.round(val) + " characters long. Longer domains are sometimes "
              + "used to embed brand keywords (e.g. paypal-secure-login.com) to appear legitimate "
              + "while the real apex domain is something else."
            : "At " + Math.round(val) + " characters, the domain length is typical of a legitimate site.",

        "path_length": isRisk
            ? "The URL path is " + Math.round(val) + " characters long. Phishing pages often use "
              + "long, complex paths to track victims or disguise the page as a legitimate resource."
            : "Short path length — typical of a clean, straightforward URL.",

        "num_dots": isRisk
            ? "The URL contains " + Math.round(val) + " dots. Multiple dots often indicate deep "
              + "subdomain nesting — e.g. paypal.secure.account.evil.com — where the real domain "
              + "is the last segment before the TLD."
            : "Few dots in the URL — typical subdomain structure.",

        "num_hyphens": isRisk
            ? Math.round(val) + " hyphens detected. Hyphenated domains like paypal-secure-login.com "
              + "are a common phishing technique — attackers add keywords around hyphens to make "
              + "the domain look related to a trusted brand."
            : "Low hyphen count — no hyphenation-based spoofing detected.",

        "num_underscores": isRisk
            ? Math.round(val) + " underscores in the URL. Underscores in domain names are unusual "
              + "and sometimes used to evade simple pattern-matching filters."
            : "No unusual underscores detected.",

        "num_slashes": isRisk
            ? Math.round(val) + " slashes in the URL. Excessive slashes can indicate a deep, "
              + "confusing path structure used to bury the real destination."
            : "Normal slash count for a URL of this type.",

        "num_at_symbols": isRisk
            ? Math.round(val) + " @ symbol(s) detected. The @ character in a URL causes browsers "
              + "to treat everything before it as credentials and everything after as the actual host. "
              + "e.g. https://paypal.com@evil.com/ navigates to evil.com — a classic deception technique."
            : "No @ symbols in the URL — no credential injection risk.",

        "num_question_marks": isRisk
            ? "Multiple query strings detected. Complex query parameters can hide redirect destinations "
              + "or tracking payloads."
            : "Normal query string usage.",

        "digit_ratio": isRisk
            ? (val * 100).toFixed(1) + "% of the URL consists of digits. A high proportion of numbers "
              + "suggests IP-based obfuscation (e.g. http://192.168.1.1/login) or algorithmically "
              + "generated domains that mix letters and digits to appear random."
            : "Low digit ratio — URL character composition looks natural.",

        "special_char_ratio": isRisk
            ? (val * 100).toFixed(1) + "% special characters. Phishing URLs often include encoded "
              + "characters (%, =, &) to obfuscate the destination or embed redirect payloads."
            : "Low special character ratio — no unusual obfuscation detected.",

        "subdomain_depth": isRisk
            ? Math.round(val) + " subdomain level(s). Deep subdomain nesting is a classic phishing "
              + "technique. e.g. accounts.google.com.login.evil.xyz — users often read only the "
              + "first part and assume they are on Google's site."
            : "Shallow subdomain structure — no deep nesting detected.",

        "has_ip_address": isRisk
            ? "The URL uses a raw IP address instead of a domain name. Legitimate services "
              + "never ask users to visit a bare IP. This is a strong phishing signal — attackers "
              + "use IPs to avoid domain-based blocklists."
            : "No raw IP address — URL uses a proper domain name.",

        "has_https": !isRisk
            ? "The URL uses HTTPS. While not a guarantee of legitimacy (phishers also get free SSL "
              + "certificates), HTTPS is expected for any legitimate site."
            : "The URL does not use HTTPS — it is transmitting over plain HTTP, which is a risk signal.",

        "has_http": isRisk
            ? "The URL uses plain HTTP without encryption. Any credentials entered on this page "
              + "are transmitted in plain text."
            : "HTTPS is used — no plain-text transmission risk.",

        "is_shortener": isRisk
            ? "The URL uses a link shortener service. Shorteners hide the real destination — "
              + "attackers use them to disguise phishing links as innocent-looking short URLs."
            : "No URL shortener detected — destination is transparent.",

        "has_suspicious_tld": isRisk
            ? "The top-level domain (TLD) is on the suspicious list (.xyz, .tk, .top, etc.). "
              + "These TLDs are disproportionately used for phishing because they are free or very "
              + "cheap to register, making them easy throwaway domains."
            : "TLD is not on the suspicious list — no cheap-registrar flag.",

        "has_at_in_domain": isRisk
            ? "The @ character appears in the domain portion of the URL. This is always suspicious — "
              + "browsers treat it as a credential separator, meaning the displayed host may not be "
              + "the actual destination."
            : "No @ in domain portion — no credential separator trick.",

        "has_double_slash": isRisk
            ? "A double slash (//) appears in the URL path. This can confuse URL parsers and "
              + "is sometimes used to obscure redirect destinations."
            : "No double slash in the path.",

        "domain_entropy": isRisk
            ? "Domain entropy is " + val.toFixed(2) + " bits. High entropy means the domain name "
              + "looks random — typical of Domain Generation Algorithms (DGAs) used by phishing C2 "
              + "infrastructure. Legitimate brands have low-entropy, memorable names."
            : "Domain entropy is " + val.toFixed(2) + " bits — the domain name looks natural and "
              + "human-readable, not algorithmically generated.",

        "path_entropy": isRisk
            ? "Path entropy is " + val.toFixed(2) + " bits — the URL path contains random-looking "
              + "characters, possibly an encoded token or obfuscated redirect target."
            : "Path entropy is " + val.toFixed(2) + " bits — the path looks clean and readable.",

        "num_digits": isRisk
            ? Math.round(val) + " digits in the URL body. Many digits suggest IP obfuscation "
              + "or an algorithmically generated domain."
            : "Low digit count in the URL — no numeric obfuscation detected.",

        "num_equals": isRisk
            ? Math.round(val) + " equals sign(s) — multiple = signs often indicate complex query "
              + "parameters that can hide redirect destinations or session tokens."
            : "Normal equals sign usage.",

        "num_ampersands": isRisk
            ? Math.round(val) + " ampersand(s) — many & characters indicate a complex query string "
              + "which can be used to chain open redirects or embed phishing payloads."
            : "Low ampersand count — simple query string.",
    };

    return explanations[feature]
        || (isRisk
            ? feature + " = " + value + " — this value increases the predicted phishing probability."
            : feature + " = " + value + " — this value decreases the predicted phishing probability.");
}


// ─── Feature contribution bars (in RF card) ───────────────────────────────────

function _renderFeatureContributions(rf) {
    var container = document.getElementById("rf-features");
    if (!container) return;

    if (!rf.available) {
        container.innerHTML =
            '<p class="model-unavailable">Train the model first: '
            + '<code>python -m backend.ml.train_url_classifier</code></p>';
        return;
    }

    var contribs = rf.feature_contributions;
    if (!contribs || !contribs.length) {
        container.innerHTML = '<p class="empty-state" style="font-size:12px">Feature contributions not available.</p>';
        return;
    }

    var top10  = contribs.slice(0, 10);
    var maxAbs = top10.reduce(function (m, c) { return Math.max(m, c.abs_contribution); }, 0.0001);

    var html = '<div style="display:flex;align-items:center;justify-content:space-between;'
             + 'margin-bottom:10px;flex-wrap:wrap;gap:6px;">'
             + '<span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;">'
             + 'Top 10 features by contribution</span>'
             + '<span style="display:flex;gap:10px;font-size:11px;">'
             + '<span style="color:var(--red)">▶ increases risk</span>'
             + '<span style="color:var(--green)">◀ decreases risk</span>'
             + '</span></div>';

    for (var i = 0; i < top10.length; i++) {
        var c         = top10[i];
        var isRisk    = c.direction === "increases_risk";
        var barColor  = isRisk ? "var(--red)" : "var(--green)";
        var barPct    = Math.round((c.abs_contribution / maxAbs) * 100);
        var valDisplay= _formatFeatureValue(c.feature, c.value);
        var contribStr= (isRisk ? "+" : "−") + Math.abs(c.contribution).toFixed(4);

        html += '<div class="feature-row" style="margin-bottom:8px;">'
              + '<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:3px;">'
              +   '<span class="feature-name" style="font-size:12px;font-weight:500;color:var(--text);font-family:monospace;">'
              +     _esc(c.feature) + '</span>'
              +   '<span style="font-size:11px;color:var(--text-muted);">' + _esc(valDisplay)
              +     ' <span style="color:' + barColor + ';font-weight:600;">' + _esc(contribStr) + '</span>'
              +   '</span>'
              + '</div>'
              + '<div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;">'
              +   '<div style="height:100%;width:' + barPct + '%;background:' + barColor + ';border-radius:3px;transition:width .4s ease;"></div>'
              + '</div>'
              + '</div>';
    }

    html += '<p style="font-size:10px;color:var(--text-muted);margin-top:10px;line-height:1.5;">'
          + 'Contributions computed by single-feature masking — each feature is temporarily replaced '
          + 'with a neutral baseline and the change in phishing probability is measured.</p>';

    container.innerHTML = html;
}


// ─── Feature value formatter ──────────────────────────────────────────────────

function _formatFeatureValue(featureName, value) {
    var boolFeatures = [
        "has_ip_address","has_https","has_http",
        "is_shortener","has_suspicious_tld","has_at_in_domain","has_double_slash"
    ];
    if (boolFeatures.indexOf(featureName) !== -1) return parseFloat(value) >= 0.5 ? "Yes" : "No";
    if (["digit_ratio","special_char_ratio"].indexOf(featureName) !== -1)
        return (parseFloat(value) * 100).toFixed(1) + "%";
    if (featureName.indexOf("entropy") !== -1) return parseFloat(value).toFixed(2) + " bits";
    if (featureName.indexOf("num_") === 0 || featureName.indexOf("length") !== -1 || featureName === "subdomain_depth")
        return Math.round(parseFloat(value)).toString();
    return parseFloat(value).toFixed(3);
}


// ─── Ensemble breakdown bar chart ─────────────────────────────────────────────

function _renderEnsembleChart(rf, bert, mc) {
    var ctx = document.getElementById("ensemble-chart");
    if (!ctx) return;

    var rfScore   = Math.round((rf.score   || 0) * 100);
    var bertScore = Math.round((bert.score || 0) * 100);
    var ensScore  = Math.round((mc.ensemble_score || 0) * 100);
    var weights   = mc.weights_used || { rf: 0.45, bert: 0.55 };
    var rfW       = Math.round(weights.rf   * 100);
    var bertW     = Math.round(weights.bert * 100);

    var labels = [
        "Random Forest (" + rfW   + "% weight)",
        "BERT ("          + bertW + "% weight)",
        "Ensemble (final)"
    ];
    var scores = [rfScore, bertScore, ensScore];
    var colors = scores.map(function (s) {
        return s >= 70 ? "rgba(248,81,73,0.8)"
             : s >= 30 ? "rgba(210,153,34,0.8)" : "rgba(63,185,80,0.8)";
    });

    if (_ensembleChart) { _ensembleChart.destroy(); _ensembleChart = null; }

    _ensembleChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{ data: scores, backgroundColor: colors, borderRadius: 4, borderWidth: 0 }]
        },
        options: {
            indexAxis: "y",
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: { label: function (ctx) { return " Phishing probability: " + ctx.parsed.x + "%"; } },
                    backgroundColor: "rgba(13,13,20,0.95)",
                    titleColor: "#e8e4ff", bodyColor: "#7a75a8",
                    borderColor: "rgba(124,106,247,0.3)", borderWidth: 1, padding: 10,
                }
            },
            scales: {
                x: {
                    min: 0, max: 100,
                    grid:  { color: "rgba(255,255,255,0.04)" },
                    ticks: { color: "#8b949e", callback: function (v) { return v + "%"; } }
                },
                y: { grid: { display: false }, ticks: { color: "#8b949e", font: { size: 12 } } }
            }
        }
    });
}


// ─── Helpers ─────────────────────────────────────────────────────────────────

function showSpinner(show) {
    var el = document.getElementById("spinner");
    if (el) el.style.display = show ? "flex" : "none";
}

function hideResultCard() {
    var el = document.getElementById("result-card");
    if (el) el.style.display = "none";
}

function _setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
}

function _esc(str) {
    if (!str && str !== 0) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}