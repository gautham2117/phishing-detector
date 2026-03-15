// ml_classifier.js
// Client-side logic for the ML Classifier dashboard page.
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

    // Keep weights summing to 100
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

    if (!url) {
        alert("Please enter a URL to classify.");
        return;
    }

    var rfWeight   = parseInt(
        document.getElementById("rf-weight").value, 10) / 100;
    var bertWeight = parseInt(
        document.getElementById("bert-weight").value, 10) / 100;

    showSpinner(true);
    hideResultCard();

    try {
        var resp = await fetch("/ml/scan", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({
                url:         url,
                rf_weight:   rfWeight,
                bert_weight: bertWeight
            })
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
    var mc = (data.module_results && data.module_results.ml_classifier)
        ? data.module_results.ml_classifier
        : {};

    var rf   = mc.rf_result   || {};
    var bert = mc.bert_result || {};

    // ── URL + ensemble verdict ──
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
            score < 30 ? "fill-safe"
            : score < 70 ? "fill-suspicious"
            : "fill-malicious"
        );
    }
    _setText("ensemble-score-num", score.toFixed(1));

    var actionPill = document.getElementById("action-pill");
    if (actionPill) {
        var action = data.recommended_action || "WARN";
        actionPill.textContent = "Recommended: " + action;
        actionPill.className   = "action-pill action-" + action.toLowerCase();
    }

    var confPct  = Math.round((mc.ensemble_confidence || 0) * 100);
    _setText("confidence-pill", "Confidence: " + confPct + "%");

    // ── RF result ──
    var rfVerdictEl = document.getElementById("rf-verdict");
    if (rfVerdictEl) {
        rfVerdictEl.textContent = rf.available
            ? (rf.label || "—")
            : "Model not trained";
        rfVerdictEl.style.color = !rf.available   ? "var(--text-muted)"
            : rf.label === "PHISHING"              ? "var(--red)"
            : "var(--green)";
    }

    var rfScore = Math.round((rf.score || 0) * 100);
    var rfBar   = document.getElementById("rf-bar");
    if (rfBar) {
        rfBar.style.width = rfScore + "%";
        rfBar.className   = "confidence-bar-fill " + (
            rfScore >= 50 ? "fill-malicious" : "fill-safe"
        );
    }
    _setText("rf-score-label", rfScore + "% phishing probability");

    // RF features placeholder (actual importances need model introspection)
    var rfFeatures = document.getElementById("rf-features");
    if (rfFeatures && rf.available) {
        var featureData = [
            { name: "url_length",       val: 0.18 },
            { name: "domain_entropy",   val: 0.15 },
            { name: "digit_ratio",      val: 0.13 },
            { name: "subdomain_depth",  val: 0.12 },
            { name: "special_char_ratio",val:0.10 },
            { name: "has_suspicious_tld",val:0.09 },
            { name: "num_dots",         val: 0.08 },
            { name: "path_length",      val: 0.07 }
        ];
        rfFeatures.innerHTML = featureData.map(function (f) {
            var pct = Math.round(f.val * 100);
            return '<div class="feature-row">'
                + '<span class="feature-name">' + f.name + '</span>'
                + '<div class="feature-bar-track">'
                + '<div class="feature-bar-fill" style="width:' + pct + '%"></div>'
                + '</div>'
                + '<span class="feature-val">' + pct + '%</span>'
                + '</div>';
        }).join("");
    } else if (rfFeatures) {
        rfFeatures.innerHTML =
            '<p class="model-unavailable">'
            + 'Train the model first: '
            + '<code>python -m backend.ml.train_url_classifier</code>'
            + '</p>';
    }

    // ── BERT result ──
    var bertVerdictEl = document.getElementById("bert-verdict");
    if (bertVerdictEl) {
        bertVerdictEl.textContent = bert.available
            ? (bert.label || "—")
            : "Model not loaded";
        bertVerdictEl.style.color = !bert.available  ? "var(--text-muted)"
            : bert.label === "PHISHING"              ? "var(--red)"
            : "var(--green)";
    }

    var bertScore = Math.round((bert.score || 0) * 100);
    var bertBar   = document.getElementById("bert-bar");
    if (bertBar) {
        bertBar.style.width = bertScore + "%";
        bertBar.className   = "confidence-bar-fill " + (
            bertScore >= 50 ? "fill-malicious" : "fill-safe"
        );
    }
    _setText("bert-score-label", bertScore + "% phishing probability");

    var bertStatus = document.getElementById("bert-status");
    if (bertStatus) {
        bertStatus.innerHTML = bert.available
            ? '<span class="model-available">Model loaded and active</span>'
            : '<span class="model-unavailable">'
              + (bert.note || bert.error || "Model unavailable")
              + '</span>';
    }

    // ── Ensemble breakdown chart ──
    _renderEnsembleChart(rf, bert, mc);

    // ── Explanation ──
    _setText("explanation-text", data.explanation || "—");

    // ── Show result card ──
    var card = document.getElementById("result-card");
    if (card) {
        card.style.display = "block";
        card.scrollIntoView({ behavior: "smooth" });
    }

    _setText("update-time", new Date().toLocaleTimeString());
}


// ─── Ensemble breakdown bar chart ─────────────────────────────────────────────

function _renderEnsembleChart(rf, bert, mc) {
    var ctx = document.getElementById("ensemble-chart");
    if (!ctx) return;

    var rfScore   = Math.round((rf.score   || 0) * 100);
    var bertScore = Math.round((bert.score || 0) * 100);
    var ensScore  = Math.round((mc.ensemble_score || 0) * 100);

    var weights = mc.weights_used || { rf: 0.45, bert: 0.55 };
    var rfW     = Math.round(weights.rf   * 100);
    var bertW   = Math.round(weights.bert * 100);

    var labels = [
        "Random Forest (" + rfW + "% weight)",
        "BERT (" + bertW + "% weight)",
        "Ensemble (final)"
    ];
    var scores = [rfScore, bertScore, ensScore];
    var colors = scores.map(function (s) {
        return s >= 70 ? "rgba(248,81,73,0.8)"
             : s >= 30 ? "rgba(210,153,34,0.8)"
             : "rgba(63,185,80,0.8)";
    });

    if (_ensembleChart) {
        _ensembleChart.destroy();
        _ensembleChart = null;
    }

    _ensembleChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                data:            scores,
                backgroundColor: colors,
                borderRadius:    4,
                borderWidth:     0
            }]
        },
        options: {
            indexAxis: "y",
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function (ctx) {
                            return " Phishing probability: " + ctx.parsed.x + "%";
                        }
                    }
                }
            },
            scales: {
                x: {
                    min: 0,
                    max: 100,
                    grid:  { color: "rgba(255,255,255,0.04)" },
                    ticks: {
                        color: "#8b949e",
                        callback: function (v) { return v + "%"; }
                    }
                },
                y: {
                    grid:  { display: false },
                    ticks: { color: "#8b949e", font: { size: 12 } }
                }
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