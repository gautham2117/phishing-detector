"use strict";

// Stores the full rule registry fetched from the API.
// Used during pass/fail comparison after a scan completes.
var _allRules = [];


// ─── On page load ─────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", function () {
    // Read the server-rendered flag from the hidden #page-data element.
    // The HTML sets data-rules-preloaded="true" or "false" via Jinja.
    // We never put {{ }} inside a script block — that causes linter errors.
    var pageData  = document.getElementById("page-data");
    var preloaded = pageData
        ? pageData.dataset.rulesPreloaded === "true"
        : false;

    // Always fetch from API so _allRules is populated for pass/fail logic.
    // If Jinja already rendered the registry rows we just update the metadata.
    loadAllRules(preloaded);
});


// ─── Load the full rule registry from the Flask proxy ────────────────────────

function loadAllRules(silent) {
    fetch("/rules/list")
        .then(function (resp) {
            if (!resp.ok) {
                throw new Error("HTTP " + resp.status);
            }
            return resp.json();
        })
        .then(function (data) {
            _allRules = data.rules || [];

            // Only re-render the registry DOM if Jinja left it empty
            if (!silent && _allRules.length > 0) {
                _renderRegistry(_allRules);
            }

            // Always update the count badge
            var countEl = document.getElementById("registry-count");
            if (countEl) {
                countEl.textContent = _allRules.length;
            }

            var timeEl = document.getElementById("update-time");
            if (timeEl) {
                timeEl.textContent = new Date().toLocaleTimeString();
            }
        })
        .catch(function (err) {
            console.warn("Could not load rule registry:", err.message);
        });
}


// ─── Render the rule registry into the DOM ────────────────────────────────────

function _renderRegistry(rules) {
    var container = document.getElementById("rules-registry");
    if (!container) return;

    // Remove the "loading..." placeholder if present
    var emptyEl = document.getElementById("registry-empty");
    if (emptyEl) {
        emptyEl.parentNode.removeChild(emptyEl);
    }

    var html = "";
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        html += '<div class="rule-registry-row" id="reg-' + _esc(r.rule_id) + '">';
        html +=   '<div style="display:flex;align-items:center;gap:10px;">';
        html +=     '<span class="sev-tag sev-' + r.severity.toLowerCase() + '">';
        html +=       _esc(r.severity);
        html +=     "</span>";
        html +=     '<span class="rule-name">' + _esc(r.name) + "</span>";
        html +=     '<span class="rule-weight-badge">+' + r.weight + " pts</span>";
        html +=   "</div>";
        html +=   '<p class="rule-desc">' + _esc(r.description) + "</p>";
        html += "</div>";
    }

    container.innerHTML = html;
}


// ─── Scan a URL against all rules ────────────────────────────────────────────

function scanUrl() {
    var urlInput = document.getElementById("url-input");
    var url      = urlInput ? urlInput.value.trim() : "";

    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }

    showSpinner(true);
    hideResultCard();

    fetch("/rules/scan/url", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ url: url })
    })
    .then(function (resp) {
        return resp.json().then(function (data) {
            return { ok: resp.ok, status: resp.status, data: data };
        });
    })
    .then(function (result) {
        showSpinner(false);
        if (!result.ok) {
            alert("Error: " + (result.data.error || "HTTP " + result.status));
            return;
        }
        renderRuleResult(result.data);
    })
    .catch(function (err) {
        showSpinner(false);
        alert("Network error: " + err.message);
    });
}


// ─── Render scan results into the result card ─────────────────────────────────

function renderRuleResult(data) {
    /*
     * data structure:
     * {
     *   status, risk_score, label, recommended_action, explanation,
     *   module_results: {
     *     rule_engine: {
     *       input, input_type,
     *       hits: [{ rule_id, name, description, severity, weight,
     *                detail, evidence, source }],
     *       rule_score, severity_counts, triggered_ids,
     *       total_rules_checked, total_rules_hit
     *     }
     *   }
     * }
     */
    var re = data.module_results && data.module_results.rule_engine
        ? data.module_results.rule_engine
        : {};

    // ── URL display ──────────────────────────────────────────────────────────
    var resInput = document.getElementById("res-input");
    if (resInput) {
        resInput.textContent = re.input || "—";
    }

    // ── Risk badge ───────────────────────────────────────────────────────────
    var label = data.label || "UNKNOWN";
    var score = typeof data.risk_score === "number" ? data.risk_score : 0;

    var badge = document.getElementById("risk-badge");
    if (badge) {
        badge.textContent = label;
        badge.className   = "risk-badge badge-" + label.toLowerCase();
    }

    // ── Score bar ────────────────────────────────────────────────────────────
    var bar = document.getElementById("score-bar");
    if (bar) {
        bar.style.width = score + "%";
        var fillClass   = "fill-safe";
        if (score >= 70) {
            fillClass = "fill-malicious";
        } else if (score >= 30) {
            fillClass = "fill-suspicious";
        }
        bar.className = "score-bar-fill " + fillClass;
    }

    var scoreNum = document.getElementById("score-num");
    if (scoreNum) {
        scoreNum.textContent = score.toFixed(1);
    }

    // ── Action pill ──────────────────────────────────────────────────────────
    var actionPill = document.getElementById("action-pill");
    if (actionPill) {
        var action = data.recommended_action || "WARN";
        actionPill.textContent = "Recommended: " + action;
        actionPill.className   = "action-pill action-" + action.toLowerCase();
    }

    // ── Severity summary pills ───────────────────────────────────────────────
    var sevRow = document.getElementById("sev-summary");
    if (sevRow) {
        var counts  = re.severity_counts || {};
        var pillDef = [
            ["CRITICAL", "sev-critical-pill"],
            ["HIGH",     "sev-high-pill"],
            ["MEDIUM",   "sev-medium-pill"],
            ["LOW",      "sev-low-pill"]
        ];

        var pillHtml = "";
        for (var p = 0; p < pillDef.length; p++) {
            var sev = pillDef[p][0];
            var cls = pillDef[p][1];
            if (counts[sev] && counts[sev] > 0) {
                pillHtml += '<span class="sev-summary-pill ' + cls + '">';
                pillHtml +=   sev + ": " + counts[sev];
                pillHtml += "</span>";
            }
        }
        sevRow.innerHTML = pillHtml;
    }

    // ── Triggered rules list ─────────────────────────────────────────────────
    var hits         = re.hits || [];
    var triggeredIds = {};

    // Build a plain object set from triggered_ids array
    var tidArr = re.triggered_ids || [];
    for (var t = 0; t < tidArr.length; t++) {
        triggeredIds[tidArr[t]] = true;
    }

    var hitCountEl = document.getElementById("hit-count");
    if (hitCountEl) {
        hitCountEl.textContent = hits.length;
    }

    var triggeredContainer = document.getElementById("triggered-rules-list");
    if (triggeredContainer) {
        if (hits.length === 0) {
            triggeredContainer.innerHTML =
                '<p class="empty-state">No rules triggered — URL appears clean.</p>';
        } else {
            var hitHtml = "";
            for (var h = 0; h < hits.length; h++) {
                var hit     = hits[h];
                var hitSev  = hit.severity ? hit.severity.toLowerCase() : "medium";

                hitHtml += '<div class="rule-hit-card sev-' + hitSev + '">';
                hitHtml +=   '<div class="rule-hit-header">';
                hitHtml +=     '<span class="sev-tag sev-' + hitSev + '">';
                hitHtml +=       _esc(hit.severity);
                hitHtml +=     "</span>";
                hitHtml +=     '<span class="rule-hit-name">' + _esc(hit.name) + "</span>";
                hitHtml +=     '<span class="rule-weight-badge">+' + hit.weight + " pts</span>";
                hitHtml +=   "</div>";
                hitHtml +=   '<p class="rule-detail">' + _esc(hit.detail) + "</p>";
                if (hit.evidence) {
                    hitHtml += '<div class="rule-evidence">' + _esc(hit.evidence) + "</div>";
                }
                hitHtml += "</div>";
            }
            triggeredContainer.innerHTML = hitHtml;
        }
    }

    // ── Passed rules list ────────────────────────────────────────────────────
    var passedContainer = document.getElementById("passed-rules-list");
    var passCountEl     = document.getElementById("pass-count");

    // Filter _allRules to those NOT in triggeredIds
    var passedRules = [];
    for (var pr = 0; pr < _allRules.length; pr++) {
        if (!triggeredIds[_allRules[pr].rule_id]) {
            passedRules.push(_allRules[pr]);
        }
    }

    if (passCountEl) {
        passCountEl.textContent = passedRules.length;
    }

    if (passedContainer) {
        if (passedRules.length === 0) {
            passedContainer.innerHTML =
                '<p class="empty-state">All rules triggered.</p>';
        } else {
            var passHtml = "";
            for (var ps = 0; ps < passedRules.length; ps++) {
                var pr2    = passedRules[ps];
                var prSev  = pr2.severity ? pr2.severity.toLowerCase() : "low";
                passHtml += '<div class="passed-rule-row">';
                passHtml +=   '<div class="pass-check">&#10003;</div>';
                passHtml +=   '<span class="sev-tag sev-' + prSev + '">';
                passHtml +=     _esc(pr2.severity);
                passHtml +=   "</span>";
                passHtml +=   "<span>" + _esc(pr2.name) + "</span>";
                passHtml += "</div>";
            }
            passedContainer.innerHTML = passHtml;
        }
    }

    // ── Highlight triggered rows in the full registry ────────────────────────
    var allRows = document.querySelectorAll(".rule-registry-row");
    for (var row = 0; row < allRows.length; row++) {
        allRows[row].classList.remove("triggered");
    }
    for (var tid in triggeredIds) {
        if (triggeredIds.hasOwnProperty(tid)) {
            var regEl = document.getElementById("reg-" + tid);
            if (regEl) {
                regEl.classList.add("triggered");
            }
        }
    }

    // ── Show result card ─────────────────────────────────────────────────────
    var resultCard = document.getElementById("result-card");
    if (resultCard) {
        resultCard.style.display = "block";
        resultCard.scrollIntoView({ behavior: "smooth" });
    }

    var timeEl = document.getElementById("update-time");
    if (timeEl) {
        timeEl.textContent = new Date().toLocaleTimeString();
    }
}


// ─── UI helpers ───────────────────────────────────────────────────────────────

function showSpinner(show) {
    var el = document.getElementById("spinner");
    if (el) {
        el.style.display = show ? "flex" : "none";
    }
}

function hideResultCard() {
    var el = document.getElementById("result-card");
    if (el) {
        el.style.display = "none";
    }
}

function _esc(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}