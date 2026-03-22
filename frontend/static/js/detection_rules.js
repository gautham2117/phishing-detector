"use strict";

// Stores the full rule registry fetched from the API.
// Used during pass/fail comparison after a scan completes.
var _allRules = [];

// Holds the Chart.js instance so we can destroy + recreate on refresh
var _analyticsChart = null;


// ─── On page load ─────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", function () {
    var pageData  = document.getElementById("page-data");
    var preloaded = pageData
        ? pageData.dataset.rulesPreloaded === "true"
        : false;

    // Load rule registry (populates _allRules for pass/fail logic)
    loadAllRules(preloaded);

    // Load analytics chart immediately on page load
    loadAnalytics(false);
});


// ─── Load the full rule registry from the Flask proxy ────────────────────────

function loadAllRules(silent) {
    fetch("/rules/list")
        .then(function (resp) {
            if (!resp.ok) throw new Error("HTTP " + resp.status);
            return resp.json();
        })
        .then(function (data) {
            _allRules = data.rules || [];

            if (!silent && _allRules.length > 0) {
                _renderRegistry(_allRules);
            }

            var countEl = document.getElementById("registry-count");
            if (countEl) countEl.textContent = _allRules.length;

            var timeEl = document.getElementById("update-time");
            if (timeEl) timeEl.textContent = new Date().toLocaleTimeString();
        })
        .catch(function (err) {
            console.warn("Could not load rule registry:", err.message);
        });
}


// ─── Render the rule registry into the DOM ────────────────────────────────────

function _renderRegistry(rules) {
    var container = document.getElementById("rules-registry");
    if (!container) return;

    var emptyEl = document.getElementById("registry-empty");
    if (emptyEl) emptyEl.parentNode.removeChild(emptyEl);

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


// ─── Rule Analytics ───────────────────────────────────────────────────────────
//
// Fetches GET /rules/analytics and renders:
//   1. A Chart.js horizontal bar chart — top 10 most-hit rules
//   2. A full frequency table beneath the chart
//
// forceRefresh=true busts the 60s server-side cache by appending ?bust=<ts>

function loadAnalytics(forceRefresh) {
    var loadingEl   = document.getElementById("analytics-loading");
    var emptyEl     = document.getElementById("analytics-empty");
    var chartWrap   = document.getElementById("analytics-chart-wrap");
    var tableWrap   = document.getElementById("analytics-table-wrap");
    var urlCountEl  = document.getElementById("analytics-url-count");
    var timeEl      = document.getElementById("analytics-time");

    // Show loading state
    if (loadingEl)  loadingEl.style.display  = "block";
    if (emptyEl)    emptyEl.style.display    = "none";
    if (chartWrap)  chartWrap.style.display  = "none";
    if (tableWrap)  tableWrap.style.display  = "none";

    var url = "/rules/analytics";
    if (forceRefresh) url += "?bust=" + Date.now();

    fetch(url)
        .then(function (resp) {
            if (!resp.ok) throw new Error("HTTP " + resp.status);
            return resp.json();
        })
        .then(function (data) {
            if (loadingEl) loadingEl.style.display = "none";

            var freq  = data.rule_frequency       || [];
            var total = data.total_urls_analyzed  || 0;
            var ts    = data.analyzed_at          || "";

            // Update metadata labels
            if (urlCountEl) urlCountEl.textContent = total;
            if (timeEl && ts) {
                var d = new Date(ts);
                timeEl.textContent = "Analyzed at " + d.toLocaleTimeString();
            }

            if (!freq.length || total === 0) {
                if (emptyEl) emptyEl.style.display = "block";
                return;
            }

            // Show chart + table
            if (chartWrap) chartWrap.style.display = "block";
            if (tableWrap) tableWrap.style.display = "block";

            _renderAnalyticsChart(freq);
            _renderAnalyticsTable(freq, total);
        })
        .catch(function (err) {
            if (loadingEl) loadingEl.style.display = "none";
            console.warn("Analytics load failed:", err.message);
            // Show empty state on error too
            if (emptyEl) {
                emptyEl.style.display = "block";
                emptyEl.innerHTML = (
                    '<div style="font-size:32px;margin-bottom:10px;">⚠️</div>' +
                    '<p style="font-size:13px;">Could not load analytics: ' +
                    _esc(err.message) + '</p>'
                );
            }
        });
}


// ─── Chart.js horizontal bar chart — top 10 rules ────────────────────────────

function _renderAnalyticsChart(freq) {
    var canvas = document.getElementById("analytics-chart");
    if (!canvas) return;

    // Destroy previous chart instance to avoid canvas reuse error
    if (_analyticsChart) {
        _analyticsChart.destroy();
        _analyticsChart = null;
    }

    // Take top 10 — already sorted by hit_count desc from the server
    var top10 = freq.slice(0, 10);

    // Reverse so highest bar appears at the top of a horizontal chart
    var labels     = [];
    var hitCounts  = [];
    var colors     = [];
    var borderColors = [];

    var sevColorMap = {
        "CRITICAL": { bg: "rgba(248,113,113,0.75)", border: "rgba(248,113,113,1)" },
        "HIGH":     { bg: "rgba(251,191,36,0.75)",  border: "rgba(251,191,36,1)"  },
        "MEDIUM":   { bg: "rgba(124,106,247,0.75)", border: "rgba(124,106,247,1)" },
        "LOW":      { bg: "rgba(74,222,128,0.65)",  border: "rgba(74,222,128,1)"  },
    };

    // Build arrays in reversed order (highest at top of horizontal chart)
    for (var i = top10.length - 1; i >= 0; i--) {
        var rule = top10[i];
        // Truncate long names so they fit on the y-axis label
        var label = rule.name.length > 38
            ? rule.name.slice(0, 36) + "…"
            : rule.name;
        labels.push(label);
        hitCounts.push(rule.hit_count);

        var sev    = (rule.severity || "MEDIUM").toUpperCase();
        var colDef = sevColorMap[sev] || sevColorMap["MEDIUM"];
        colors.push(colDef.bg);
        borderColors.push(colDef.border);
    }

    var ctx = canvas.getContext("2d");

    _analyticsChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels:   labels,
            datasets: [{
                label:           "Hit count",
                data:            hitCounts,
                backgroundColor: colors,
                borderColor:     borderColors,
                borderWidth:     1,
                borderRadius:    4,
                borderSkipped:   false,
            }]
        },
        options: {
            indexAxis: "y",          // horizontal bars
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 500 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function (ctx) {
                            var idx      = (top10.length - 1) - ctx.dataIndex;
                            var rule     = top10[idx] || {};
                            var rate     = rule.hit_rate_pct != null
                                          ? rule.hit_rate_pct.toFixed(1)
                                          : "?";
                            return [
                                " Hits: " + ctx.parsed.x,
                                " Hit rate: " + rate + "%",
                                " Severity: " + (rule.severity || "?"),
                            ];
                        }
                    },
                    backgroundColor: "rgba(13,13,20,0.95)",
                    titleColor:      "#e8e4ff",
                    bodyColor:       "#7a75a8",
                    borderColor:     "rgba(124,106,247,0.3)",
                    borderWidth:     1,
                    padding:         10,
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        color:     "#7a75a8",
                        font:      { size: 11 },
                        precision: 0,
                    },
                    grid: {
                        color: "rgba(42,38,80,0.5)",
                    },
                    title: {
                        display: true,
                        text:    "Number of URLs triggered",
                        color:   "#7a75a8",
                        font:    { size: 11 },
                    }
                },
                y: {
                    ticks: {
                        color: "#e8e4ff",
                        font:  { size: 11 },
                    },
                    grid: {
                        display: false,
                    }
                }
            },
            // Set explicit height so canvas isn't squashed
            layout: { padding: { right: 10 } }
        }
    });

    // Fix canvas height explicitly for horizontal bar chart to breathe
    canvas.parentElement.style.height = Math.max(top10.length * 38 + 60, 200) + "px";
}


// ─── Frequency table below the chart ─────────────────────────────────────────

function _renderAnalyticsTable(freq, total) {
    var tbody = document.getElementById("analytics-table-body");
    if (!tbody) return;

    if (!freq.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No data</td></tr>';
        return;
    }

    var html = "";
    for (var i = 0; i < freq.length; i++) {
        var rule  = freq[i];
        var rank  = i + 1;
        var sev   = (rule.severity || "MEDIUM").toLowerCase();
        var rate  = typeof rule.hit_rate_pct === "number"
                    ? rule.hit_rate_pct.toFixed(1)
                    : "0.0";

        var rankCls = rank <= 3 ? " rank-" + rank : "";

        html += "<tr>";

        // Rank
        html += '<td><span class="rank-badge' + rankCls + '">' + rank + "</span></td>";

        // Rule name + ID
        html += "<td>";
        html +=   '<span style="font-weight:600;font-size:13px;">' + _esc(rule.name) + "</span>";
        html +=   '<br><span style="font-size:10px;color:var(--text-muted);font-family:monospace;">';
        html +=     _esc(rule.rule_id);
        html +=   "</span>";
        html += "</td>";

        // Severity
        html += '<td><span class="sev-tag sev-' + sev + '">' + _esc(rule.severity) + "</span></td>";

        // Hit count
        html += '<td><strong>' + rule.hit_count + "</strong> / " + total + "</td>";

        // Hit rate with mini bar
        var fillCls = "fill-" + sev;
        html += "<td>";
        html +=   '<div style="display:flex;align-items:center;gap:6px;">';
        html +=     '<div class="hit-rate-bar-track">';
        html +=       '<div class="hit-rate-bar-fill ' + fillCls + '" ';
        html +=         'style="width:' + Math.min(parseFloat(rate), 100) + '%"></div>';
        html +=     "</div>";
        html +=     '<span style="font-size:12px;color:var(--text-muted);">' + rate + "%</span>";
        html +=   "</div>";
        html += "</td>";

        html += "</tr>";
    }

    tbody.innerHTML = html;
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
    var re = data.module_results && data.module_results.rule_engine
        ? data.module_results.rule_engine
        : {};

    // ── URL display ──────────────────────────────────────────────────────────
    var resInput = document.getElementById("res-input");
    if (resInput) resInput.textContent = re.input || "—";

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
        if (score >= 70)      fillClass = "fill-malicious";
        else if (score >= 30) fillClass = "fill-suspicious";
        bar.className = "score-bar-fill " + fillClass;
    }

    var scoreNum = document.getElementById("score-num");
    if (scoreNum) scoreNum.textContent = score.toFixed(1);

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
    var hits        = re.hits || [];
    var triggeredIds = {};
    var tidArr      = re.triggered_ids || [];
    for (var t = 0; t < tidArr.length; t++) {
        triggeredIds[tidArr[t]] = true;
    }

    var hitCountEl = document.getElementById("hit-count");
    if (hitCountEl) hitCountEl.textContent = hits.length;

    var triggeredContainer = document.getElementById("triggered-rules-list");
    if (triggeredContainer) {
        if (hits.length === 0) {
            triggeredContainer.innerHTML =
                '<p class="empty-state">No rules triggered — URL appears clean.</p>';
        } else {
            var hitHtml = "";
            for (var h = 0; h < hits.length; h++) {
                var hit    = hits[h];
                var hitSev = hit.severity ? hit.severity.toLowerCase() : "medium";

                hitHtml += '<div class="rule-hit-card sev-' + hitSev + '">';
                hitHtml +=   '<div class="rule-hit-header">';
                hitHtml +=     '<span class="sev-tag sev-' + hitSev + '">' + _esc(hit.severity) + "</span>";
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

    var passedRules = [];
    for (var pr = 0; pr < _allRules.length; pr++) {
        if (!triggeredIds[_allRules[pr].rule_id]) {
            passedRules.push(_allRules[pr]);
        }
    }

    if (passCountEl) passCountEl.textContent = passedRules.length;

    if (passedContainer) {
        if (passedRules.length === 0) {
            passedContainer.innerHTML = '<p class="empty-state">All rules triggered.</p>';
        } else {
            var passHtml = "";
            for (var ps = 0; ps < passedRules.length; ps++) {
                var pr2   = passedRules[ps];
                var prSev = pr2.severity ? pr2.severity.toLowerCase() : "low";
                passHtml += '<div class="passed-rule-row">';
                passHtml +=   '<div class="pass-check">&#10003;</div>';
                passHtml +=   '<span class="sev-tag sev-' + prSev + '">' + _esc(pr2.severity) + "</span>";
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
            if (regEl) regEl.classList.add("triggered");
        }
    }

    // ── Show result card ─────────────────────────────────────────────────────
    var resultCard = document.getElementById("result-card");
    if (resultCard) {
        resultCard.style.display = "block";
        resultCard.scrollIntoView({ behavior: "smooth" });
    }

    var timeEl = document.getElementById("update-time");
    if (timeEl) timeEl.textContent = new Date().toLocaleTimeString();
}


// ─── UI helpers ───────────────────────────────────────────────────────────────

function showSpinner(show) {
    var el = document.getElementById("spinner");
    if (el) el.style.display = show ? "flex" : "none";
}

function hideResultCard() {
    var el = document.getElementById("result-card");
    if (el) el.style.display = "none";
}

function _esc(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}