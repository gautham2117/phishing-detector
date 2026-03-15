"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd          = document.getElementById("page-data");
var FEEDBACK_URL = _pd.dataset.feedbackUrl;
var RETRAIN_URL  = _pd.dataset.retrainUrl;
var STATUS_URL   = _pd.dataset.statusUrl;
var VERSIONS_URL = _pd.dataset.versionsUrl;
var PLAN_URL     = _pd.dataset.planUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var mmSubmitBtn    = document.getElementById("mmSubmitBtn");
var mmRetrainBtn   = document.getElementById("mmRetrainBtn");
var mmLog          = document.getElementById("mmLog");
var mmLogWrap      = document.getElementById("mmLogWrap");
var mmLogPoll      = document.getElementById("mmLogPoll");
var mmRetrainStatus= document.getElementById("mmRetrainStatus");
var mmVersionBody  = document.getElementById("mmVersionBody");
var mmVersionCount = document.getElementById("mmVersionCount");
var mmFeedbackBody = document.getElementById("mmFeedbackBody");
var mmCmCard       = document.getElementById("mmCmCard");

var _statusTimer   = null;
var _pollTimer     = null;
var _planLoaded    = false;


// ════════════════════════════════════════════════════════════════════════════
// FEEDBACK SUBMIT
// ════════════════════════════════════════════════════════════════════════════

mmSubmitBtn.addEventListener("click", function () {
    var url       = document.getElementById("mmUrl").value.trim();
    var labelType = document.getElementById("mmLabelType").value;
    var fbLabel   = document.getElementById("mmFeedbackLabel").value;
    var note      = document.getElementById("mmNote").value.trim();

    if (!url) {
        showFbError("URL is required.");
        return;
    }
    if (!labelType) {
        showFbError("Please select a label type.");
        return;
    }

    mmSubmitBtn.disabled    = true;
    mmSubmitBtn.textContent = "Submitting…";
    hideFbError();
    hideFbSuccess();

    fetch(FEEDBACK_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            url:            url,
            label_type:     labelType,
            feedback_label: fbLabel,
            admin_note:     note,
        }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        mmSubmitBtn.disabled    = false;
        mmSubmitBtn.textContent = "Submit Label";
        if (data.status !== "success") {
            showFbError(data.message || "Submission failed.");
            return;
        }
        document.getElementById("mmUrl").value  = "";
        document.getElementById("mmNote").value = "";
        document.getElementById("mmLabelType").value = "";
        showFbSuccess("Label submitted — ID #" + data.sample.id);
        loadFeedbackQueue();
    })
    .catch(function (err) {
        mmSubmitBtn.disabled    = false;
        mmSubmitBtn.textContent = "Submit Label";
        showFbError("Request failed: " + err.message);
    });
});


// ════════════════════════════════════════════════════════════════════════════
// RETRAIN
// ════════════════════════════════════════════════════════════════════════════

mmRetrainBtn.addEventListener("click", function () {
    if (!confirm(
        "Start retraining the Random Forest model?\n\n" +
        "This will run in the background. " +
        "The live log will appear below."
    )) { return; }

    mmRetrainBtn.disabled    = true;
    mmRetrainBtn.textContent = "⏳ Starting…";
    mmLogWrap.style.display  = "block";
    mmLog.textContent        = "";
    mmRetrainStatus.textContent = "● Running";
    mmRetrainStatus.className   = "mm-retrain-status mm-status-running";

    fetch(RETRAIN_URL, { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") {
                mmRetrainBtn.disabled    = false;
                mmRetrainBtn.textContent = "▶ Trigger Retrain";
                appendLog("ERROR: " + (data.message || "Failed to start."));
                return;
            }
            appendLog("Retraining started…");
            startStatusPolling();
        })
        .catch(function (err) {
            mmRetrainBtn.disabled    = false;
            mmRetrainBtn.textContent = "▶ Trigger Retrain";
            appendLog("Request failed: " + err.message);
        });
});

function startStatusPolling() {
    if (_statusTimer) { clearInterval(_statusTimer); }
    _statusTimer = setInterval(pollStatus, 2000);
}

function pollStatus() {
    fetch(STATUS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            var t = data.training || {};

            // Update log
            var lines = t.log || [];
            mmLog.textContent = lines.join("\n");
            mmLog.scrollTop   = mmLog.scrollHeight;

            // Update status badge
            if (t.running) {
                mmRetrainStatus.textContent = "● Running";
                mmRetrainStatus.className   = "mm-retrain-status mm-status-running";
                mmLogPoll.style.display     = "inline";
            } else {
                mmLogPoll.style.display     = "none";
                if (t.error) {
                    mmRetrainStatus.textContent = "✕ Error";
                    mmRetrainStatus.className   = "mm-retrain-status mm-status-error";
                } else if (t.version) {
                    mmRetrainStatus.textContent = "✓ v" + t.version + " Active";
                    mmRetrainStatus.className   = "mm-retrain-status mm-status-done";
                }
                // Stop polling, re-enable button, refresh versions
                clearInterval(_statusTimer);
                mmRetrainBtn.disabled    = false;
                mmRetrainBtn.textContent = "▶ Trigger Retrain";
                loadVersions();
            }
        })
        .catch(function () {/* silent */});
}

function appendLog(msg) {
    mmLog.textContent += msg + "\n";
    mmLog.scrollTop    = mmLog.scrollHeight;
}


// ════════════════════════════════════════════════════════════════════════════
// MODEL VERSIONS
// ════════════════════════════════════════════════════════════════════════════

function loadVersions() {
    fetch(VERSIONS_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderVersions(data.versions || []);
        })
        .catch(function () {/* silent */});
}

function renderVersions(versions) {
    mmVersionCount.textContent = versions.length;
    mmVersionBody.innerHTML    = "";

    if (versions.length === 0) {
        mmVersionBody.innerHTML =
            '<tr><td colspan="10" class="att-empty-row">' +
            'No model versions yet. Trigger a retrain to create v1.</td></tr>';
        return;
    }

    versions.forEach(function (v) {
        var activeBadge = v.is_active
            ? "<span class='badge badge-safe'>Active</span>"
            : "<span style='color:var(--text-muted)'>—</span>";

        var fmtMetric = function (val) {
            return val !== null && val !== undefined
                ? (val * 100).toFixed(1) + "%"
                : "—";
        };

        var ts = (v.created_at || "").replace("T"," ").replace("Z","").slice(0,16);

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td><strong>v" + v.version_number + "</strong></td>" +
            "<td>" + (v.training_samples || 0) + "</td>" +
            "<td>" + (v.feedback_samples || 0) + "</td>" +
            "<td class='" + metricClass(v.accuracy) + "'>" +
                fmtMetric(v.accuracy)   + "</td>" +
            "<td>" + fmtMetric(v.precision)  + "</td>" +
            "<td>" + fmtMetric(v.recall)     + "</td>" +
            "<td>" + fmtMetric(v.f1_score)   + "</td>" +
            "<td>" + activeBadge + "</td>" +
            "<td class='att-ts'>" + ts + "</td>" +
            "<td>" +
                "<button class='pm-btn mm-cm-btn' " +
                "data-cm='" + escapeAttr(JSON.stringify(v.confusion_matrix)) + "' " +
                "data-version='" + v.version_number + "'>CM</button>" +
            "</td>";
        mmVersionBody.appendChild(tr);
    });
}

function metricClass(val) {
    if (val === null || val === undefined) { return ""; }
    if (val >= 0.9) { return ""; }
    if (val >= 0.7) { return "att-cell-amber"; }
    return "att-cell-red";
}

// Confusion matrix display
document.addEventListener("click", function (e) {
    if (!e.target.classList.contains("mm-cm-btn")) { return; }
    var cm      = JSON.parse(e.target.dataset.cm || "[]");
    var version = e.target.dataset.version;
    renderConfusionMatrix(cm, version);
});

function renderConfusionMatrix(cm, version) {
    document.getElementById("mmCmVersion").textContent = version;
    var grid = document.getElementById("mmCmGrid");
    grid.innerHTML = "";

    if (!cm || cm.length === 0) {
        grid.innerHTML = "<p class='att-empty-note'>No confusion matrix data.</p>";
        mmCmCard.style.display = "block";
        return;
    }

    // Header row
    var labels = ["Pred SAFE", "Pred MAL"];
    var header = document.createElement("div");
    header.className = "mm-cm-row";
    header.innerHTML = "<div class='mm-cm-cell mm-cm-header'></div>" +
        labels.map(function (l) {
            return "<div class='mm-cm-cell mm-cm-header'>" + l + "</div>";
        }).join("");
    grid.appendChild(header);

    var rowLabels = ["Act SAFE", "Act MAL"];
    cm.forEach(function (row, ri) {
        var total   = cm[ri].reduce(function (a, b) { return a + b; }, 0) || 1;
        var rowEl   = document.createElement("div");
        rowEl.className = "mm-cm-row";
        var cells   = "<div class='mm-cm-cell mm-cm-header'>" +
            rowLabels[ri] + "</div>";
        row.forEach(function (val, ci) {
            var pct   = Math.round((val / total) * 100);
            var isDiag= ri === ci;
            cells += "<div class='mm-cm-cell " +
                (isDiag ? "mm-cm-diag" : "mm-cm-offdiag") + "'>" +
                "<div class='mm-cm-count'>" + val + "</div>" +
                "<div class='mm-cm-pct'>" + pct + "%</div>" +
                "</div>";
        });
        rowEl.innerHTML = cells;
        grid.appendChild(rowEl);
    });

    mmCmCard.style.display = "block";
    mmCmCard.scrollIntoView({ behavior: "smooth" });
}

document.getElementById("mmCmClose").addEventListener("click", function () {
    mmCmCard.style.display = "none";
});


// ════════════════════════════════════════════════════════════════════════════
// FEEDBACK QUEUE
// ════════════════════════════════════════════════════════════════════════════

function loadFeedbackQueue() {
    fetch(FEEDBACK_URL + "?limit=50")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderFeedbackQueue(data.queue || []);
        })
        .catch(function () {/* silent */});
}

function renderFeedbackQueue(queue) {
    mmFeedbackBody.innerHTML = "";

    if (queue.length === 0) {
        mmFeedbackBody.innerHTML =
            '<tr><td colspan="7" class="att-empty-row">No feedback labels yet.</td></tr>';
        return;
    }

    var labelTypeColors = {
        FALSE_POSITIVE:    "badge-suspicious",
        FALSE_NEGATIVE:    "badge-suspicious",
        CONFIRMED_PHISHING:"badge-malicious",
        CONFIRMED_SAFE:    "badge-safe",
    };

    queue.forEach(function (s) {
        var ltClass = labelTypeColors[s.label_type] || "";
        var used    = s.used_in_training
            ? "<span class='badge badge-safe'>✓ Used</span>"
            : "<span class='badge'>Pending</span>";
        var ver     = s.trained_in_version
            ? "v" + s.trained_in_version : "—";
        var ts      = (s.created_at || "").replace("T"," ").replace("Z","").slice(0,16);

        var tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + s.id + "</td>" +
            "<td class='lm-ref-cell'>" + escapeHtml(s.url) + "</td>" +
            "<td><span class='badge " + ltClass + "'>" +
                escapeHtml(s.label_type) + "</span></td>" +
            "<td>" + escapeHtml(s.feedback_label) + "</td>" +
            "<td>" + used + "</td>" +
            "<td>" + ver  + "</td>" +
            "<td class='att-ts'>" + ts + "</td>";
        mmFeedbackBody.appendChild(tr);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// HUGGINGFACE FINE-TUNE PLAN
// ════════════════════════════════════════════════════════════════════════════

document.getElementById("mmPlanToggle").addEventListener("click", function () {
    var body = document.getElementById("mmPlanBody");
    if (body.style.display === "none") {
        body.style.display = "block";
        this.textContent   = "Hide Plan";
        if (!_planLoaded) {
            loadFinetunePlan();
            _planLoaded = true;
        }
    } else {
        body.style.display = "none";
        this.textContent   = "Show Plan";
    }
});

function loadFinetunePlan() {
    fetch(PLAN_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            renderFinetunePlan(data.plan || {});
        })
        .catch(function () {/* silent */});
}

function renderFinetunePlan(plan) {
    var container = document.getElementById("mmPlanSteps");
    container.innerHTML = "";

    (plan.steps || []).forEach(function (step) {
        var div = document.createElement("div");
        div.className = "mm-plan-step";
        div.innerHTML =
            "<div class='mm-plan-step-header'>" +
                "<span class='mm-plan-step-num'>Step " + step.step + "</span>" +
                "<span class='mm-plan-step-name'>" +
                    escapeHtml(step.name) + "</span>" +
            "</div>" +
            "<p class='mm-plan-desc'>" +
                escapeHtml(step.description) + "</p>" +
            "<pre class='mm-plan-code'>" +
                escapeHtml(step.code_sketch) + "</pre>";
        container.appendChild(div);
    });

    var noteEl = document.getElementById("mmPlanNote");
    noteEl.innerHTML =
        "<strong>Hardware note:</strong> " +
        escapeHtml(plan.hardware_note || "") +
        "<br><strong>Requirements:</strong> " +
        escapeHtml((plan.requirements || []).join(", "));
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function showFbError(msg) {
    var el = document.getElementById("mmSubmitError");
    el.textContent   = "⚠ " + msg;
    el.style.display = "block";
}
function hideFbError() {
    document.getElementById("mmSubmitError").style.display = "none";
}
function showFbSuccess(msg) {
    var el = document.getElementById("mmSubmitSuccess");
    el.textContent   = "✓ " + msg;
    el.style.display = "block";
}
function hideFbSuccess() {
    document.getElementById("mmSubmitSuccess").style.display = "none";
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function escapeAttr(str) {
    return (str || "").replace(/'/g, "&#39;").replace(/"/g, "&quot;");
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadVersions();
loadFeedbackQueue();
pollStatus();

_pollTimer = setInterval(function () {
    loadVersions();
    loadFeedbackQueue();
}, 5000);