"use strict";

// ── Data island ────────────────────────────────────────────────────────────
var _pd           = document.getElementById("page-data");
var GENERATE_URL  = _pd.dataset.generateUrl;
var TRANSLATE_URL = _pd.dataset.translateUrl;
var LANGUAGES_URL = _pd.dataset.languagesUrl;

// ── DOM ────────────────────────────────────────────────────────────────────
var teGenerateBtn   = document.getElementById("teGenerateBtn");
var teBtnText       = document.getElementById("teBtnText");
var teSpinner       = document.getElementById("teSpinner");
var teError         = document.getElementById("teError");
var teResultsPanel  = document.getElementById("teResultsPanel");
var teTranslateBtn  = document.getElementById("teTranslateBtn");
var teTransBtnText  = document.getElementById("teTransBtnText");
var teTransSpinner  = document.getElementById("teTransSpinner");
var teLangSelector  = document.getElementById("teLangSelector");

var _currentExplanation = "";
var _selectedLang       = "";
var _languages          = [];


// ════════════════════════════════════════════════════════════════════════════
// LOAD LANGUAGES
// ════════════════════════════════════════════════════════════════════════════

function loadLanguages() {
    fetch(LANGUAGES_URL)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.status !== "success") { return; }
            _languages = data.languages || [];
            renderLanguageSelector(_languages);
        })
        .catch(function () {/* silent */});
}

function renderLanguageSelector(languages) {
    teLangSelector.innerHTML = "";
    languages.forEach(function (lang) {
        var btn = document.createElement("button");
        btn.className        = "te-lang-btn";
        btn.dataset.code     = lang.code;
        btn.dataset.name     = lang.name;
        btn.dataset.native   = lang.native_name;
        btn.dataset.model    = lang.model;
        btn.innerHTML = (
            "<span class='te-lang-flag'>" + lang.flag + "</span>" +
            "<span class='te-lang-name'>" + lang.native_name + "</span>" +
            "<span class='te-lang-eng'>"  + lang.name + "</span>"
        );
        btn.addEventListener("click", function () {
            // Deselect all
            document.querySelectorAll(".te-lang-btn").forEach(function (b) {
                b.classList.remove("te-lang-selected");
            });
            btn.classList.add("te-lang-selected");
            _selectedLang = lang.code;
            teTranslateBtn.disabled = !_currentExplanation;
        });
        teLangSelector.appendChild(btn);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// GENERATE EXPLANATION
// ════════════════════════════════════════════════════════════════════════════

teGenerateBtn.addEventListener("click", function () {
    var text      = document.getElementById("teTextInput").value.trim();
    var verdict   = document.getElementById("teVerdict").value;
    var module    = document.getElementById("teModule").value;
    var riskScore = parseFloat(
        document.getElementById("teRiskScore").value
    ) || 0.0;

    if (!text) {
        showError("Please enter some threat text.");
        return;
    }

    hideError();
    setGenerateLoading(true);
    teResultsPanel.style.display = "none";

    fetch(GENERATE_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            text:       text,
            verdict:    verdict,
            module:     module,
            risk_score: riskScore,
        }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        setGenerateLoading(false);
        if (data.status !== "success") {
            showError(data.message || "Failed to generate explanation.");
            return;
        }
        renderResults(data);
        teResultsPanel.style.display = "block";
        teResultsPanel.scrollIntoView({ behavior: "smooth" });
    })
    .catch(function (err) {
        setGenerateLoading(false);
        showError("Request failed: " + err.message);
    });
});

function renderResults(data) {
    // English explanation
    _currentExplanation = data.explanation || "";
    document.getElementById("teEnglishExplanation").textContent =
        _currentExplanation || "No explanation generated.";

    // Enable translate button if language already selected
    teTranslateBtn.disabled = !(_currentExplanation && _selectedLang);

    // Reset translation output
    document.getElementById("teTranslatedOutput").style.display = "none";
    document.getElementById("teTranslateNote").style.display    = "none";

    // Security tips
    renderTips(data.tips || {});
}

function renderTips(tips) {
    if (!tips || !tips.tips || tips.tips.length === 0) {
        document.getElementById("teTipsCard").style.display = "none";
        return;
    }

    document.getElementById("teTipsCard").style.display = "block";
    document.getElementById("teTipsIcon").textContent   = tips.icon || "🛡";
    document.getElementById("teTipsCategory").textContent =
        tips.category || "General Security";

    var colorMap = {
        red:  "var(--red)",
        amber:"var(--amber)",
        blue: "var(--blue)",
        green:"var(--green)",
    };
    var color = colorMap[tips.color] || "var(--blue)";

    var list = document.getElementById("teTipsList");
    list.innerHTML = "";
    tips.tips.forEach(function (tip) {
        var li = document.createElement("li");
        li.className   = "te-tip-item";
        li.style.borderLeftColor = color;
        li.textContent = tip;
        list.appendChild(li);
    });
}


// ════════════════════════════════════════════════════════════════════════════
// TRANSLATE
// ════════════════════════════════════════════════════════════════════════════

teTranslateBtn.addEventListener("click", function () {
    if (!_currentExplanation || !_selectedLang) { return; }

    setTranslateLoading(true);

    // Show first-time download warning
    document.getElementById("teTranslateNote").style.display = "block";
    document.getElementById("teTranslatedOutput").style.display = "none";

    fetch(TRANSLATE_URL, {
        method:  "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            text:      _currentExplanation,
            lang_code: _selectedLang,
        }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        setTranslateLoading(false);
        document.getElementById("teTranslateNote").style.display = "none";

        if (data.status !== "success") {
            showTransError(data.message || "Translation failed.");
            return;
        }
        renderTranslation(data.result || {});
    })
    .catch(function (err) {
        setTranslateLoading(false);
        document.getElementById("teTranslateNote").style.display = "none";
        showTransError("Request failed: " + err.message);
    });
});

function renderTranslation(result) {
    var output = document.getElementById("teTranslatedOutput");
    output.style.display = "block";

    document.getElementById("teTransFlag").textContent =
        result.flag || "";
    document.getElementById("teTransLangName").textContent =
        (result.native_name || result.language_name || "") +
        " (" + (result.language_name || "") + ")";
    document.getElementById("teTransModel").textContent =
        result.model_used ? result.model_used.split("/").pop() : "";

    var textEl = document.getElementById("teTranslatedText");
    textEl.textContent = result.translated || "No translation available.";

    var errEl = document.getElementById("teTransError");
    if (result.error) {
        errEl.textContent   = "⚠ " + result.error;
        errEl.style.display = "block";
    } else {
        errEl.style.display = "none";
    }
}

function showTransError(msg) {
    var output = document.getElementById("teTranslatedOutput");
    var errEl  = document.getElementById("teTransError");
    output.style.display  = "block";
    errEl.textContent     = "⚠ " + msg;
    errEl.style.display   = "block";
    document.getElementById("teTranslatedText").textContent = "";
}


// ════════════════════════════════════════════════════════════════════════════
// LOADING STATES
// ════════════════════════════════════════════════════════════════════════════

function setGenerateLoading(on) {
    teGenerateBtn.disabled     = on;
    teBtnText.style.display    = on ? "none"   : "inline";
    teSpinner.style.display    = on ? "inline" : "none";
}

function setTranslateLoading(on) {
    teTranslateBtn.disabled       = on;
    teTransBtnText.style.display  = on ? "none"   : "inline";
    teTransSpinner.style.display  = on ? "inline" : "none";
}


// ════════════════════════════════════════════════════════════════════════════
// UTILITY
// ════════════════════════════════════════════════════════════════════════════

function showError(msg) {
    teError.textContent   = "⚠ " + msg;
    teError.style.display = "block";
}
function hideError() {
    teError.style.display = "none";
}


// ════════════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════════════

loadLanguages();
document.getElementById("teTipsCard").style.display = "none";