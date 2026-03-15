# threat_explain.py
# Flask Blueprint for the Threat Explanation dashboard page.
# Phase 16 will fill this with multilingual threat explanations
# using Helsinki-NLP MarianMT translation models.
# For now it serves a placeholder page so the sidebar link works.

from flask import Blueprint, render_template

threat_bp = Blueprint("threat_bp", __name__)


@threat_bp.route("/threat/explain", methods=["GET"])
def threat_explain_page():
    """
    Placeholder for the Threat Explanation dashboard page.
    Phase 16 (Multi-Language Threat Explanation Engine) will replace
    this with BART-generated summaries and MarianMT translations.
    """
    return render_template("placeholder.html",
        module_title="Threat Explanation",
        module_phase="Phase 16",
        module_description=(
            "Generates plain-language threat explanations for every scan "
            "result and translates them into French, Spanish, German, "
            "Chinese, Arabic, and Tamil using Helsinki-NLP MarianMT models. "
            "Also provides per-threat security awareness tips."
        ),
        coming_modules=[
            "BART-generated natural language threat summary",
            "Language selector dropdown (EN / FR / ES / DE / ZH / AR / TA)",
            "MarianMT real-time translation of threat explanation",
            "Per-threat-category security awareness tips card",
            "Link back to originating scan result",
        ]
    )