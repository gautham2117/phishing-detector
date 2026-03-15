"""
backend/app/routes/threat_explain.py
Phase 16 — Multi-Language Threat Explanation & User Awareness Engine
Flask blueprint for BART explanations, MarianMT translation, and security tips.
Variable name: threat_bp  |  url_prefix: /threat
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

logger    = logging.getLogger(__name__)
threat_bp = Blueprint("threat_bp", __name__, url_prefix="/threat")

PROXY_TIMEOUT = 120   # Translation models can take time on first load


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@threat_bp.route("/explain")
def threat_explain_page():
    """
    Threat Explanation dashboard page.
    Serves BART-generated summaries and MarianMT translations.
    """
    return render_template("threat_explain.html")


# ── Generate explanation ──────────────────────────────────────────────────────

@threat_bp.route("/explain/generate", methods=["POST"])
def generate():
    payload = request.get_json(silent=True) or {}
    text    = payload.get("text", "").strip()

    if not text:
        return jsonify({
            "status":  "error",
            "message": "Text is required."
        }), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/threat/explain",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({
            "status":  "error",
            "message": "Explanation timed out."
        }), 504
    except Exception as ex:
        logger.error("Explain proxy error: %s", ex)
        return jsonify({
            "status":  "error",
            "message": str(ex)
        }), 502


# ── Translate ──────────────────────────────────────────────────────────────────

@threat_bp.route("/explain/translate", methods=["POST"])
def translate():
    payload   = request.get_json(silent=True) or {}
    text      = payload.get("text",      "").strip()
    lang_code = payload.get("lang_code", "").strip()

    if not text or not lang_code:
        return jsonify({
            "status":  "error",
            "message": "text and lang_code are required."
        }), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/threat/translate",
            json={"text": text, "lang_code": lang_code},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({
            "status":  "error",
            "message": (
                "Translation timed out — the model may be downloading "
                "for the first time. Please try again in 30 seconds."
            ),
        }), 504
    except Exception as ex:
        logger.error("Translate proxy error: %s", ex)
        return jsonify({
            "status":  "error",
            "message": str(ex)
        }), 502


# ── Tips ───────────────────────────────────────────────────────────────────────

@threat_bp.route("/explain/tips", methods=["POST"])
def tips():
    payload = request.get_json(silent=True) or {}
    try:
        resp = http_requests.post(
            f"{_api()}/api/threat/tips",
            json=payload,
            timeout=15,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({
            "status":  "error",
            "message": str(ex)
        }), 502


# ── Supported languages ────────────────────────────────────────────────────────

@threat_bp.route("/explain/languages")
def languages():
    try:
        resp = http_requests.get(
            f"{_api()}/api/threat/languages",
            timeout=10,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({
            "status":  "error",
            "message": str(ex)
        }), 502