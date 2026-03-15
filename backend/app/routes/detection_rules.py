# detection_rules.py
# Flask Blueprint for the Detection Rules dashboard page.
# Replaces the Phase 0 placeholder with a fully functional page.

import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

logger    = logging.getLogger(__name__)
rules_bp  = Blueprint("rules_bp", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@rules_bp.route("/rules", methods=["GET"])
def detection_rules_page():
    """
    Render the Detection Rules dashboard page.
    Pre-loads the full rule registry from FastAPI so the page
    shows all rules immediately without waiting for a scan.
    """
    all_rules = []
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        if resp.status_code == 200:
            all_rules = resp.json().get("rules", [])
    except Exception:
        pass   # Page still works — rules load from JS on first scan

    return render_template(
        "detection_rules.html",
        all_rules=all_rules
    )


@rules_bp.route("/rules/scan/url", methods=["POST"])
def scan_url_rules():
    """
    Proxy: run the rule engine on a single URL.
    Called by the detection_rules.js URL scan form.
    """
    data = request.get_json() or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        resp = requests.post(
            f"{_api()}/api/scan/rules/url",
            json={"url": url},
            timeout=30
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@rules_bp.route("/rules/scan/email", methods=["POST"])
def scan_email_rules():
    """
    Proxy: run the rule engine on email content.
    Called automatically from the Email Scan page after a scan completes.
    """
    data = request.get_json() or {}

    try:
        resp = requests.post(
            f"{_api()}/api/scan/rules/email",
            json={
                "subject":   data.get("subject",   ""),
                "body_text": data.get("body_text", ""),
                "body_html": data.get("body_html", ""),
                "urls":      data.get("urls",      [])
            },
            timeout=30
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@rules_bp.route("/rules/list", methods=["GET"])
def get_rules_list():
    """Return the full rule registry as JSON (for dashboard live use)."""
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500