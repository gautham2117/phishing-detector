# detection_rules.py
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

logger   = logging.getLogger(__name__)
rules_bp = Blueprint("rules_bp", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@rules_bp.route("/rules", methods=["GET"])
def detection_rules_page():
    all_rules = []
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        if resp.status_code == 200:
            all_rules = resp.json().get("rules", [])
    except Exception:
        pass
    return render_template("detection_rules.html", all_rules=all_rules)


@rules_bp.route("/rules/scan/url", methods=["POST"])
def scan_url_rules():
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
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500