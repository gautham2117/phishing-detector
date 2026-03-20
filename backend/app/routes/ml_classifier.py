# ml_classifier.py
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.auth import role_required

logger = logging.getLogger(__name__)
ml_bp  = Blueprint("ml_bp", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@ml_bp.route("/ml/classifier", methods=["GET"])
@role_required("admin", "analyst")
def ml_classifier_page():
    return render_template("ml_classifier.html")


@ml_bp.route("/ml/scan", methods=["POST"])
@role_required("admin", "analyst")
def ml_scan():
    data = request.get_json() or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        resp = requests.post(
            f"{_api()}/api/scan/ml/url",
            json={
                "url":         url,
                "rf_weight":   data.get("rf_weight",   0.45),
                "bert_weight": data.get("bert_weight", 0.55)
            },
            timeout=60
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "ML inference timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ml_bp.route("/ml/scan/batch", methods=["POST"])
@role_required("admin", "analyst")
def ml_scan_batch():
    data = request.get_json() or {}
    urls = data.get("urls", [])
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    try:
        resp = requests.post(
            f"{_api()}/api/scan/ml/url/batch",
            json=urls,
            timeout=120
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500