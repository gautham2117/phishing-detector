"""
backend/app/routes/risk_score.py
Phase 10 — Risk Score Aggregator Flask blueprint
Variable name: risk_score_bp  |  url_prefix: /risk
"""

import logging

import requests as http_requests
from flask import Blueprint, render_template, request, jsonify, current_app

logger        = logging.getLogger(__name__)
risk_score_bp = Blueprint("risk_score_bp", __name__, url_prefix="/risk")

PROXY_TIMEOUT = 30


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@risk_score_bp.route("/")
def index():
    return render_template("risk_score.html")


@risk_score_bp.route("/aggregate", methods=["POST"])
def aggregate():
    payload = request.get_json(silent=True) or {}
    ids = [
        payload.get("email_scan_id"),
        payload.get("url_scan_id"),
        payload.get("network_scan_id"),
        payload.get("attachment_id"),
        payload.get("ai_detection_id"),
        payload.get("image_scan_id"),
    ]
    if not any(ids):
        return jsonify({
            "status":  "error",
            "message": "Provide at least one scan ID."
        }), 400
    try:
        resp = http_requests.post(
            f"{_api()}/api/risk/aggregate",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Aggregation timed out"}), 504
    except Exception as ex:
        logger.error("Risk aggregate proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


@risk_score_bp.route("/history")
def history():
    limit = request.args.get("limit", 20)
    try:
        resp = http_requests.get(
            f"{_api()}/api/risk/history",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


@risk_score_bp.route("/history/<int:record_id>")
def detail(record_id):
    try:
        resp = http_requests.get(
            f"{_api()}/api/risk/history/{record_id}",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502