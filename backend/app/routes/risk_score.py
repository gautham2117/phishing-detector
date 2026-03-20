"""
backend/app/routes/risk_score.py
Phase 10 — Risk Score Aggregator Flask blueprint
Variable name: risk_score_bp  |  url_prefix: /risk

ADDED:
  GET  /risk/status         — probe all module tables, return online/offline status
  POST /risk/aggregate/auto — auto-pull most recent scan per module + aggregate
"""

import logging

import requests as http_requests
from flask import Blueprint, render_template, request, jsonify, current_app
from backend.app.routes.dashboard import role_required

logger        = logging.getLogger(__name__)
risk_score_bp = Blueprint("risk_score_bp", __name__, url_prefix="/risk")

PROXY_TIMEOUT = 30


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@risk_score_bp.route("/")
@role_required("admin", "analyst")
def index():
    return render_template("risk_score.html")


# ── Manual aggregate (existing) ───────────────────────────────────────────────
@risk_score_bp.route("/aggregate", methods=["POST"])
@role_required("admin", "analyst")
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


# ── Auto aggregate (NEW) ──────────────────────────────────────────────────────
@risk_score_bp.route("/aggregate/auto", methods=["POST"])
@role_required("admin", "analyst")
def aggregate_auto():
    """
    Proxy to FastAPI /api/risk/aggregate/auto.
    No body required — backend pulls most recent scan per module automatically.
    Optional body: {"weights": {...}} to override default weights.
    """
    payload = request.get_json(silent=True) or {}
    try:
        resp = http_requests.post(
            f"{_api()}/api/risk/aggregate/auto",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Auto aggregation timed out"}), 504
    except Exception as ex:
        logger.error("Risk auto-aggregate proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Module status probe (NEW) ─────────────────────────────────────────────────
@risk_score_bp.route("/status", methods=["GET"])
@role_required("admin", "analyst")
def status():
    """
    Proxy to FastAPI /api/risk/status.
    Returns online/offline status + latest scan metadata for all six modules.
    Consumed by the auto-mode status grid in the frontend.
    """
    try:
        resp = http_requests.get(
            f"{_api()}/api/risk/status",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Risk status proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── History (existing) ────────────────────────────────────────────────────────
@risk_score_bp.route("/history")
@role_required("admin", "analyst")
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
@role_required("admin", "analyst")
def detail(record_id):
    try:
        resp = http_requests.get(
            f"{_api()}/api/risk/history/{record_id}",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502