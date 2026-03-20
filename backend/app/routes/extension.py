"""
backend/app/routes/extension.py
Phase 14 — Browser Extension & Integration Flask blueprint
Variable name: extension_bp  |  url_prefix: /extension
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.auth import role_required

logger       = logging.getLogger(__name__)
extension_bp = Blueprint("extension_bp", __name__, url_prefix="/extension")

PROXY_TIMEOUT = 30


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@extension_bp.route("/")
@role_required("admin", "analyst")
def index():
    return render_template("extension.html")


# ── Manual scan (from dashboard) ──────────────────────────────────────────────

@extension_bp.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    url     = payload.get("url", "").strip()
    if not url:
        return jsonify({"status": "error", "message": "URL is required"}), 400
    try:
        resp = http_requests.post(
            f"{_api()}/api/extension/scan",
            json={"url": url, "source": "dashboard"},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Scan timed out"}), 504
    except Exception as ex:
        logger.error("Extension scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── History ───────────────────────────────────────────────────────────────────

@extension_bp.route("/history")
@role_required("admin", "analyst")
def history():
    limit = request.args.get("limit", 50)
    try:
        resp = http_requests.get(
            f"{_api()}/api/extension/history",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Status ping ───────────────────────────────────────────────────────────────

@extension_bp.route("/status")
@role_required("admin", "analyst")
def status():
    try:
        resp = http_requests.get(
            f"{_api()}/api/extension/status",
            timeout=5,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"status": "offline"}), 200