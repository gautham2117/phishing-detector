"""
backend/app/routes/live_monitor.py
Phase 11 — Live Monitor Flask blueprint
Variable name: live_monitor_bp  |  url_prefix: /monitor
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

logger          = logging.getLogger(__name__)
live_monitor_bp = Blueprint(
    "live_monitor_bp", __name__, url_prefix="/monitor"
)

PROXY_TIMEOUT = 15


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@live_monitor_bp.route("/")
def index():
    return render_template("live_monitor.html")


# ── Feed ──────────────────────────────────────────────────────────────────────

@live_monitor_bp.route("/feed")
def feed():
    limit = request.args.get("limit", 100)
    try:
        resp = http_requests.get(
            f"{_api()}/api/monitor/feed",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Monitor feed proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Stats ─────────────────────────────────────────────────────────────────────

@live_monitor_bp.route("/stats")
def stats():
    try:
        resp = http_requests.get(
            f"{_api()}/api/monitor/stats",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Monitor stats proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Alerts ────────────────────────────────────────────────────────────────────

@live_monitor_bp.route("/alerts")
def alerts():
    threshold = request.args.get("threshold", 70.0, type=float)
    limit     = request.args.get("limit", 20, type=int)
    try:
        resp = http_requests.get(
            f"{_api()}/api/monitor/alerts",
            params={"threshold": threshold, "limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Monitor alerts proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502