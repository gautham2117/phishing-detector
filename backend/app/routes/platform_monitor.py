"""
backend/app/routes/platform_monitor.py
Phase 9 — Platform Monitor Flask blueprint
Variable name: platform_bp  |  url_prefix: /platform
"""

import json
import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

from backend.app.database import db
from backend.app.models   import MonitoredTarget, MonitorScanResult
from backend.app.auth import role_required

logger      = logging.getLogger(__name__)
platform_bp = Blueprint("platform_bp", __name__, url_prefix="/platform")

PROXY_TIMEOUT = 90


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@platform_bp.route("/")
@role_required("admin", "analyst")

def index():
    return render_template("platform_monitor.html")


# ── Add target ────────────────────────────────────────────────────────────────

@platform_bp.route("/targets/add", methods=["POST"])
@role_required("admin", "analyst")
def add_target():
    payload = request.get_json(silent=True) or {}
    if not payload.get("url"):
        return jsonify({"status": "error", "message": "URL is required"}), 400
    try:
        resp = http_requests.post(
            f"{_api()}/api/platform/targets",
            json=payload, timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Add target proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Remove target ─────────────────────────────────────────────────────────────

@platform_bp.route("/targets/<int:target_id>/remove", methods=["DELETE"])
@role_required("admin", "analyst")
def remove_target(target_id):
    try:
        resp = http_requests.delete(
            f"{_api()}/api/platform/targets/{target_id}",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Remove target proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Manual scan ───────────────────────────────────────────────────────────────

@platform_bp.route("/targets/<int:target_id>/scan", methods=["POST"])
@role_required("admin", "analyst")
def manual_scan(target_id):
    try:
        resp = http_requests.post(
            f"{_api()}/api/platform/targets/{target_id}/scan",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Scan timed out"}), 504
    except Exception as ex:
        logger.error("Manual scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── List targets ──────────────────────────────────────────────────────────────

@platform_bp.route("/targets")
@role_required("admin", "analyst")
def list_targets():
    try:
        resp = http_requests.get(
            f"{_api()}/api/platform/targets",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Target scan history ───────────────────────────────────────────────────────

@platform_bp.route("/targets/<int:target_id>/history")
@role_required("admin", "analyst")

def target_history(target_id):
    limit = request.args.get("limit", 20)
    try:
        resp = http_requests.get(
            f"{_api()}/api/platform/targets/{target_id}/history",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Unified feed ──────────────────────────────────────────────────────────────

@platform_bp.route("/feed")
@role_required("admin", "analyst")
def unified_feed():
    limit = request.args.get("limit", 50)
    try:
        resp = http_requests.get(
            f"{_api()}/api/platform/feed",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Poll due targets ──────────────────────────────────────────────────────────

@platform_bp.route("/poll", methods=["POST"])
@role_required("admin", "analyst")

def poll():
    try:
        resp = http_requests.post(
            f"{_api()}/api/platform/poll",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Poll timed out"}), 504
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502