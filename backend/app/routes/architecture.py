"""
backend/app/routes/architecture.py
Phase 15 — System Architecture Flask blueprint
Variable name: architecture_bp  |  url_prefix: /architecture
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.auth import role_required

logger           = logging.getLogger(__name__)
architecture_bp  = Blueprint(
    "architecture_bp", __name__, url_prefix="/architecture"
)

PROXY_TIMEOUT = 30


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@architecture_bp.route("/")
@role_required("admin")
def index():
    return render_template("architecture.html")


# ── Health ────────────────────────────────────────────────────────────────────

@architecture_bp.route("/health")
@role_required("admin")
def health():
    try:
        resp = http_requests.get(
            f"{_api()}/api/architecture/health",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Health proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Metrics ───────────────────────────────────────────────────────────────────

@architecture_bp.route("/metrics")
@role_required("admin")
def metrics():
    try:
        resp = http_requests.get(
            f"{_api()}/api/architecture/metrics",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Metrics proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Migration plan ────────────────────────────────────────────────────────────

@architecture_bp.route("/migration-plan")
@role_required("admin")
def migration_plan():
    try:
        resp = http_requests.get(
            f"{_api()}/api/architecture/migration-plan",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502