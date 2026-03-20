"""
backend/app/routes/model_mgmt.py
Phase 12 — Model Management Flask blueprint
Variable name: model_mgmt_bp  |  url_prefix: /models

Access control: ALL routes in this blueprint require the 'admin' role.
Analysts and visitors receive a 403 via the role_required decorator.
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.routes.dashboard import role_required


logger        = logging.getLogger(__name__)
model_mgmt_bp = Blueprint(
    "model_mgmt_bp", __name__, url_prefix="/models"
)

PROXY_TIMEOUT = 120   # retraining can take time


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@model_mgmt_bp.route("/")
@role_required("admin")
def index():
    return render_template("model_mgmt.html")


# ── Feedback (submit POST + fetch queue GET — single endpoint, method dispatch)

@model_mgmt_bp.route("/feedback", methods=["GET", "POST"])
@role_required("admin")
def feedback():
    """
    GET  /models/feedback?limit=N  → returns the feedback queue
    POST /models/feedback           → submits a new feedback entry

    Merged into one view to avoid Flask endpoint name collision that
    occurred when submit_feedback and feedback_queue were registered
    separately on the same URL path.
    """
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        if not payload.get("url") or not payload.get("label_type"):
            return jsonify({
                "status":  "error",
                "message": "url and label_type are required."
            }), 400
        try:
            resp = http_requests.post(
                f"{_api()}/api/models/feedback",
                json=payload,
                timeout=15,
            )
            return jsonify(resp.json()), resp.status_code
        except Exception as ex:
            logger.error("Feedback proxy error: %s", ex)
            return jsonify({"status": "error", "message": str(ex)}), 502

    # GET — return feedback queue
    limit = request.args.get("limit", 50)
    try:
        resp = http_requests.get(
            f"{_api()}/api/models/feedback",
            params={"limit": limit},
            timeout=15,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Feedback queue proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Trigger retrain ───────────────────────────────────────────────────────────

@model_mgmt_bp.route("/retrain", methods=["POST"])
@role_required("admin")
def trigger_retrain():
    try:
        resp = http_requests.post(
            f"{_api()}/api/models/retrain",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Retrain timed out"}), 504
    except Exception as ex:
        logger.error("Retrain proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Training status / log ─────────────────────────────────────────────────────

@model_mgmt_bp.route("/retrain/status")
@role_required("admin")
def retrain_status():
    try:
        resp = http_requests.get(
            f"{_api()}/api/models/retrain/status",
            timeout=10,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Retrain status proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Model versions ────────────────────────────────────────────────────────────

@model_mgmt_bp.route("/versions")
@role_required("admin")
def model_versions():
    try:
        resp = http_requests.get(
            f"{_api()}/api/models/versions",
            timeout=15,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Model versions proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── HuggingFace fine-tune plan ────────────────────────────────────────────────

@model_mgmt_bp.route("/finetune-plan")
@role_required("admin")
def finetune_plan():
    try:
        resp = http_requests.get(
            f"{_api()}/api/models/finetune-plan",
            timeout=10,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Finetune plan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502