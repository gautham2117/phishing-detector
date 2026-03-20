"""
backend/app/routes/alerts.py
Phase 13 — Alerts & Audit Flask blueprint
Variable name: alerts_bp  |  url_prefix: /alerts
"""

import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app, Response
)
from backend.app.routes.dashboard import role_required

logger    = logging.getLogger(__name__)
alerts_bp = Blueprint("alerts_bp", __name__, url_prefix="/alerts")

PROXY_TIMEOUT = 60


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@alerts_bp.route("/")
@role_required("admin", "analyst")
def index():
    return render_template("alerts.html")


# ── List alerts ───────────────────────────────────────────────────────────────

@alerts_bp.route("/list")
@role_required("admin", "analyst")
def list_alerts():
    params = {
        k: request.args.get(k)
        for k in ("severity", "module", "status",
                  "date_from", "date_to", "limit")
        if request.args.get(k)
    }
    try:
        resp = http_requests.get(
            f"{_api()}/api/alerts",
            params=params,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("List alerts proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Alert stats ───────────────────────────────────────────────────────────────

@alerts_bp.route("/stats")
@role_required("admin", "analyst") 
def stats():
    try:
        resp = http_requests.get(
            f"{_api()}/api/alerts/stats",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Alert detail ──────────────────────────────────────────────────────────────

@alerts_bp.route("/<int:alert_id>")
@role_required("admin", "analyst")
def alert_detail(alert_id):
    try:
        resp = http_requests.get(
            f"{_api()}/api/alerts/{alert_id}",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Create alert (manual) ─────────────────────────────────────────────────────

@alerts_bp.route("/create", methods=["POST"])
@role_required("admin", "analyst")
def create_alert():
    payload = request.get_json(silent=True) or {}
    try:
        resp = http_requests.post(
            f"{_api()}/api/alerts",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        logger.error("Create alert proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Acknowledge ───────────────────────────────────────────────────────────────

@alerts_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@role_required("admin", "analyst")
def acknowledge(alert_id):
    payload = request.get_json(silent=True) or {}
    try:
        resp = http_requests.post(
            f"{_api()}/api/alerts/{alert_id}/acknowledge",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Dismiss ───────────────────────────────────────────────────────────────────

@alerts_bp.route("/<int:alert_id>/dismiss", methods=["POST"])
@role_required("admin", "analyst")
def dismiss(alert_id):
    payload = request.get_json(silent=True) or {}
    try:
        resp = http_requests.post(
            f"{_api()}/api/alerts/{alert_id}/dismiss",
            json=payload,
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Export CSV ────────────────────────────────────────────────────────────────

@alerts_bp.route("/export/csv")
@role_required("admin", "analyst")

def export_csv():
    params = {
        k: request.args.get(k)
        for k in ("severity", "module", "status", "date_from", "date_to")
        if request.args.get(k)
    }
    try:
        resp = http_requests.get(
            f"{_api()}/api/alerts/export/csv",
            params=params,
            timeout=PROXY_TIMEOUT,
            stream=True,
        )
        cd = resp.headers.get(
            "Content-Disposition",
            "attachment; filename=alerts.csv"
        )
        return Response(
            resp.content,
            mimetype="text/csv",
            headers={"Content-Disposition": cd},
        )
    except Exception as ex:
        logger.error("CSV export proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Export PDF ────────────────────────────────────────────────────────────────

@alerts_bp.route("/<int:alert_id>/export/pdf")
@role_required("admin", "analyst")
def export_pdf(alert_id):
    try:
        resp = http_requests.get(
            f"{_api()}/api/alerts/{alert_id}/export/pdf",
            timeout=PROXY_TIMEOUT,
            stream=True,
        )
        ct = resp.headers.get("Content-Type", "application/pdf")
        cd = resp.headers.get(
            "Content-Disposition",
            f"attachment; filename=alert_{alert_id}_report.pdf"
        )
        return Response(
            resp.content,
            mimetype=ct,
            headers={"Content-Disposition": cd},
        )
    except Exception as ex:
        logger.error("PDF export proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── Audit log ─────────────────────────────────────────────────────────────────

@alerts_bp.route("/audit")
@role_required("admin")
def audit_log():
    limit = request.args.get("limit", 100)
    try:
        resp = http_requests.get(
            f"{_api()}/api/audit/log",
            params={"limit": limit},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502