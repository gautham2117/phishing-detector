"""
backend/app/routes/ai_detection.py
Phase 8 — AI-Generated Content Detection Flask blueprint
Variable name must be `ai_bp` to match __init__.py expectation.
URL prefix must be `/ai` so routes resolve to /ai/detection/...
"""

import json
import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

from backend.app.database import db
from backend.app.models   import AIDetectionScan
from backend.app.auth import role_required

logger = logging.getLogger(__name__)
ai_bp  = Blueprint("ai_bp", __name__, url_prefix="/ai")

PROXY_TIMEOUT = 60


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@ai_bp.route("/detection")
@role_required("admin", "analyst")
def index():
    return render_template("ai_detection.html")


# ── Text scan ─────────────────────────────────────────────────────────────────

@ai_bp.route("/detection/scan/text", methods=["POST"])
@role_required("admin", "analyst")
def scan_text():
    payload    = request.get_json(silent=True) or {}
    text       = payload.get("text", "").strip()
    source_ref = payload.get("source_ref", "")

    if not text:
        return jsonify({"status": "error", "message": "No text provided"}), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/scan/ai/text",
            json={"text": text, "source_ref": source_ref},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Detection timed out"}), 504
    except Exception as ex:
        logger.error("AI text scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── URL scan ──────────────────────────────────────────────────────────────────

@ai_bp.route("/detection/scan/url", methods=["POST"])
@role_required("admin", "analyst")
def scan_url():
    payload = request.get_json(silent=True) or {}
    url     = payload.get("url", "").strip()

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/scan/ai/url",
            json={"url": url},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "URL fetch timed out"}), 504
    except Exception as ex:
        logger.error("AI URL scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── File scan ─────────────────────────────────────────────────────────────────

@ai_bp.route("/detection/scan/file", methods=["POST"])
@role_required("admin", "analyst")
def scan_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"status": "error", "message": "No file provided"}), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/scan/ai/file",
            files={"file": (
                uploaded.filename,
                uploaded.read(),
                uploaded.content_type or "application/octet-stream",
            )},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "File scan timed out"}), 504
    except Exception as ex:
        logger.error("AI file scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── History ───────────────────────────────────────────────────────────────────

@ai_bp.route("/detection/history")
@role_required("admin", "analyst")
def history():
    try:
        limit   = int(request.args.get("limit", 20))
        records = (
            AIDetectionScan.query
            .order_by(AIDetectionScan.scanned_at.desc())
            .limit(limit)
            .all()
        )
        rows = []
        for r in records:
            rows.append({
                "id":             r.id,
                "input_type":     r.input_type,
                "source_ref":     r.source_ref,
                "input_preview":  r.input_preview,
                "char_count":     r.char_count,
                "sentence_count": r.sentence_count,
                "ai_probability": r.ai_probability,
                "verdict":        r.verdict,
                "risk_score":     r.risk_score,
                "scanned_at":     r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
        return jsonify({"status": "success", "scans": rows})
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500


# ── Detail ────────────────────────────────────────────────────────────────────

@ai_bp.route("/detection/detail/<int:scan_id>")
@role_required("admin", "analyst")
def detail(scan_id):
    try:
        r = AIDetectionScan.query.get_or_404(scan_id)
        return jsonify({
            "id":              r.id,
            "input_type":      r.input_type,
            "source_ref":      r.source_ref,
            "input_preview":   r.input_preview,
            "char_count":      r.char_count,
            "sentence_count":  r.sentence_count,
            "ai_probability":  r.ai_probability,
            "verdict":         r.verdict,
            "risk_score":      r.risk_score,
            "sentence_scores": json.loads(r.sentence_scores or "[]"),
            "scanned_at":      r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
        })
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500