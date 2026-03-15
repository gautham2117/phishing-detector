"""
backend/app/routes/image_analysis.py
Phase 7 — Image Analysis Flask blueprint
Variable name must be `image_bp` to match __init__.py expectation.
"""

import json
import logging

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

from backend.app.database import db
from backend.app.models   import ImageAnalysisScan

logger   = logging.getLogger(__name__)
image_bp = Blueprint("image_bp", __name__, url_prefix="/image")

PROXY_TIMEOUT = 60


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@image_bp.route("/analysis")
def index():
    return render_template("image_analysis.html")


# ── Image scan ────────────────────────────────────────────────────────────────

@image_bp.route("/analysis/scan", methods=["POST"])
def scan_image():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"status": "error", "message": "No file provided"}), 400

    allowed_ext = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
    import os
    ext = os.path.splitext(uploaded.filename)[1].lower()
    if ext not in allowed_ext:
        return jsonify({
            "status":  "error",
            "message": f"Unsupported file type '{ext}'. "
                       f"Allowed: PNG, JPG, GIF, BMP, WEBP."
        }), 400

    try:
        resp = http_requests.post(
            f"{_api()}/api/scan/image",
            files={"file": (
                uploaded.filename,
                uploaded.read(),
                uploaded.content_type or "application/octet-stream",
            )},
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code

    except http_requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Analysis timed out"}), 504
    except http_requests.exceptions.ConnectionError:
        return jsonify({"status": "error", "message": "Cannot connect to FastAPI"}), 503
    except Exception as ex:
        logger.error("Image scan proxy error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 502


# ── History ───────────────────────────────────────────────────────────────────

@image_bp.route("/analysis/history")
def history():
    try:
        limit   = int(request.args.get("limit", 20))
        records = (
            ImageAnalysisScan.query
            .order_by(ImageAnalysisScan.scanned_at.desc())
            .limit(limit)
            .all()
        )
        rows = []
        for r in records:
            rows.append({
                "id":               r.id,
                "filename":         r.filename,
                "file_size":        r.file_size,
                "image_width":      r.image_width,
                "image_height":     r.image_height,
                "image_format":     r.image_format,
                "ocr_word_count":   r.ocr_word_count,
                "detected_brands":  json.loads(r.detected_brands  or "[]"),
                "phishing_keywords":json.loads(r.phishing_keywords or "[]"),
                "classifier_label": r.classifier_label,
                "classifier_score": r.classifier_score,
                "verdict":          r.verdict,
                "risk_score":       r.risk_score,
                "scanned_at":       r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
        return jsonify({"status": "success", "scans": rows})
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500


# ── Detail ────────────────────────────────────────────────────────────────────

@image_bp.route("/analysis/detail/<int:scan_id>")
def detail(scan_id):
    try:
        r = ImageAnalysisScan.query.get_or_404(scan_id)
        return jsonify({
            "id":               r.id,
            "filename":         r.filename,
            "file_size":        r.file_size,
            "image_width":      r.image_width,
            "image_height":     r.image_height,
            "image_format":     r.image_format,
            "ocr_text":         r.ocr_text,
            "ocr_word_count":   r.ocr_word_count,
            "detected_brands":  json.loads(r.detected_brands  or "[]"),
            "phishing_keywords":json.loads(r.phishing_keywords or "[]"),
            "classifier_label": r.classifier_label,
            "classifier_score": r.classifier_score,
            "verdict":          r.verdict,
            "risk_score":       r.risk_score,
            "scanned_at":       r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
        })
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500