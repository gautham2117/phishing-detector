# backend/app/routes/attachment.py
# Phase 6 — Attachment Analysis Flask blueprint
# url_prefix="/attachments" is set on the Blueprint constructor.
#
# FIXES IN THIS VERSION:
#   1. attachment_history() — was returning a raw list [{},...].
#      JS loadHistory() checks data.status === "success" and reads
#      data.scans — so a raw list caused the history to never render.
#      Fixed: now returns {"status": "success", "scans": [...], "total": n}
#
#   2. attachment_history() — was reading s.static_finds (DB column) and
#      serialising it as "static_finds". Now also returns "verdict_reasons"
#      and "risk_flags" so the detail panel can show them.
#
#   3. attachment_detail() — same static_finds → static_findings rename
#      + added risk_flags and verdict_reasons fields.

import json
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import AttachmentScan
from backend.app.database import db
from backend.app.auth import role_required


logger        = logging.getLogger(__name__)
attachment_bp = Blueprint("attachment_bp", __name__, url_prefix="/attachments")


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ── Page ──────────────────────────────────────────────────────────────────────

@attachment_bp.route("/")
@role_required("admin", "analyst")
def attachment_page():
    recent = (
        AttachmentScan.query
        .order_by(AttachmentScan.scanned_at.desc())
        .limit(15)
        .all()
    )
    return render_template("attachment.html", recent_scans=recent)


# ── Single file scan ──────────────────────────────────────────────────────────

@attachment_bp.route("/scan", methods=["POST"])
@role_required("admin", "analyst")
def submit_attachment():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    upload_file   = request.files["file"]
    email_scan_id = request.form.get("email_scan_id", None)

    if upload_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        # Read file bytes once — the stream can only be consumed once
        file_bytes = upload_file.read()

        files_payload = {
            "file": (
                upload_file.filename,
                file_bytes,
                upload_file.content_type or "application/octet-stream"
            )
        }
        data_payload = {}
        if email_scan_id:
            data_payload["email_scan_id"] = email_scan_id

        resp = requests.post(
            f"{_api()}/api/scan/file",
            files=files_payload,
            data=data_payload,
            timeout=45
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI backend"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "File analysis timed out (>90s)"}), 504
    except Exception as e:
        logger.error("Attachment submit error: %s", e, exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Batch scan ────────────────────────────────────────────────────────────────

@attachment_bp.route("/scan/batch", methods=["POST"])
@role_required("admin", "analyst")
def submit_attachment_batch():
    uploaded_files = request.files.getlist("files")
    email_scan_id  = request.form.get("email_scan_id", None)

    if not uploaded_files:
        return jsonify({"error": "No files provided"}), 400
    if len(uploaded_files) > 10:
        return jsonify({"error": "Maximum 10 files per batch"}), 400

    try:
        files_payload = [
            ("files", (f.filename, f.read(),
             f.content_type or "application/octet-stream"))
            for f in uploaded_files if f.filename
        ]
        data_payload = {}
        if email_scan_id:
            data_payload["email_scan_id"] = email_scan_id

        resp = requests.post(
            f"{_api()}/api/scan/file/batch",
            files=files_payload,
            data=data_payload,
            timeout=180
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.Timeout:
        return jsonify({"error": "Batch analysis timed out"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI backend"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── History ───────────────────────────────────────────────────────────────────
# FIX: was returning a raw list [] — JS expects {status, scans, total}

@attachment_bp.route("/history", methods=["GET"])
@role_required("admin", "analyst")
def attachment_history():
    limit = min(int(request.args.get("limit", 20)), 100)
    scans = (
        AttachmentScan.query
        .order_by(AttachmentScan.scanned_at.desc())
        .limit(limit)
        .all()
    )

    def _safe_json(val):
        """Safely parse a JSON column that may be None or already a list."""
        if val is None:
            return []
        if isinstance(val, (list, dict)):
            return val
        try:
            return json.loads(val)
        except Exception:
            return []

    records = []
    for s in scans:
        records.append({
            "id":             s.id,
            "filename":       s.filename,
            "file_type":      s.file_type     or "unknown",
            "md5":            s.md5           or "",
            "sha256":         s.sha256        or "",
            "file_size":      s.file_size     or 0,
            "entropy":        float(s.entropy or 0.0),
            "yara_matches":   _safe_json(s.yara_matches),
            # DB column is "static_finds" — expose as both keys for JS
            "static_findings":_safe_json(s.static_finds),
            "verdict":        s.verdict       or "UNKNOWN",
            "scanned_at":     s.scanned_at.isoformat() + "Z" if s.scanned_at else "",
        })

    # FIX: wrap in the envelope the JS expects
    return jsonify({
        "status": "success",
        "scans":  records,
        "total":  len(records)
    })


# ── Detail ────────────────────────────────────────────────────────────────────

@attachment_bp.route("/detail/<int:scan_id>", methods=["GET"])
@role_required("admin", "analyst")
def attachment_detail(scan_id: int):
    scan = AttachmentScan.query.get_or_404(scan_id)

    def _safe_json(val):
        if val is None:
            return []
        if isinstance(val, (list, dict)):
            return val
        try:
            return json.loads(val)
        except Exception:
            return []

    return jsonify({
        "id":              scan.id,
        "filename":        scan.filename,
        "file_type":       scan.file_type      or "unknown",
        "md5":             scan.md5            or "",
        "sha256":          scan.sha256         or "",
        "file_size":       scan.file_size      or 0,
        "entropy":         float(scan.entropy  or 0.0),
        "yara_matches":    _safe_json(scan.yara_matches),
        "static_findings": _safe_json(scan.static_finds),
        "verdict":         scan.verdict        or "UNKNOWN",
        "scanned_at":      scan.scanned_at.isoformat() + "Z" if scan.scanned_at else "",
    })