# attachment.py
# Flask Blueprint for the Attachment Analysis dashboard page.
# Phase 6 — File & Attachment Analysis Module.
#
# Responsibilities:
#   - Render the Attachment Analysis dashboard page
#   - Proxy file uploads from the browser to FastAPI /api/scan/file
#   - Serve scan history from the AttachmentScan database table
#   - Handle both single file and batch file uploads

import json
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import AttachmentScan
from backend.app.database import db

logger = logging.getLogger(__name__)

# Blueprint variable name must match what __init__.py imports
attachment_bp = Blueprint("attachment_bp", __name__)


def _api():
    """Return the FastAPI base URL from Flask config."""
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard page
# ─────────────────────────────────────────────────────────────────────────────

@attachment_bp.route("/attachments", methods=["GET"])
def attachment_page():
    """
    Render the Attachment Analysis dashboard page.
    Pre-loads the 15 most recent attachment scans for the history table.
    """
    recent = (
        AttachmentScan.query
        .order_by(AttachmentScan.scanned_at.desc())
        .limit(15)
        .all()
    )
    return render_template("attachment.html", recent_scans=recent)


# ─────────────────────────────────────────────────────────────────────────────
# Single file upload proxy
# ─────────────────────────────────────────────────────────────────────────────

@attachment_bp.route("/attachments/submit", methods=["POST"])
def submit_attachment():
    """
    Proxy a single file upload to FastAPI /api/scan/file.
    Called by the attachment dashboard's upload form.

    Accepts multipart/form-data with:
      - file:          the attachment file
      - email_scan_id: optional int linking to a parent EmailScan
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided in the request"}), 400

    upload_file   = request.files["file"]
    email_scan_id = request.form.get("email_scan_id", None)

    if upload_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        # Forward the file to FastAPI using requests
        # requests.post with files= handles multipart encoding automatically
        files_payload = {
            "file": (
                upload_file.filename,
                upload_file.read(),
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
            # File analysis with YARA + entropy can take time
            timeout=90
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Cannot connect to FastAPI service. Is it running on port 8001?"
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "error": "File analysis timed out. Large files may take longer."
        }), 504
    except Exception as e:
        logger.error(f"Attachment submit proxy error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Batch file upload proxy
# ─────────────────────────────────────────────────────────────────────────────

@attachment_bp.route("/attachments/submit/batch", methods=["POST"])
def submit_attachment_batch():
    """
    Proxy multiple file uploads to FastAPI /api/scan/file/batch.
    Called when an email scan has multiple attachments to analyze.

    Accepts multipart/form-data with:
      - files:          multiple file fields
      - email_scan_id:  optional int linking to parent EmailScan
    """
    uploaded_files = request.files.getlist("files")
    email_scan_id  = request.form.get("email_scan_id", None)

    if not uploaded_files:
        return jsonify({"error": "No files provided"}), 400

    if len(uploaded_files) > 10:
        return jsonify({"error": "Maximum 10 files per batch"}), 400

    try:
        # Build multipart payload with all files
        files_payload = [
            (
                "files",
                (
                    f.filename,
                    f.read(),
                    f.content_type or "application/octet-stream"
                )
            )
            for f in uploaded_files
            if f.filename
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
        return jsonify({"error": "Batch file analysis timed out"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI service"}), 503
    except Exception as e:
        logger.error(f"Batch attachment proxy error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# History endpoint — polled every 5 seconds by the dashboard JS
# ─────────────────────────────────────────────────────────────────────────────

@attachment_bp.route("/attachments/history", methods=["GET"])
def attachment_history():
    """
    Return the 20 most recent attachment scans as JSON.
    Called by attachment.js every 5 seconds for live table updates.
    """
    scans = (
        AttachmentScan.query
        .order_by(AttachmentScan.scanned_at.desc())
        .limit(20)
        .all()
    )
    return jsonify([{
        "id":           s.id,
        "filename":     s.filename,
        "file_type":    s.file_type,
        "md5":          s.md5,
        "sha256":       s.sha256,
        "file_size":    s.file_size,
        "entropy":      s.entropy,
        "yara_matches": json.loads(s.yara_matches or "[]"),
        "verdict":      s.verdict,
        "scanned_at":   s.scanned_at.isoformat() if s.scanned_at else ""
    } for s in scans])


# ─────────────────────────────────────────────────────────────────────────────
# Detail endpoint — returns full data for one scan
# ─────────────────────────────────────────────────────────────────────────────

@attachment_bp.route("/attachments/detail/<int:scan_id>", methods=["GET"])
def attachment_detail(scan_id: int):
    """
    Return the full analysis data for a specific attachment scan.
    Used by the detail drawer on the dashboard page.
    """
    scan = AttachmentScan.query.get_or_404(scan_id)
    return jsonify({
        "id":           scan.id,
        "filename":     scan.filename,
        "file_type":    scan.file_type,
        "md5":          scan.md5,
        "sha256":       scan.sha256,
        "file_size":    scan.file_size,
        "entropy":      scan.entropy,
        "yara_matches": json.loads(scan.yara_matches or "[]"),
        "static_finds": json.loads(scan.static_finds or "[]"),
        "verdict":      scan.verdict,
        "scanned_at":   scan.scanned_at.isoformat() if scan.scanned_at else ""
    })