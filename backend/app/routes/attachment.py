"""
backend/app/routes/attachment.py
Phase 6 — Attachment Analysis Flask blueprint
Proxies analysis to FastAPI; saves results to AttachmentScan table.
"""

import json
import datetime

import requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)

from backend.app.database import db
from backend.app.models   import AttachmentScan

bp = Blueprint("attachment_bp", __name__, url_prefix="/attachments")

FASTAPI_FILE_URL = "http://127.0.0.1:8001/api/scan/file"
PROXY_TIMEOUT    = 30   # file uploads may be larger → longer timeout


# ── Page render ────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return render_template("attachment.html")


# ── File scan endpoint ─────────────────────────────────────────────────────────

@bp.route("/scan", methods=["POST"])
def scan_attachment():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"status": "error", "message": "No file provided"}), 400

    filename      = uploaded.filename
    file_bytes    = uploaded.read()
    email_scan_id = request.form.get("email_scan_id", "")

    # ── Forward to FastAPI ──
    try:
        form_data = {}
        if email_scan_id:
            form_data["email_scan_id"] = email_scan_id

        resp = requests.post(
            FASTAPI_FILE_URL,
            files={"file": (filename, file_bytes, uploaded.content_type or "application/octet-stream")},
            data=form_data,
            timeout=PROXY_TIMEOUT,
        )
        resp.raise_for_status()
        api_data = resp.json()
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Analysis service timed out"}), 504
    except Exception as ex:
        return jsonify({"status": "error", "message": f"FastAPI error: {str(ex)[:120]}"}), 502

    # ── Persist to DB ──
    try:
        mod = api_data.get("module_results", {})
        hashes = mod.get("hashes", {})

        record = AttachmentScan(
            email_id     = int(email_scan_id) if email_scan_id and email_scan_id.isdigit() else None,
            filename     = filename,
            file_type    = mod.get("file_type", ""),
            md5          = hashes.get("md5", ""),
            sha256       = hashes.get("sha256", ""),
            file_size    = mod.get("file_size", 0),
            entropy      = mod.get("entropy", 0.0),
            yara_matches = json.dumps(mod.get("yara_matches", [])),
            static_finds = json.dumps(mod.get("suspicious_strings", [])),
            verdict      = mod.get("verdict", "CLEAN"),
            scanned_at   = datetime.datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        api_data["db_id"] = record.id
    except Exception as db_err:
        db.session.rollback()
        current_app.logger.error("AttachmentScan DB save failed: %s", db_err)
        api_data["db_id"] = None

    return jsonify(api_data)


# ── History endpoint (polled by JS every 5 s) ──────────────────────────────────

@bp.route("/history")
def history():
    try:
        limit   = int(request.args.get("limit", 20))
        records = (
            AttachmentScan.query
            .order_by(AttachmentScan.scanned_at.desc())
            .limit(limit)
            .all()
        )
        rows = []
        for r in records:
            rows.append({
                "id":         r.id,
                "filename":   r.filename,
                "file_type":  r.file_type,
                "md5":        r.md5,
                "sha256":     r.sha256,
                "file_size":  r.file_size,
                "entropy":    r.entropy,
                "verdict":    r.verdict,
                "yara_matches": json.loads(r.yara_matches) if r.yara_matches else [],
                "static_finds": json.loads(r.static_finds) if r.static_finds else [],
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "email_id":   r.email_id,
            })
        return jsonify({"status": "success", "scans": rows})
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500


# ── Single scan detail ─────────────────────────────────────────────────────────

@bp.route("/detail/<int:scan_id>")
def detail(scan_id):
    try:
        r = AttachmentScan.query.get_or_404(scan_id)
        return jsonify({
            "id":           r.id,
            "filename":     r.filename,
            "file_type":    r.file_type,
            "md5":          r.md5,
            "sha256":       r.sha256,
            "file_size":    r.file_size,
            "entropy":      r.entropy,
            "verdict":      r.verdict,
            "yara_matches": json.loads(r.yara_matches) if r.yara_matches else [],
            "static_finds": json.loads(r.static_finds) if r.static_finds else [],
            "scanned_at":   r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "email_id":     r.email_id,
        })
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 500