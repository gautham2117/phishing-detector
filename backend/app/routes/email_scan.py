# email_scan.py
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import EmailScan, URLScan
from backend.app.database import db
from backend.app.routes.dashboard import role_required

logger       = logging.getLogger(__name__)
email_scan_bp = Blueprint("email_scan", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@email_scan_bp.route("/email/scan", methods=["GET"])
@role_required("admin", "analyst")
def email_scan_page():
    recent_scans = (
        EmailScan.query
        .order_by(EmailScan.scanned_at.desc())
        .limit(10)
        .all()
    )
    return render_template("email_scan.html", recent_scans=recent_scans)


@email_scan_bp.route("/email/submit", methods=["POST"])
@role_required("admin", "analyst")
def submit_email():
    fastapi_base = _api()

    try:
        if "eml_file" in request.files:
            eml_file = request.files["eml_file"]
            if not eml_file.filename.endswith(".eml"):
                return jsonify({"error": "Only .eml files accepted"}), 400

            response = requests.post(
                f"{fastapi_base}/api/scan/email/upload",
                files={"file": (eml_file.filename, eml_file.read(), "message/rfc822")},
                data={"submitter": "dashboard_user"},
                timeout=60
            )
            return jsonify(response.json()), response.status_code

        elif request.is_json:
            data      = request.get_json()
            raw_email = data.get("raw_email", "").strip()
            if not raw_email:
                return jsonify({"error": "No email content provided"}), 400

            response = requests.post(
                f"{fastapi_base}/api/scan/email",
                json={"raw_email": raw_email, "submitter": "dashboard_user"},
                timeout=60
            )
            return jsonify(response.json()), response.status_code

        else:
            return jsonify({"error": "Send a .eml file or JSON with raw_email"}), 400

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI on port 8001"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "FastAPI timed out — try again in 30 seconds"}), 504
    except Exception as e:
        logger.error(f"Email submit error: {e}")
        return jsonify({"error": str(e)}), 500


@email_scan_bp.route("/email/history", methods=["GET"])
@role_required("admin", "analyst")
def email_history():
    scans = (
        EmailScan.query
        .order_by(EmailScan.scanned_at.desc())
        .limit(20)
        .all()
    )
    return jsonify([{
        "id":         s.id,
        "filename":   s.filename,
        "sender":     s.sender,
        "subject":    s.subject,
        "risk_score": s.risk_score,
        "label":      s.label,
        "scanned_at": s.scanned_at.isoformat() if s.scanned_at else ""
    } for s in scans])