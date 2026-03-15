# email_scan.py
# Flask Blueprint for the Email Scan dashboard page.
#
# Flask's job here is:
#   1. Render the email_scan.html template (GET /)
#   2. Proxy file uploads from the browser to FastAPI (POST /submit)
#   3. Serve the scan history from the database
#
# The actual detection logic lives in FastAPI.
# Flask is purely the web/UI layer.

import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import EmailScan, URLScan
from backend.app.database import db

logger = logging.getLogger(__name__)

email_scan_bp = Blueprint("email_scan", __name__)

# The FastAPI service URL — reads from app config
def _fastapi_url():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@email_scan_bp.route("/email/scan", methods=["GET"])
def email_scan_page():
    """
    Render the Email Scan dashboard page.
    Passes the 10 most recent scans to the template for the history table.
    """
    recent_scans = (
        EmailScan.query
        .order_by(EmailScan.scanned_at.desc())
        .limit(10)
        .all()
    )
    return render_template("email_scan.html", recent_scans=recent_scans)


@email_scan_bp.route("/email/submit", methods=["POST"])
def submit_email():
    """
    Proxy endpoint: receives the scan form from the browser
    and forwards it to FastAPI for processing.

    Why proxy? The browser can't call FastAPI directly because of CORS
    restrictions in production. Flask acts as a secure middleman.

    Handles both:
      - File upload (multipart/form-data with .eml file)
      - Raw text paste (JSON body with raw_email field)
    """
    fastapi_base = _fastapi_url()

    try:
        # ── File upload path ──
        if "eml_file" in request.files:
            eml_file = request.files["eml_file"]

            if not eml_file.filename.endswith(".eml"):
                return jsonify({"error": "Only .eml files accepted"}), 400

            # Forward the file to FastAPI using the requests library
            response = requests.post(
                f"{fastapi_base}/api/scan/email/upload",
                files={"file": (eml_file.filename, eml_file.read(), "message/rfc822")},
                data={"submitter": "dashboard_user"},
                timeout=60  # scanning can take time with ML models
            )
            return jsonify(response.json()), response.status_code

        # ── Raw text paste path ──
        elif request.is_json:
            data = request.get_json()
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
            return jsonify({"error": "Send either a .eml file or JSON with raw_email"}), 400

    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Cannot connect to FastAPI service. Is it running on port 8001?"
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "error": "FastAPI timed out. ML models may still be loading — try again in 30 seconds."
        }), 504
    except Exception as e:
        logger.error(f"Email submit proxy error: {e}")
        return jsonify({"error": str(e)}), 500


@email_scan_bp.route("/email/history", methods=["GET"])
def email_history():
    """
    Return the last 20 email scans as JSON.
    Called by the dashboard's auto-refresh JavaScript every 5 seconds.
    """
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