# url_intel.py
# Flask Blueprint for the URL Intelligence dashboard page.

import json
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import URLScan
from backend.app.database import db

logger = logging.getLogger(__name__)
url_intel_bp = Blueprint("url_intel", __name__)


def _fastapi_url():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@url_intel_bp.route("/url/intel", methods=["GET"])
def url_intel_page():
    """Render the URL Intelligence dashboard page."""
    recent = (
        URLScan.query
        .order_by(URLScan.scanned_at.desc())
        .limit(15)
        .all()
    )
    return render_template("url_intel.html", recent_scans=recent)


@url_intel_bp.route("/url/submit", methods=["POST"])
def submit_url():
    """
    Proxy a single URL scan to FastAPI.
    Called by the URL intelligence page's scan form.
    """
    data = request.get_json()
    url  = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        resp = requests.post(
            f"{_fastapi_url()}/api/scan/url",
            json={"url": url, "submitter": "dashboard_user"},
            timeout=90    # URL analysis with WHOIS/DNS/redirects can take ~30s
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI service"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Scan timed out — WHOIS/DNS queries may be slow"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@url_intel_bp.route("/url/submit/batch", methods=["POST"])
def submit_url_batch():
    """
    Proxy a batch URL scan (called after an email scan to analyze all its URLs).
    Accepts: {"urls": [...], "email_scan_id": int}
    """
    data         = request.get_json() or {}
    urls         = data.get("urls", [])
    email_scan_id = data.get("email_scan_id")

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    try:
        resp = requests.post(
            f"{_fastapi_url()}/api/scan/url/batch",
            json=urls,
            params={"email_scan_id": email_scan_id} if email_scan_id else {},
            timeout=120
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.Timeout:
        return jsonify({"error": "Batch scan timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@url_intel_bp.route("/url/history", methods=["GET"])
def url_history():
    """Return the 20 most recent URL scans as JSON (for live polling)."""
    scans = (
        URLScan.query
        .order_by(URLScan.scanned_at.desc())
        .limit(20)
        .all()
    )
    return jsonify([{
        "id":             s.id,
        "domain":         s.domain,
        "raw_url":        s.raw_url,
        "ip_address":     s.ip_address,
        "country":        s.country,
        "domain_age_days":s.domain_age_days,
        "ssl_valid":      s.ssl_valid,
        "ml_score":       s.ml_score,
        "final_label":    s.final_label,
        "scanned_at":     s.scanned_at.isoformat() if s.scanned_at else ""
    } for s in scans])


@url_intel_bp.route("/url/detail/<int:scan_id>", methods=["GET"])
def url_detail(scan_id: int):
    """Return full scan data for a specific URL scan (used by detail modal)."""
    scan = URLScan.query.get_or_404(scan_id)
    return jsonify({
        "id":             scan.id,
        "raw_url":        scan.raw_url,
        "domain":         scan.domain,
        "ip_address":     scan.ip_address,
        "country":        scan.country,
        "whois_data":     json.loads(scan.whois_data or "{}"),
        "domain_age_days":scan.domain_age_days,
        "ssl_valid":      scan.ssl_valid,
        "ssl_issuer":     scan.ssl_issuer,
        "redirect_chain": json.loads(scan.redirect_chain or "[]"),
        "ml_score":       scan.ml_score,
        "final_label":    scan.final_label,
        "scanned_at":     scan.scanned_at.isoformat() if scan.scanned_at else ""
    })