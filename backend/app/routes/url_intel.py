# url_intel.py
import json
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import URLScan
from backend.app.database import db
from backend.app.routes.dashboard import role_required

logger       = logging.getLogger(__name__)
url_intel_bp = Blueprint("url_intel", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@url_intel_bp.route("/url/intel", methods=["GET"])
@role_required("admin", "analyst")
def url_intel_page():
    recent = (
        URLScan.query
        .order_by(URLScan.scanned_at.desc())
        .limit(15)
        .all()
    )
    return render_template("url_intel.html", recent_scans=recent)


@url_intel_bp.route("/url/submit", methods=["POST"])
@role_required("admin", "analyst")
def submit_url():
    data = request.get_json() or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        resp = requests.post(
            f"{_api()}/api/scan/url",
            json={"url": url, "submitter": "dashboard_user"},
            timeout=120
        )
        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Scan timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@url_intel_bp.route("/url/submit/batch", methods=["POST"])
@role_required("admin", "analyst")
def submit_url_batch():
    data          = request.get_json() or {}
    urls          = data.get("urls", [])
    email_scan_id = data.get("email_scan_id")

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    try:
        resp = requests.post(
            f"{_api()}/api/scan/url/batch",
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
@role_required("admin", "analyst")
def url_history():
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
@role_required("admin", "analyst")
def url_detail(scan_id: int):
    import json as _json
    scan = URLScan.query.get_or_404(scan_id)
    return jsonify({
        "id":             scan.id,
        "raw_url":        scan.raw_url,
        "domain":         scan.domain,
        "ip_address":     scan.ip_address,
        "country":        scan.country,
        "whois_data":     _json.loads(scan.whois_data or "{}"),
        "domain_age_days":scan.domain_age_days,
        "ssl_valid":      scan.ssl_valid,
        "ssl_issuer":     scan.ssl_issuer,
        "redirect_chain": _json.loads(scan.redirect_chain or "[]"),
        "ml_score":       scan.ml_score,
        "final_label":    scan.final_label,
        "scanned_at":     scan.scanned_at.isoformat() if scan.scanned_at else ""
    })