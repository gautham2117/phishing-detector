# backend/routes/network_scan.py
import json
import requests
import logging
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.models import NetworkScan, PortResult
from backend.app.database import db
from backend.modules.network_scanner import is_demo_target

logger         = logging.getLogger(__name__)
network_scan_bp = Blueprint("network_scan", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


@network_scan_bp.route("/network/scan", methods=["GET"])
def network_scan_page():
    recent = (
        NetworkScan.query
        .order_by(NetworkScan.scanned_at.desc())
        .limit(15)
        .all()
    )
    return render_template("network_scan.html", recent_scans=recent)


@network_scan_bp.route("/network/submit", methods=["POST"])
def submit_network_scan():
    data              = request.get_json() or {}
    target            = data.get("target", "").strip()
    scan_type         = data.get("scan_type", "top100")
    consent_confirmed = data.get("consent_confirmed", False)
    url_scan_id       = data.get("url_scan_id")
    email_scan_id     = data.get("email_scan_id")

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # --------------------------------------------------------------
    # FIX 1: Better frontend consent handling
    # If target is not a demo target and consent_confirmed is False,
    # return a 400 with a clear message explaining what's needed.
    # --------------------------------------------------------------
    if not is_demo_target(target) and not consent_confirmed:
        return jsonify({
            "status": "consent_required",
            "message": (
                f"'{target}' is not a pre‑authorized demo target. "
                "Port scanning without authorization is illegal.\n\n"
                "To proceed, you must:\n"
                "1. Set SCAN_AUTHORIZED=1 in your .env file\n"
                "2. Check the consent checkbox in the UI\n\n"
                "Only continue if you own this domain or have "
                "explicit written permission."
            )
        }), 400  # Using 400 so frontend can distinguish from real errors

    try:
        # Forward the request to FastAPI
        resp = requests.post(
            f"{_api()}/api/scan/network",
            json={
                "target":            target,
                "scan_type":         scan_type,
                "consent_confirmed": consent_confirmed,
                "url_scan_id":       url_scan_id,
                "email_scan_id":     email_scan_id
            },
            timeout={"quick": 30, "top100": 60,
                     "top1000": 120, "full": 700}.get(scan_type, 60)
        )

        # --------------------------------------------------------------
        # FIX 2: Better error forwarding
        # If FastAPI returns a 403 with a clear message, preserve it
        # --------------------------------------------------------------
        if resp.status_code == 403:
            try:
                error_data = resp.json()
                return jsonify({
                    "status": "blocked",
                    "message": error_data.get("detail", error_data.get("error", 
                                "Scan blocked by ethics gate. Check SCAN_AUTHORIZED env var."))
                }), 403
            except:
                return jsonify({
                    "status": "blocked",
                    "message": "Scan blocked by ethics gate. Check SCAN_AUTHORIZED env var."
                }), 403

        return jsonify(resp.json()), resp.status_code

    except requests.exceptions.Timeout:
        return jsonify({"error": "Scan timed out"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except Exception as e:
        logger.error(f"Network scan proxy error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@network_scan_bp.route("/network/history", methods=["GET"])
def network_history():
    scans = (
        NetworkScan.query
        .order_by(NetworkScan.scanned_at.desc())
        .limit(20)
        .all()
    )
    return jsonify([{
        "id":              s.id,
        "target":          s.target,
        "ip_resolved":     s.ip_resolved,
        "scan_type":       s.scan_type,
        "total_open_ports":s.total_open_ports,
        "risk_level":      s.risk_level,
        "risk_flags":      json.loads(s.risk_flags or "[]"),
        "authorized":      s.authorized,
        "scan_duration_s": s.scan_duration_s,
        "scanned_at":      s.scanned_at.isoformat() if s.scanned_at else ""
    } for s in scans])


@network_scan_bp.route("/network/detail/<int:scan_id>", methods=["GET"])
def network_detail(scan_id: int):
    scan  = NetworkScan.query.get_or_404(scan_id)
    ports = PortResult.query.filter_by(network_scan_id=scan_id).all()

    return jsonify({
        "id":              scan.id,
        "target":          scan.target,
        "ip_resolved":     scan.ip_resolved,
        "scan_type":       scan.scan_type,
        "nmap_version":    scan.nmap_version,
        "os_guess":        scan.os_guess,
        "risk_level":      scan.risk_level,
        "risk_flags":      json.loads(scan.risk_flags or "[]"),
        "scan_duration_s": scan.scan_duration_s,
        "scanned_at":      scan.scanned_at.isoformat() if scan.scanned_at else "",
        "ports": [{
            "port":            p.port,
            "protocol":        p.protocol,
            "state":           p.state,
            "service_name":    p.service_name,
            "service_product": p.service_product,
            "service_version": p.service_version,
            "service_extra":   p.service_extra,
            "is_dangerous":    p.is_dangerous,
            "danger_reason":   p.danger_reason,
            "cpe":             p.cpe
        } for p in ports]
    })

@network_scan_bp.route("/network/is-demo", methods=["GET"])
def check_is_demo():
    """Check if a target is on the demo allowlist (for UI consent logic)"""
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    is_demo = is_demo_target(target)
    return jsonify({"is_demo": is_demo, "target": target})