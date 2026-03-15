# dashboard.py
# Flask Blueprint for the main Overview dashboard page.
#
# This is the landing page of the entire application.
# It aggregates live summary data from every module's database tables
# and serves it to the frontend — both on initial page load (via
# Jinja2 template context) and on every 5-second polling request
# (via the /dashboard/stats JSON endpoint).
#
# Data it pulls together:
#   - Scan counts today (email / URL / network / file / image / SMS)
#   - Live threat feed (last 10 detections with scores)
#   - Threat distribution (Safe / Suspicious / Malicious breakdown)
#   - Module health status (each module responds to a ping or is marked offline)
#   - Recent alerts (pulled from the Alert table)
#   - Top risky domains detected today

import json
import logging
import requests
from datetime import datetime, date, timedelta
from flask import (
    Blueprint, render_template, jsonify, current_app
)
from sqlalchemy import func, cast, Date

from backend.app.database import db
from backend.app.models import (
    EmailScan, URLScan, AttachmentScan,
    Alert, NetworkScan, ModelVersion
)

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ─────────────────────────────────────────────────────────────────────────────
# GET /  — main overview page
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/", methods=["GET"])
def overview():
    """
    Render the main Overview dashboard page.

    Pre-computes all summary stats server-side so the page loads with
    real data immediately (no spinner on first visit).
    The JS polling then keeps numbers live without full page reloads.
    """
    stats    = _compute_stats()
    alerts   = _recent_alerts(limit=5)
    feed     = _threat_feed(limit=10)
    health   = _module_health()
    top_doms = _top_risky_domains(limit=8)

    return render_template(
        "dashboard.html",
        stats=stats,
        alerts=alerts,
        threat_feed=feed,
        module_health=health,
        top_domains=top_doms,
        now=datetime.utcnow()
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /dashboard/stats  — JSON endpoint polled every 5 s by dashboard.js
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """
    Return all live dashboard data as JSON.
    Called by the frontend JavaScript every 5 seconds to refresh
    counters, charts, and the threat feed without a page reload.
    """
    return jsonify({
        "stats":          _compute_stats(),
        "threat_feed":    _threat_feed(limit=10),
        "alerts":         _recent_alerts(limit=5),
        "module_health":  _module_health(),
        "top_domains":    _top_risky_domains(limit=8),
        "distribution":   _threat_distribution(),
        "trend":          _scan_trend_last_7_days(),
        "timestamp":      datetime.utcnow().isoformat() + "Z"
    })


# ─────────────────────────────────────────────────────────────────────────────
# Stat computation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _compute_stats() -> dict:
    """
    Count scans performed today, broken down by input type.
    Also computes total all-time scan counts for the overview cards.

    We use SQLAlchemy's func.count() with a date filter:
      cast(Model.scanned_at, Date) == date.today()
    This is SQLite-compatible and works with PostgreSQL too.
    """
    today = date.today()

    def count_today(model, date_col):
        """Count rows where date_col falls on today's date."""
        return (
            db.session.query(func.count(model.id))
            .filter(cast(date_col, Date) == today)
            .scalar() or 0
        )

    def count_total(model):
        return db.session.query(func.count(model.id)).scalar() or 0

    # Today's counts
    emails_today     = count_today(EmailScan,      EmailScan.scanned_at)
    urls_today       = count_today(URLScan,        URLScan.scanned_at)
    networks_today   = count_today(NetworkScan,    NetworkScan.scanned_at)
    attachments_today= count_today(AttachmentScan, AttachmentScan.scanned_at)
    alerts_today     = count_today(Alert,          Alert.created_at)

    total_scans_today = emails_today + urls_today + networks_today + attachments_today

    # All-time totals
    total_emails  = count_total(EmailScan)
    total_urls    = count_total(URLScan)
    total_alerts  = count_total(Alert)

    # Threat counts today (malicious + suspicious detections)
    malicious_today = (
        db.session.query(func.count(EmailScan.id))
        .filter(
            cast(EmailScan.scanned_at, Date) == today,
            EmailScan.label == "MALICIOUS"
        )
        .scalar() or 0
    )

    suspicious_today = (
        db.session.query(func.count(EmailScan.id))
        .filter(
            cast(EmailScan.scanned_at, Date) == today,
            EmailScan.label == "SUSPICIOUS"
        )
        .scalar() or 0
    )

    return {
        # Today's scan volume
        "total_scans_today":   total_scans_today,
        "emails_today":        emails_today,
        "urls_today":          urls_today,
        "networks_today":      networks_today,
        "attachments_today":   attachments_today,
        "alerts_today":        alerts_today,

        # Threat detections today
        "malicious_today":     malicious_today,
        "suspicious_today":    suspicious_today,
        "threats_today":       malicious_today + suspicious_today,

        # All-time totals
        "total_emails_alltime": total_emails,
        "total_urls_alltime":   total_urls,
        "total_alerts_alltime": total_alerts,
    }


def _threat_distribution() -> dict:
    """
    Count how many email scans fall into each threat category (all-time).
    Used to populate the doughnut/pie chart on the overview page.

    Returns: {"safe": N, "suspicious": N, "malicious": N}
    """
    rows = (
        db.session.query(EmailScan.label, func.count(EmailScan.id))
        .group_by(EmailScan.label)
        .all()
    )

    dist = {"safe": 0, "suspicious": 0, "malicious": 0}
    for label, count in rows:
        if label:
            dist[label.lower()] = count

    return dist


def _threat_feed(limit: int = 10) -> list:
    """
    Build the live threat feed — the most recent detections across
    all scan types, ordered by scan time descending.

    For Phase 1–3 we pull from EmailScan and URLScan.
    Later phases (attachments, images, SMS) will add their own tables.

    Returns a list of unified feed item dicts:
      {type, subject/url, label, risk_score, scanned_at, scan_id}
    """
    feed_items = []

    # ── Email scans ──
    recent_emails = (
        EmailScan.query
        .order_by(EmailScan.scanned_at.desc())
        .limit(limit)
        .all()
    )
    for s in recent_emails:
        feed_items.append({
            "type":       "Email",
            "display":    s.subject or s.sender or "(no subject)",
            "detail":     f"From: {s.sender or '—'}",
            "label":      s.label or "UNKNOWN",
            "risk_score": round(s.risk_score or 0, 1),
            "scanned_at": s.scanned_at.isoformat() if s.scanned_at else "",
            "scan_id":    s.id,
            "link":       f"/email/scan"
        })

    # ── URL scans ──
    recent_urls = (
        URLScan.query
        .order_by(URLScan.scanned_at.desc())
        .limit(limit)
        .all()
    )
    for s in recent_urls:
        feed_items.append({
            "type":       "URL",
            "display":    s.domain or s.raw_url or "—",
            "detail":     s.raw_url[:80] if s.raw_url else "",
            "label":      s.final_label or "UNKNOWN",
            "risk_score": round((s.ml_score or 0) * 100, 1),
            "scanned_at": s.scanned_at.isoformat() if s.scanned_at else "",
            "scan_id":    s.id,
            "link":       f"/url/intel"
        })

    # ── Network scans ──
    recent_nets = (
        NetworkScan.query
        .order_by(NetworkScan.scanned_at.desc())
        .limit(limit)
        .all()
    )
    risk_to_score = {"LOW": 10, "MEDIUM": 35, "HIGH": 65,
                     "CRITICAL": 90, "UNKNOWN": 0}
    for s in recent_nets:
        feed_items.append({
            "type":       "Network",
            "display":    s.target or "—",
            "detail":     f"{s.total_open_ports} open ports · {s.ip_resolved or '—'}",
            "label":      (
                "SAFE" if s.risk_level == "LOW" else
                "MALICIOUS" if s.risk_level == "CRITICAL" else
                "SUSPICIOUS"
            ),
            "risk_score": risk_to_score.get(s.risk_level, 0),
            "scanned_at": s.scanned_at.isoformat() if s.scanned_at else "",
            "scan_id":    s.id,
            "link":       f"/network/scan"
        })

    # ── Alerts ──
    recent_alerts = (
        Alert.query
        .filter(Alert.severity.in_(["High", "Critical"]))
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
    for a in recent_alerts:
        feed_items.append({
            "type":       "Alert",
            "display":    f"{a.severity} alert — {a.input_type or '—'}",
            "detail":     (a.bart_summary or "")[:80],
            "label":      "MALICIOUS" if a.risk_score >= 70 else "SUSPICIOUS",
            "risk_score": round(a.risk_score or 0, 1),
            "scanned_at": a.created_at.isoformat() if a.created_at else "",
            "scan_id":    a.id,
            "link":       "/alerts"
        })

    # Sort all items by scanned_at descending and return top N
    feed_items.sort(
        key=lambda x: x.get("scanned_at", ""),
        reverse=True
    )
    return feed_items[:limit]


def _recent_alerts(limit: int = 5) -> list:
    """
    Return the most recent alerts for the Recent Alerts panel.
    Includes severity, type, risk score, and BART summary.
    """
    alerts = (
        Alert.query
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
    return [{
        "id":          a.id,
        "input_type":  a.input_type or "—",
        "severity":    a.severity or "Low",
        "risk_score":  round(a.risk_score or 0, 1),
        "summary":     (a.bart_summary or "No summary available.")[:120],
        "action":      a.recommended_action or "WARN",
        "created_at":  a.created_at.isoformat() if a.created_at else ""
    } for a in alerts]


def _module_health() -> list:
    """
    Check the health of each module by querying the FastAPI /health endpoint
    and by checking whether recent DB activity exists for each module.

    Each module returns one of:
      "online"    — API responds + recent DB rows exist
      "idle"      — API responds but no recent activity (no scans yet)
      "degraded"  — API responds but a model failed to load
      "offline"   — Cannot reach FastAPI

    This powers the Module Health Status row on the overview page.
    """
    # Try to reach FastAPI health endpoint
    api_online = False
    model_statuses = {}

    try:
        resp = requests.get(f"{_api()}/health", timeout=3)
        if resp.status_code == 200:
            api_online     = True
            model_statuses = resp.json().get("models", {})
    except Exception:
        pass

    # Helper: was there any scan in the last 24 hours?
    yesterday = datetime.utcnow() - timedelta(hours=24)

    def recent_activity(model, date_col):
        return (
            db.session.query(func.count(model.id))
            .filter(date_col >= yesterday)
            .scalar() or 0
        ) > 0

    def module_status(model_key: str, has_recent: bool) -> str:
        if not api_online:
            return "offline"
        if model_key and model_statuses.get(model_key) is False:
            return "degraded"
        return "online" if has_recent else "idle"

    modules = [
        {
            "id":    "email_parser",
            "name":  "Email Scan",
            "link":  "/email/scan",
            "status": module_status(
                "email_classifier",
                recent_activity(EmailScan, EmailScan.scanned_at)
            )
        },
        {
            "id":    "url_intel",
            "name":  "URL Intelligence",
            "link":  "/url/intel",
            "status": module_status(
                "url_malware_detector",
                recent_activity(URLScan, URLScan.scanned_at)
            )
        },
        {
            "id":    "network_scan",
            "name":  "Network Scan",
            "link":  "/network/scan",
            "status": module_status(
                None,
                recent_activity(NetworkScan, NetworkScan.scanned_at)
            )
        },
        {
            "id":    "rule_engine",
            "name":  "Detection Rules",
            "link":  "/rules",
            "status": "idle" if api_online else "offline"
        },
        {
            "id":    "ml_classifier",
            "name":  "ML Classifier",
            "link":  "/ml/classifier",
            "status": module_status("url_phishing_bert", False)
        },
        {
            "id":    "attachment",
            "name":  "Attachment Analysis",
            "link":  "/attachments",
            "status": module_status(
                None,
                recent_activity(AttachmentScan, AttachmentScan.scanned_at)
            )
        },
        {
            "id":    "image_analysis",
            "name":  "Image Analysis",
            "link":  "/image/analysis",
            "status": "idle" if api_online else "offline"
        },
        {
            "id":    "ai_detection",
            "name":  "AI Detection",
            "link":  "/ai/detection",
            "status": module_status("ai_text_detector", False)
        },
        {
            "id":    "platform_monitor",
            "name":  "Platform Monitor",
            "link":  "/platform",
            "status": "idle" if api_online else "offline"
        },
        {
            "id":    "risk_engine",
            "name":  "Risk Score",
            "link":  "/risk",
            "status": "idle" if api_online else "offline"
        },
        {
            "id":    "live_monitor",
            "name":  "Live Monitor",
            "link":  "/monitor",
            "status": "online" if api_online else "offline"
        },
        {
            "id":    "model_mgmt",
            "name":  "Model Management",
            "link":  "/models",
            "status": module_status("threat_summarizer", False)
        },
        {
            "id":    "alerts",
            "name":  "Alerts & Audit",
            "link":  "/alerts",
            "status": module_status(
                None,
                recent_activity(Alert, Alert.created_at)
            )
        },
        {
            "id":    "extension",
            "name":  "Extension",
            "link":  "/extension",
            "status": "idle" if api_online else "offline"
        },
        {
            "id":    "architecture",
            "name":  "Architecture",
            "link":  "/architecture",
            "status": "online" if api_online else "offline"
        },
        {
            "id":    "threat_explain",
            "name":  "Threat Explanation",
            "link":  "/threat/explain",
            "status": module_status("threat_summarizer", False)
        },
    ]

    return modules


def _top_risky_domains(limit: int = 8) -> list:
    """
    Return the domains with the highest average ML risk score
    from URL scans, limited to scans from the last 7 days.
    Used for the "Top risky domains today" panel.
    """
    seven_days_ago = datetime.utcnow() - timedelta(days=7)

    rows = (
        db.session.query(
            URLScan.domain,
            func.avg(URLScan.ml_score).label("avg_score"),
            func.count(URLScan.id).label("scan_count")
        )
        .filter(
            URLScan.scanned_at >= seven_days_ago,
            URLScan.domain != None,
            URLScan.domain != ""
        )
        .group_by(URLScan.domain)
        .order_by(func.avg(URLScan.ml_score).desc())
        .limit(limit)
        .all()
    )

    return [{
        "domain":     row.domain,
        "avg_score":  round((row.avg_score or 0) * 100, 1),
        "scan_count": row.scan_count,
        "label": (
            "MALICIOUS"  if (row.avg_score or 0) >= 0.70 else
            "SUSPICIOUS" if (row.avg_score or 0) >= 0.30 else
            "BENIGN"
        )
    } for row in rows]


def _scan_trend_last_7_days() -> list:
    """
    Return daily scan counts for the last 7 days.
    Used to draw the sparkline/bar chart on the overview page.

    Returns a list of 7 dicts: [{date: "YYYY-MM-DD", count: N}, ...]
    ordered oldest-first so Chart.js can plot them left-to-right.
    """
    trend = []
    for days_ago in range(6, -1, -1):  # 6 days ago → today
        day = date.today() - timedelta(days=days_ago)

        email_count = (
            db.session.query(func.count(EmailScan.id))
            .filter(cast(EmailScan.scanned_at, Date) == day)
            .scalar() or 0
        )
        url_count = (
            db.session.query(func.count(URLScan.id))
            .filter(cast(URLScan.scanned_at, Date) == day)
            .scalar() or 0
        )

        trend.append({
            "date":   day.strftime("%Y-%m-%d"),
            "label":  day.strftime("%d %b"),
            "emails": email_count,
            "urls":   url_count,
            "total":  email_count + url_count
        })

    return trend