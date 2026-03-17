"""
backend/app/routes/dashboard.py
Phase 17 — Unified Dashboard & Role-Based Access Control
"""

import json
import logging
import datetime
import functools

import requests as http_requests
from flask import (
    Blueprint, render_template, request,
    jsonify, session, redirect, url_for,
    current_app
)

from backend.app.database import db
from backend.app.models   import (
    EmailScan, URLScan, NetworkScan,
    AttachmentScan, AIDetectionScan,
    ImageAnalysisScan, Alert,
)

logger       = logging.getLogger(__name__)
dashboard_bp = Blueprint("dashboard_bp", __name__)

FASTAPI_BASE = "http://127.0.0.1:8001"
PROXY_TIMEOUT = 15

# ─────────────────────────────────────────────────────────────────────────────
# Role definitions
# ─────────────────────────────────────────────────────────────────────────────

ROLES = {
    "admin": {
        "label":       "Admin",
        "icon":        "👑",
        "description": "Full access — all modules, model management, alerts",
        "color":       "#f85149",
        "allowed_prefixes": None,   # None = all pages allowed
    },
    "analyst": {
        "label":       "Analyst",
        "icon":        "🔬",
        "description": "Scan pages, alerts, live monitor, threat explanation",
        "color":       "#388bfd",
        "allowed_prefixes": [
            "/", "/email", "/url", "/network", "/rules",
            "/ml", "/attachments", "/image", "/ai",
            "/alerts", "/monitor", "/threat", "/extension",
            "/platform", "/risk",
        ],
    },
    "viewer": {
        "label":       "Viewer",
        "icon":        "👁",
        "description": "Overview dashboard only — read-only access",
        "color":       "#3fb950",
        "allowed_prefixes": ["/"],
    },
}

# Pages that are always public (no role check)
PUBLIC_PATHS = ["/role/select", "/role/set", "/static/"]


# ─────────────────────────────────────────────────────────────────────────────
# Role helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_current_role() -> str:
    return session.get("role", "")


def is_allowed(path: str) -> bool:
    role = get_current_role()
    if not role:
        return False
    cfg = ROLES.get(role)
    if not cfg:
        return False
    if cfg["allowed_prefixes"] is None:
        return True   # admin — all allowed
    for prefix in cfg["allowed_prefixes"]:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def role_required(f):
    """Decorator that checks role before serving a page."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        path = request.path
        # Always allow public paths
        for pub in PUBLIC_PATHS:
            if path.startswith(pub):
                return f(*args, **kwargs)
        # Check role
        if not get_current_role():
            return redirect(url_for("dashboard_bp.role_select"))
        if not is_allowed(path):
            return render_template(
                "access_denied.html",
                path=path,
            ), 403
        return f(*args, **kwargs)
    return decorated


def get_sidebar_config():
    """Return sidebar items filtered by current role."""
    role = get_current_role()
    cfg  = ROLES.get(role, {})
    all_items = _all_sidebar_items()

    if cfg.get("allowed_prefixes") is None:
        return all_items   # admin sees everything

    allowed = cfg.get("allowed_prefixes", ["/"])
    filtered = []
    for section in all_items:
        items = [
            item for item in section["items"]
            if any(
                item["url"] == p or
                item["url"].startswith(p.rstrip("/") + "/")
                for p in allowed
            )
        ]
        if items:
            filtered.append({**section, "items": items})
    return filtered


def _all_sidebar_items():
    return [
        {
            "section": "Overview",
            "items": [
                {"label": "Dashboard",      "url": "/",              "icon": "🏠"},
            ],
        },
        {
            "section": "Detection Modules",
            "items": [
                {"label": "Email Scan",      "url": "/email/scan",    "icon": "✉"},
                {"label": "URL Intelligence","url": "/url/intel",     "icon": "🔗"},
                {"label": "Network Scan",    "url": "/network/scan",  "icon": "🌐"},
                {"label": "Detection Rules", "url": "/rules",         "icon": "📏"},
                {"label": "ML Classifier",   "url": "/ml/classifier", "icon": "🧠"},
                {"label": "Attachments",     "url": "/attachments/",  "icon": "📎"},
                {"label": "Image Analysis",  "url": "/image/analysis","icon": "🖼"},
                {"label": "AI Detection",    "url": "/ai/detection",  "icon": "🤖"},
            ],
        },
        {
            "section": "Operations",
            "items": [
                {"label": "Platform Monitor","url": "/platform/",     "icon": "📡"},
                {"label": "Risk Score",      "url": "/risk/",         "icon": "⚖"},
                {"label": "Alerts & Audit",  "url": "/alerts/",       "icon": "🚨"},
                {"label": "Extension",       "url": "/extension/",    "icon": "🧩"},
            ],
        },
        {
            "section": "Administration",
            "items": [
                {"label": "Model Management","url": "/models/",       "icon": "📦"},
                {"label": "Architecture",    "url": "/architecture/", "icon": "🏗"},
            ],
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Role selector routes
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/role/select")
def role_select():
    return render_template(
        "role_select.html",
        roles=ROLES,
    )


@dashboard_bp.route("/role/set", methods=["POST"])
def role_set():
    role = request.form.get("role", "").strip()
    if role not in ROLES:
        return redirect(url_for("dashboard_bp.role_select"))
    session["role"]       = role
    session["role_label"] = ROLES[role]["label"]
    session["role_icon"]  = ROLES[role]["icon"]
    return redirect(url_for("dashboard_bp.overview"))


@dashboard_bp.route("/role/clear")
def role_clear():
    session.clear()
    return redirect(url_for("dashboard_bp.role_select"))


# ─────────────────────────────────────────────────────────────────────────────
# Overview dashboard
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/")
@role_required
def overview():
    # sidebar / role / role_label / role_icon are injected by the context
    # processor in __init__.py — do NOT pass them manually here.
    return render_template("dashboard.html")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard widget API endpoints (called by JS every 5 seconds)
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/dashboard/stats")
@role_required
def dashboard_stats():
    """
    Returns all widget data in one call:
    scan counts, threat distribution, live feed, top domains, alerts.
    """
    try:
        today = datetime.datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        )

        # ── Scan counts today ──────────────────────────────────────────────
        counts = {
            "email":      EmailScan.query.filter(
                EmailScan.scanned_at >= today).count(),
            "url":        URLScan.query.filter(
                URLScan.scanned_at >= today).count(),
            "network":    NetworkScan.query.filter(
                NetworkScan.scanned_at >= today).count(),
            "attachment": AttachmentScan.query.filter(
                AttachmentScan.scanned_at >= today).count(),
            "ai":         AIDetectionScan.query.filter(
                AIDetectionScan.scanned_at >= today).count(),
            "image":      ImageAnalysisScan.query.filter(
                ImageAnalysisScan.scanned_at >= today).count(),
        }
        counts["total"] = sum(counts.values())

        # ── Threat distribution (all time) ─────────────────────────────────
        distribution = _get_threat_distribution()

        # ── Live feed (last 10) ────────────────────────────────────────────
        live_feed = _get_live_feed(limit=10)

        # ── Top risky domains today ────────────────────────────────────────
        top_domains = _get_top_risky_domains(today, limit=5)

        # ── Recent alerts ──────────────────────────────────────────────────
        recent_alerts = _recent_alerts(limit=5)

        return jsonify({
            "status":       "success",
            "counts":       counts,
            "distribution": distribution,
            "live_feed":    live_feed,
            "top_domains":  top_domains,
            "alerts":       recent_alerts,
            "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        })

    except Exception as ex:
        logger.error("Dashboard stats error: %s", ex)
        return jsonify({"status": "error", "message": str(ex)}), 500


@dashboard_bp.route("/dashboard/health")
@role_required
def dashboard_health():
    """Module health status row — proxies to FastAPI health endpoint."""
    try:
        resp = http_requests.get(
            f"{FASTAPI_BASE}/api/architecture/health",
            timeout=PROXY_TIMEOUT,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as ex:
        return jsonify({"status": "error", "message": str(ex)}), 502


# ─────────────────────────────────────────────────────────────────────────────
# Widget helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_threat_distribution() -> dict:
    safe = suspicious = malicious = 0

    def _tally(verdict: str) -> tuple:
        v = (verdict or "").upper()
        if v in ("SAFE", "CLEAN", "LOW", "HUMAN", "BENIGN"):
            return 1, 0, 0
        if v in ("SUSPICIOUS", "MIXED", "MEDIUM"):
            return 0, 1, 0
        if v in ("MALICIOUS", "HIGH", "CRITICAL", "PHISHING", "AI_GENERATED"):
            return 0, 0, 1
        return 0, 0, 0

    try:
        for r in EmailScan.query.with_entities(EmailScan.label).all():
            s, su, m = _tally(r.label)
            safe += s; suspicious += su; malicious += m
    except Exception:
        pass

    try:
        for r in URLScan.query.with_entities(URLScan.final_label).all():
            s, su, m = _tally(r.final_label)
            safe += s; suspicious += su; malicious += m
    except Exception:
        pass

    try:
        for r in AttachmentScan.query.with_entities(AttachmentScan.verdict).all():
            s, su, m = _tally(r.verdict)
            safe += s; suspicious += su; malicious += m
    except Exception:
        pass

    try:
        for r in AIDetectionScan.query.with_entities(AIDetectionScan.verdict).all():
            s, su, m = _tally(r.verdict)
            safe += s; suspicious += su; malicious += m
    except Exception:
        pass

    try:
        for r in ImageAnalysisScan.query.with_entities(
            ImageAnalysisScan.verdict
        ).all():
            s, su, m = _tally(r.verdict)
            safe += s; suspicious += su; malicious += m
    except Exception:
        pass

    return {
        "safe":       safe,
        "suspicious": suspicious,
        "malicious":  malicious,
        "total":      safe + suspicious + malicious,
    }


def _get_live_feed(limit: int = 10) -> list:
    feed = []

    try:
        for r in (EmailScan.query
                  .order_by(EmailScan.scanned_at.desc())
                  .limit(limit).all()):
            feed.append({
                "module":     "Email",
                "icon":       "✉",
                "ref":        (r.sender or r.subject or "—")[:60],
                "risk_score": float(r.risk_score or 0),
                "verdict":    r.label or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z"
                              if r.scanned_at else "",
            })
    except Exception:
        pass

    try:
        for r in (URLScan.query
                  .order_by(URLScan.scanned_at.desc())
                  .limit(limit).all()):
            score = float(r.ml_score or 0)
            if score <= 1.0:
                score = score * 100.0
            feed.append({
                "module":     "URL",
                "icon":       "🔗",
                "ref":        (r.domain or r.raw_url or "—")[:60],
                "risk_score": round(score, 1),
                "verdict":    r.final_label or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z"
                              if r.scanned_at else "",
            })
    except Exception:
        pass

    try:
        for r in (AttachmentScan.query
                  .order_by(AttachmentScan.scanned_at.desc())
                  .limit(limit).all()):
            feed.append({
                "module":     "Attachment",
                "icon":       "📎",
                "ref":        (r.filename or "—")[:60],
                "risk_score": 0.0,
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z"
                              if r.scanned_at else "",
            })
    except Exception:
        pass

    try:
        for r in (AIDetectionScan.query
                  .order_by(AIDetectionScan.scanned_at.desc())
                  .limit(limit).all()):
            feed.append({
                "module":     "AI Detection",
                "icon":       "🤖",
                "ref":        (r.source_ref or
                               r.input_preview or "—")[:60],
                "risk_score": float(r.risk_score or 0),
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z"
                              if r.scanned_at else "",
            })
    except Exception:
        pass

    try:
        for r in (ImageAnalysisScan.query
                  .order_by(ImageAnalysisScan.scanned_at.desc())
                  .limit(limit).all()):
            feed.append({
                "module":     "Image",
                "icon":       "🖼",
                "ref":        (r.filename or "—")[:60],
                "risk_score": float(r.risk_score or 0),
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z"
                              if r.scanned_at else "",
            })
    except Exception:
        pass

    feed.sort(key=lambda x: x["scanned_at"], reverse=True)
    return feed[:limit]


def _get_top_risky_domains(today: datetime.datetime,
                           limit: int = 5) -> list:
    try:
        rows = (
            URLScan.query
            .filter(URLScan.scanned_at >= today)
            .filter(URLScan.domain != "")
            .order_by(URLScan.ml_score.desc())
            .limit(limit * 3)
            .all()
        )
        seen    = set()
        domains = []
        for r in rows:
            domain = r.domain or ""
            if not domain or domain in seen:
                continue
            seen.add(domain)
            score = float(r.ml_score or 0)
            if score <= 1.0:
                score = score * 100.0
            domains.append({
                "domain":    domain,
                "risk_score":round(score, 1),
                "verdict":   r.final_label or "UNKNOWN",
            })
            if len(domains) >= limit:
                break
        return domains
    except Exception as ex:
        logger.warning("Top domains error: %s", ex)
        return []


def _recent_alerts(limit: int = 5) -> list:
    try:
        rows = (
            Alert.query
            .filter(Alert.status == "open")
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id":         r.id,
                "module":     r.module,
                "severity":   r.severity,
                "verdict":    r.verdict,
                "risk_score": r.risk_score,
                "summary":    (r.threat_summary or "")[:120],
                "detail":     (r.threat_summary or "")[:80],
                "status":     r.status,
                "created_at": r.created_at.isoformat() + "Z"
                              if r.created_at else "",
            }
            for r in rows
        ]
    except Exception as ex:
        logger.warning("Recent alerts error: %s", ex)
        return []