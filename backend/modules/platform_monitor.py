"""
backend/modules/platform_monitor.py
Phase 9 — Platform Monitor Engine
Handles multi-phase scanning of watched targets and unified feed aggregation.
"""

import logging
import datetime
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-PHASE TARGET SCAN
# ══════════════════════════════════════════════════════════════════════════════

def scan_target_full(url: str) -> dict:
    """
    Run URL Intelligence + Rule Engine + ML Classifier on a URL.
    Returns a combined result dict with individual and ensemble scores.
    """
    result = {
        "url":        url,
        "url_score":  0.0,
        "rules_score":0.0,
        "ml_score":   0.0,
        "risk_score": 0.0,
        "verdict":    "UNKNOWN",
        "summary":    "",
        "errors":     [],
    }

    # ── Phase 2: URL Intelligence ──────────────────────────────────────────
    try:
        from backend.modules.url_intelligence import analyze_url
        url_result          = analyze_url(url)
        result["url_score"] = float(url_result.get("risk_score", 0.0))
    except Exception as ex:
        logger.warning("URL intelligence failed for %s: %s", url, ex)
        result["errors"].append(f"url_intelligence: {str(ex)[:80]}")

    # ── Phase 4: Rule Engine ───────────────────────────────────────────────
    try:
        from backend.modules.rule_engine import analyze_url_rules
        rules_result          = analyze_url_rules(url)
        result["rules_score"] = float(rules_result.get("rule_score", 0.0))
    except Exception as ex:
        logger.warning("Rule engine failed for %s: %s", url, ex)
        result["errors"].append(f"rule_engine: {str(ex)[:80]}")

    # ── Phase 5: ML Classifier ─────────────────────────────────────────────
    try:
        from backend.modules.ml_url_classifier import classify_url
        ml_result           = classify_url(url)
        raw                 = float(ml_result.get("ensemble_score", 0.0))
        result["ml_score"]  = round(raw * 100, 2)
    except Exception as ex:
        logger.warning("ML classifier failed for %s: %s", url, ex)
        result["errors"].append(f"ml_classifier: {str(ex)[:80]}")

    # ── Ensemble score (weighted average) ──────────────────────────────────
    scores  = [result["url_score"], result["rules_score"], result["ml_score"]]
    weights = [0.35, 0.30, 0.35]
    active  = [(s, w) for s, w in zip(scores, weights) if s > 0]

    if active:
        total_w = sum(w for _, w in active)
        result["risk_score"] = round(
            sum(s * w for s, w in active) / total_w, 2
        )
    else:
        result["risk_score"] = 0.0

    # ── Verdict ────────────────────────────────────────────────────────────
    score = result["risk_score"]
    if score >= 70:
        result["verdict"] = "MALICIOUS"
    elif score >= 35:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    # ── Summary ────────────────────────────────────────────────────────────
    result["summary"] = (
        f"URL:{result['url_score']:.1f} "
        f"Rules:{result['rules_score']:.1f} "
        f"ML:{result['ml_score']:.1f} "
        f"→ {result['verdict']} ({result['risk_score']:.1f}/100)"
    )

    return result


# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        return parsed.netloc or url
    except Exception:
        return url


# ══════════════════════════════════════════════════════════════════════════════
# DUE TARGET CHECK
# ══════════════════════════════════════════════════════════════════════════════

def get_due_targets(app_context) -> list:
    """
    Return all active MonitoredTarget rows that are due for rescanning.
    Must be called inside a Flask app context.
    """
    try:
        from backend.app.models import MonitoredTarget
        now     = datetime.datetime.utcnow()
        targets = MonitoredTarget.query.filter_by(is_active=True).all()
        due     = []
        for t in targets:
            if t.last_scanned is None:
                due.append(t)
                continue
            delta = (now - t.last_scanned).total_seconds() / 60
            if delta >= t.interval_minutes:
                due.append(t)
        return due
    except Exception as ex:
        logger.error("get_due_targets error: %s", ex)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED FEED
# ══════════════════════════════════════════════════════════════════════════════

def get_unified_feed(limit: int = 50) -> list:
    """
    Query all scan tables and return a merged, time-sorted feed.
    Must be called inside a Flask app context.
    """
    feed = []

    try:
        from backend.app.models import EmailScan
        rows = EmailScan.query.order_by(
            EmailScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "Email Scan",
                "icon":       "✉",
                "ref":        r.sender or r.subject or "—",
                "risk_score": r.risk_score or 0.0,
                "verdict":    r.label or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed EmailScan error: %s", ex)

    try:
        from backend.app.models import URLScan
        rows = URLScan.query.order_by(
            URLScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "URL Scan",
                "icon":       "🔗",
                "ref":        r.domain or r.raw_url or "—",
                "risk_score": r.ml_score or 0.0,
                "verdict":    r.final_label or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed URLScan error: %s", ex)

    try:
        from backend.app.models import NetworkScan
        score_map = {"LOW": 10, "MEDIUM": 35, "HIGH": 65, "CRITICAL": 90}
        rows = NetworkScan.query.order_by(
            NetworkScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "Network Scan",
                "icon":       "🌐",
                "ref":        r.target or "—",
                "risk_score": score_map.get(r.risk_level, 0),
                "verdict":    r.risk_level or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed NetworkScan error: %s", ex)

    try:
        from backend.app.models import AttachmentScan
        rows = AttachmentScan.query.order_by(
            AttachmentScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "Attachment",
                "icon":       "📎",
                "ref":        r.filename or "—",
                "risk_score": r.entropy * 10 if r.entropy else 0.0,
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed AttachmentScan error: %s", ex)

    try:
        from backend.app.models import AIDetectionScan
        rows = AIDetectionScan.query.order_by(
            AIDetectionScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "AI Detection",
                "icon":       "🤖",
                "ref":        r.source_ref or r.input_preview[:40] or "—",
                "risk_score": r.risk_score or 0.0,
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed AIDetectionScan error: %s", ex)

    try:
        from backend.app.models import ImageAnalysisScan
        rows = ImageAnalysisScan.query.order_by(
            ImageAnalysisScan.scanned_at.desc()
        ).limit(limit).all()
        for r in rows:
            feed.append({
                "module":     "Image Analysis",
                "icon":       "🖼",
                "ref":        r.filename or "—",
                "risk_score": r.risk_score or 0.0,
                "verdict":    r.verdict or "UNKNOWN",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
                "scan_id":    r.id,
            })
    except Exception as ex:
        logger.warning("Feed ImageAnalysisScan error: %s", ex)

    # Sort all entries by scanned_at descending
    feed.sort(key=lambda x: x["scanned_at"], reverse=True)
    return feed[:limit]