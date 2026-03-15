"""
backend/modules/live_monitor.py
Phase 11 — Live Monitor Engine
Queries all scan tables and returns a unified live feed + stats.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Label normaliser ───────────────────────────────────────────────────────────

def _normalise_verdict(raw: str) -> str:
    """Map any verdict string to SAFE / SUSPICIOUS / MALICIOUS / UNKNOWN."""
    if not raw:
        return "UNKNOWN"
    v = raw.upper()
    if v in ("CLEAN", "SAFE", "BENIGN", "LOW", "HUMAN"):
        return "SAFE"
    if v in ("SUSPICIOUS", "MEDIUM", "MIXED"):
        return "SUSPICIOUS"
    if v in ("MALICIOUS", "HIGH", "CRITICAL", "PHISHING",
             "AI_GENERATED", "MALWARE"):
        return "MALICIOUS"
    return "UNKNOWN"


# ══════════════════════════════════════════════════════════════════════════════
# FEED BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def get_live_feed(limit: int = 100) -> list:
    """
    Query every scan table and return a merged, time-sorted list.
    Each entry has a consistent shape so the JS renderer is simple.
    """
    feed = []

    # ── Email scans ────────────────────────────────────────────────────────
    try:
        from backend.app.models import EmailScan
        rows = (EmailScan.query
                .order_by(EmailScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            feed.append({
                "id":         r.id,
                "module":     "Email",
                "icon":       "✉",
                "ref":        (r.sender or r.subject or "—")[:80],
                "risk_score": float(r.risk_score or 0),
                "verdict":    _normalise_verdict(r.label),
                "raw_verdict":r.label or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed EmailScan error: %s", ex)

    # ── URL scans ──────────────────────────────────────────────────────────
    try:
        from backend.app.models import URLScan
        rows = (URLScan.query
                .order_by(URLScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            score = float(r.ml_score or 0)
            if score <= 1.0:
                score = score * 100.0
            feed.append({
                "id":         r.id,
                "module":     "URL",
                "icon":       "🔗",
                "ref":        (r.domain or r.raw_url or "—")[:80],
                "risk_score": round(score, 1),
                "verdict":    _normalise_verdict(r.final_label),
                "raw_verdict":r.final_label or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed URLScan error: %s", ex)

    # ── Network scans ──────────────────────────────────────────────────────
    try:
        from backend.app.models import NetworkScan
        score_map = {
            "LOW": 10.0, "MEDIUM": 35.0,
            "HIGH": 65.0, "CRITICAL": 90.0, "UNKNOWN": 5.0
        }
        rows = (NetworkScan.query
                .order_by(NetworkScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            feed.append({
                "id":         r.id,
                "module":     "Network",
                "icon":       "🌐",
                "ref":        (r.target or "—")[:80],
                "risk_score": score_map.get(r.risk_level or "UNKNOWN", 5.0),
                "verdict":    _normalise_verdict(r.risk_level),
                "raw_verdict":r.risk_level or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed NetworkScan error: %s", ex)

    # ── Attachment scans ───────────────────────────────────────────────────
    try:
        from backend.app.models import AttachmentScan
        rows = (AttachmentScan.query
                .order_by(AttachmentScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            feed.append({
                "id":         r.id,
                "module":     "Attachment",
                "icon":       "📎",
                "ref":        (r.filename or "—")[:80],
                "risk_score": float(r.entropy * 10 if r.entropy else 0),
                "verdict":    _normalise_verdict(r.verdict),
                "raw_verdict":r.verdict or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed AttachmentScan error: %s", ex)

    # ── AI Detection scans ─────────────────────────────────────────────────
    try:
        from backend.app.models import AIDetectionScan
        rows = (AIDetectionScan.query
                .order_by(AIDetectionScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            feed.append({
                "id":         r.id,
                "module":     "AI Detection",
                "icon":       "🤖",
                "ref":        (r.source_ref or r.input_preview or "—")[:80],
                "risk_score": float(r.risk_score or 0),
                "verdict":    _normalise_verdict(r.verdict),
                "raw_verdict":r.verdict or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed AIDetectionScan error: %s", ex)

    # ── Image Analysis scans ───────────────────────────────────────────────
    try:
        from backend.app.models import ImageAnalysisScan
        rows = (ImageAnalysisScan.query
                .order_by(ImageAnalysisScan.scanned_at.desc())
                .limit(limit).all())
        for r in rows:
            feed.append({
                "id":         r.id,
                "module":     "Image",
                "icon":       "🖼",
                "ref":        (r.filename or "—")[:80],
                "risk_score": float(r.risk_score or 0),
                "verdict":    _normalise_verdict(r.verdict),
                "raw_verdict":r.verdict or "",
                "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            })
    except Exception as ex:
        logger.warning("Live feed ImageAnalysisScan error: %s", ex)

    # Sort all entries newest-first
    feed.sort(key=lambda x: x["scanned_at"], reverse=True)
    return feed[:limit]


# ══════════════════════════════════════════════════════════════════════════════
# STATS BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def get_live_stats() -> dict:
    """
    Count totals across all scan tables.
    Returns dict with total, malicious, suspicious, safe, unknown counts
    and per-module breakdown.
    """
    stats = {
        "total":      0,
        "malicious":  0,
        "suspicious": 0,
        "safe":       0,
        "unknown":    0,
        "by_module":  {},
    }

    tables = [
        ("Email",      "backend.app.models", "EmailScan",
         lambda r: _normalise_verdict(r.label)),
        ("URL",        "backend.app.models", "URLScan",
         lambda r: _normalise_verdict(r.final_label)),
        ("Network",    "backend.app.models", "NetworkScan",
         lambda r: _normalise_verdict(r.risk_level)),
        ("Attachment", "backend.app.models", "AttachmentScan",
         lambda r: _normalise_verdict(r.verdict)),
        ("AI Detection","backend.app.models","AIDetectionScan",
         lambda r: _normalise_verdict(r.verdict)),
        ("Image",      "backend.app.models", "ImageAnalysisScan",
         lambda r: _normalise_verdict(r.verdict)),
    ]

    for module_name, mod_path, class_name, verdict_fn in tables:
        try:
            import importlib
            mod   = importlib.import_module(mod_path)
            model = getattr(mod, class_name)
            rows  = model.query.all()

            m_total = s_total = sus_total = safe_total = unk_total = 0
            for r in rows:
                v = verdict_fn(r)
                m_total += 1
                if v == "MALICIOUS":   s_total   += 1
                elif v == "SUSPICIOUS":sus_total += 1
                elif v == "SAFE":      safe_total+= 1
                else:                  unk_total += 1

            stats["total"]      += m_total
            stats["malicious"]  += s_total
            stats["suspicious"] += sus_total
            stats["safe"]       += safe_total
            stats["unknown"]    += unk_total
            stats["by_module"][module_name] = {
                "total":      m_total,
                "malicious":  s_total,
                "suspicious": sus_total,
                "safe":       safe_total,
            }
        except Exception as ex:
            logger.warning("Stats error for %s: %s", module_name, ex)

    return stats


# ══════════════════════════════════════════════════════════════════════════════
# ALERTS ABOVE THRESHOLD
# ══════════════════════════════════════════════════════════════════════════════

def get_alerts_above_threshold(
    threshold: float = 70.0,
    limit:     int   = 20,
) -> list:
    """
    Return recent scan entries whose risk_score is above threshold.
    Uses the same feed builder — just filters by score.
    """
    feed = get_live_feed(limit=200)
    return [
        item for item in feed
        if item["risk_score"] >= threshold
    ][:limit]