"""
backend/modules/risk_aggregator.py
Phase 10 — Risk Score Aggregator Engine

ADDED IN THIS VERSION:
  aggregate_risk_scores_auto() — automatically pulls the most recent scan
  from each module table. Modules with no records are excluded (shown as
  "offline" in the UI with a distinct colour).
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Default weights — must sum to 1.0 ─────────────────────────────────────────
DEFAULT_WEIGHTS = {
    "email":      0.20,
    "url":        0.25,
    "network":    0.15,
    "attachment": 0.20,
    "ai":         0.10,
    "image":      0.10,
}


# ══════════════════════════════════════════════════════════════════════════════
# SCORE EXTRACTORS  (manual — by explicit scan ID)
# ══════════════════════════════════════════════════════════════════════════════

def _get_email_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import EmailScan
        r = EmailScan.query.get(scan_id)
        return float(r.risk_score or 0.0) if r else None
    except Exception as ex:
        logger.warning("EmailScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_url_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import URLScan
        r = URLScan.query.get(scan_id)
        if r is None:
            return None
        score = float(r.ml_score or 0.0)
        return score * 100.0 if score <= 1.0 else score
    except Exception as ex:
        logger.warning("URLScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_network_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import NetworkScan
        r = NetworkScan.query.get(scan_id)
        if r is None:
            return None
        return {"LOW": 10.0, "MEDIUM": 35.0,
                "HIGH": 65.0, "CRITICAL": 90.0, "UNKNOWN": 5.0
                }.get(r.risk_level or "UNKNOWN", 5.0)
    except Exception as ex:
        logger.warning("NetworkScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_attachment_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import AttachmentScan
        r = AttachmentScan.query.get(scan_id)
        if r is None:
            return None
        base = {"CLEAN": 5.0, "SUSPICIOUS": 50.0,
                "MALICIOUS": 90.0}.get(r.verdict or "CLEAN", 5.0)
        yara = len(json.loads(r.yara_matches or "[]")) * 10.0
        return min(base + yara, 100.0)
    except Exception as ex:
        logger.warning("AttachmentScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_ai_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import AIDetectionScan
        r = AIDetectionScan.query.get(scan_id)
        return float(r.risk_score or 0.0) if r else None
    except Exception as ex:
        logger.warning("AIDetectionScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_image_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import ImageAnalysisScan
        r = ImageAnalysisScan.query.get(scan_id)
        return float(r.risk_score or 0.0) if r else None
    except Exception as ex:
        logger.warning("ImageAnalysisScan fetch error id=%s: %s", scan_id, ex)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# AUTO EXTRACTORS — most recent row from each table
# Returns dict: {"score": float, "scan_id": int, "scanned_at": str} or None
# ══════════════════════════════════════════════════════════════════════════════

def _latest_email() -> Optional[dict]:
    try:
        from backend.app.models import EmailScan
        r = EmailScan.query.order_by(EmailScan.scanned_at.desc()).first()
        if r is None:
            return None
        return {
            "score":      float(r.risk_score or 0.0),
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        r.sender or r.subject or "—",
        }
    except Exception as ex:
        logger.warning("Auto email latest error: %s", ex)
        return None


def _latest_url() -> Optional[dict]:
    try:
        from backend.app.models import URLScan
        r = URLScan.query.order_by(URLScan.scanned_at.desc()).first()
        if r is None:
            return None
        score = float(r.ml_score or 0.0)
        if score <= 1.0:
            score = score * 100.0
        return {
            "score":      score,
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        r.domain or r.raw_url or "—",
        }
    except Exception as ex:
        logger.warning("Auto URL latest error: %s", ex)
        return None


def _latest_network() -> Optional[dict]:
    try:
        from backend.app.models import NetworkScan
        r = NetworkScan.query.order_by(NetworkScan.scanned_at.desc()).first()
        if r is None:
            return None
        score = {"LOW": 10.0, "MEDIUM": 35.0,
                 "HIGH": 65.0, "CRITICAL": 90.0, "UNKNOWN": 5.0
                 }.get(r.risk_level or "UNKNOWN", 5.0)
        return {
            "score":      score,
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        r.target or "—",
        }
    except Exception as ex:
        logger.warning("Auto network latest error: %s", ex)
        return None


def _latest_attachment() -> Optional[dict]:
    try:
        from backend.app.models import AttachmentScan
        r = AttachmentScan.query.order_by(AttachmentScan.scanned_at.desc()).first()
        if r is None:
            return None
        base = {"CLEAN": 5.0, "SUSPICIOUS": 50.0,
                "MALICIOUS": 90.0}.get(r.verdict or "CLEAN", 5.0)
        yara  = len(json.loads(r.yara_matches or "[]")) * 10.0
        score = min(base + yara, 100.0)
        return {
            "score":      score,
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        r.filename or "—",
        }
    except Exception as ex:
        logger.warning("Auto attachment latest error: %s", ex)
        return None


def _latest_ai() -> Optional[dict]:
    try:
        from backend.app.models import AIDetectionScan
        r = AIDetectionScan.query.order_by(AIDetectionScan.scanned_at.desc()).first()
        if r is None:
            return None
        return {
            "score":      float(r.risk_score or 0.0),
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        getattr(r, "source_ref", None) or "—",
        }
    except Exception as ex:
        logger.warning("Auto AI latest error: %s", ex)
        return None


def _latest_image() -> Optional[dict]:
    try:
        from backend.app.models import ImageAnalysisScan
        r = ImageAnalysisScan.query.order_by(
            ImageAnalysisScan.scanned_at.desc()).first()
        if r is None:
            return None
        return {
            "score":      float(r.risk_score or 0.0),
            "scan_id":    r.id,
            "scanned_at": r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
            "ref":        r.filename or "—",
        }
    except Exception as ex:
        logger.warning("Auto image latest error: %s", ex)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE STATUS PROBE
# Returns the online/offline status + latest scan info for all six modules.
# Called by the auto-mode UI before aggregation so it can show the status grid.
# ══════════════════════════════════════════════════════════════════════════════

MODULE_LABELS = {
    "email":      "Email Scan",
    "url":        "URL Scan",
    "network":    "Network Scan",
    "attachment": "Attachment",
    "ai":         "AI Detection",
    "image":      "Image Analysis",
}

_AUTO_FETCHERS = {
    "email":      _latest_email,
    "url":        _latest_url,
    "network":    _latest_network,
    "attachment": _latest_attachment,
    "ai":         _latest_ai,
    "image":      _latest_image,
}


def probe_module_status() -> dict:
    """
    Return online/offline status + latest scan metadata for all six modules.
    Called by GET /api/risk/status — consumed by the auto-mode status grid.

    Returns:
        {
          "email":      {"online": bool, "scan_id": int|None,
                         "score": float|None, "ref": str, "scanned_at": str},
          ...
        }
    """
    status = {}
    for key, fetcher in _AUTO_FETCHERS.items():
        latest = fetcher()
        if latest:
            status[key] = {
                "online":     True,
                "scan_id":    latest["scan_id"],
                "score":      round(latest["score"], 2),
                "ref":        latest["ref"],
                "scanned_at": latest["scanned_at"],
            }
        else:
            status[key] = {
                "online":     False,
                "scan_id":    None,
                "score":      None,
                "ref":        "—",
                "scanned_at": "",
            }
    return status


# ══════════════════════════════════════════════════════════════════════════════
# VERDICT / EXPLANATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _score_to_verdict(score: float) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "CLEAN"


def _verdict_to_action(verdict: str) -> str:
    return {"CLEAN": "ALLOW", "SUSPICIOUS": "WARN",
            "MALICIOUS": "BLOCK"}.get(verdict, "WARN")


def _build_explanation(
    final_score: float,
    verdict: str,
    breakdown: dict,
    phases_used: list,
    mode: str = "manual",
) -> str:
    parts = [
        f"[{mode.upper()} MODE] Aggregated across "
        f"{len(phases_used)} phase(s): {', '.join(phases_used)}."
    ]
    if breakdown:
        top = max(breakdown.items(), key=lambda x: x[1]["weighted"])
        parts.append(
            f"Largest contributor: {top[0].title()} "
            f"(raw {top[1]['raw']:.1f} → weighted {top[1]['weighted']:.1f})."
        )
    parts.append(f"Final score: {final_score:.1f}/100 — verdict: {verdict}.")
    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# SHARED AGGREGATION CORE
# ══════════════════════════════════════════════════════════════════════════════

def _aggregate_fetched(fetched: dict, mode: str, weights: Optional[dict] = None) -> dict:
    """
    Given a dict of {phase: {raw, weight, scan_id}} already fetched,
    compute the weighted average and return the full result dict.
    """
    if not fetched:
        return {
            "error":       "No valid scan data found.",
            "final_score": 0.0,
            "verdict":     "UNKNOWN",
            "action":      "WARN",
            "phases_used": [],
            "breakdown":   {},
            "explanation": "No valid scan records found.",
            "mode":        mode,
        }

    total_weight = sum(v["weight"] for v in fetched.values())
    breakdown    = {}
    weighted_sum = 0.0

    for phase, data in fetched.items():
        norm_weight  = data["weight"] / total_weight
        weighted_val = data["raw"] * norm_weight
        weighted_sum += weighted_val
        breakdown[phase] = {
            "raw":          round(data["raw"], 2),
            "weight":       round(data["weight"], 4),
            "norm_weight":  round(norm_weight, 4),
            "weighted":     round(weighted_val, 2),
            "scan_id":      data["scan_id"],
            "pct_of_total": round((data["weight"] / total_weight) * 100, 1),
        }

    final_score = round(weighted_sum, 2)
    verdict     = _score_to_verdict(final_score)
    action      = _verdict_to_action(verdict)
    phases_used = sorted(fetched.keys())

    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    return {
        "final_score":  final_score,
        "verdict":      verdict,
        "action":       action,
        "phases_used":  phases_used,
        "breakdown":    breakdown,
        "explanation":  _build_explanation(
            final_score, verdict, breakdown, phases_used, mode
        ),
        "weights_used": {k: round(v, 4) for k, v in w.items()},
        "mode":         mode,
        "error":        None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ══════════════════════════════════════════════════════════════════════════════

def aggregate_risk_scores(
    email_scan_id:   Optional[int] = None,
    url_scan_id:     Optional[int] = None,
    network_scan_id: Optional[int] = None,
    attachment_id:   Optional[int] = None,
    ai_detection_id: Optional[int] = None,
    image_scan_id:   Optional[int] = None,
    weights:         Optional[dict] = None,
) -> dict:
    """Manual mode — aggregate by explicit scan IDs."""
    w       = {**DEFAULT_WEIGHTS, **(weights or {})}
    fetched = {}

    _pairs = [
        ("email",      email_scan_id,   _get_email_score),
        ("url",        url_scan_id,     _get_url_score),
        ("network",    network_scan_id, _get_network_score),
        ("attachment", attachment_id,   _get_attachment_score),
        ("ai",         ai_detection_id, _get_ai_score),
        ("image",      image_scan_id,   _get_image_score),
    ]

    for phase, scan_id, getter in _pairs:
        if scan_id:
            s = getter(scan_id)
            if s is not None:
                fetched[phase] = {
                    "raw":     s,
                    "weight":  w[phase],
                    "scan_id": scan_id,
                }

    return _aggregate_fetched(fetched, mode="manual", weights=weights)


def aggregate_risk_scores_auto(weights: Optional[dict] = None) -> dict:
    """
    Automatic mode — pulls the most recent scan from every module that has
    any data. Modules with no records are excluded from the calculation and
    returned as offline in the status grid.
    """
    w       = {**DEFAULT_WEIGHTS, **(weights or {})}
    fetched = {}

    for phase, fetcher in _AUTO_FETCHERS.items():
        latest = fetcher()
        if latest is not None:
            fetched[phase] = {
                "raw":     latest["score"],
                "weight":  w[phase],
                "scan_id": latest["scan_id"],
            }

    return _aggregate_fetched(fetched, mode="auto", weights=weights)