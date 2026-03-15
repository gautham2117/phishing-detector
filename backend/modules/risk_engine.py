"""
backend/modules/risk_aggregator.py
Phase 10 — Risk Score Aggregator Engine
Pulls existing scan records from the DB and computes
a weighted aggregate risk score across all phases.
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
# SCORE EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

def _get_email_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import EmailScan
        r = EmailScan.query.get(scan_id)
        if r is None:
            return None
        return float(r.risk_score or 0.0)
    except Exception as ex:
        logger.warning("EmailScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_url_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import URLScan
        r = URLScan.query.get(scan_id)
        if r is None:
            return None
        score = r.ml_score or 0.0
        # ml_score is stored as 0–1 in some versions, normalise to 0–100
        if score <= 1.0:
            score = score * 100.0
        return float(score)
    except Exception as ex:
        logger.warning("URLScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_network_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import NetworkScan
        r = NetworkScan.query.get(scan_id)
        if r is None:
            return None
        score_map = {
            "LOW": 10.0, "MEDIUM": 35.0,
            "HIGH": 65.0, "CRITICAL": 90.0, "UNKNOWN": 5.0
        }
        return score_map.get(r.risk_level or "UNKNOWN", 5.0)
    except Exception as ex:
        logger.warning("NetworkScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_attachment_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import AttachmentScan
        r = AttachmentScan.query.get(scan_id)
        if r is None:
            return None
        verdict_map = {
            "CLEAN": 5.0, "SUSPICIOUS": 50.0, "MALICIOUS": 90.0
        }
        # Use entropy-based proxy if no direct score field
        base  = verdict_map.get(r.verdict or "CLEAN", 5.0)
        yara  = len(json.loads(r.yara_matches or "[]")) * 10.0
        return min(base + yara, 100.0)
    except Exception as ex:
        logger.warning("AttachmentScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_ai_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import AIDetectionScan
        r = AIDetectionScan.query.get(scan_id)
        if r is None:
            return None
        return float(r.risk_score or 0.0)
    except Exception as ex:
        logger.warning("AIDetectionScan fetch error id=%s: %s", scan_id, ex)
        return None


def _get_image_score(scan_id: int) -> Optional[float]:
    try:
        from backend.app.models import ImageAnalysisScan
        r = ImageAnalysisScan.query.get(scan_id)
        if r is None:
            return None
        return float(r.risk_score or 0.0)
    except Exception as ex:
        logger.warning("ImageAnalysisScan fetch error id=%s: %s", scan_id, ex)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# VERDICT
# ══════════════════════════════════════════════════════════════════════════════

def _score_to_verdict(score: float) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "CLEAN"


def _verdict_to_action(verdict: str) -> str:
    return {
        "CLEAN":     "ALLOW",
        "SUSPICIOUS":"WARN",
        "MALICIOUS": "BLOCK",
    }.get(verdict, "WARN")


# ══════════════════════════════════════════════════════════════════════════════
# EXPLANATION
# ══════════════════════════════════════════════════════════════════════════════

def _build_explanation(
    final_score: float,
    verdict: str,
    breakdown: dict,
    phases_used: list,
) -> str:
    parts = [
        f"Aggregated across {len(phases_used)} phase(s): "
        f"{', '.join(phases_used)}."
    ]

    # Find the highest-contributing phase
    if breakdown:
        top = max(breakdown.items(), key=lambda x: x[1]["weighted"])
        parts.append(
            f"Largest contributor: {top[0].title()} "
            f"(raw {top[1]['raw']:.1f} → weighted {top[1]['weighted']:.1f})."
        )

    parts.append(
        f"Final score: {final_score:.1f}/100 — verdict: {verdict}."
    )
    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
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
    """
    Pull scores from each provided scan ID, apply weights,
    and return a full aggregation result dict.

    At least one scan ID must be provided.
    Missing IDs are simply excluded from the weighted average.
    """

    w = {**DEFAULT_WEIGHTS, **(weights or {})}

    # ── Fetch scores ──────────────────────────────────────────────────────
    fetched = {}

    if email_scan_id:
        s = _get_email_score(email_scan_id)
        if s is not None:
            fetched["email"] = {"raw": s, "weight": w["email"], "scan_id": email_scan_id}

    if url_scan_id:
        s = _get_url_score(url_scan_id)
        if s is not None:
            fetched["url"] = {"raw": s, "weight": w["url"], "scan_id": url_scan_id}

    if network_scan_id:
        s = _get_network_score(network_scan_id)
        if s is not None:
            fetched["network"] = {"raw": s, "weight": w["network"], "scan_id": network_scan_id}

    if attachment_id:
        s = _get_attachment_score(attachment_id)
        if s is not None:
            fetched["attachment"] = {"raw": s, "weight": w["attachment"], "scan_id": attachment_id}

    if ai_detection_id:
        s = _get_ai_score(ai_detection_id)
        if s is not None:
            fetched["ai"] = {"raw": s, "weight": w["ai"], "scan_id": ai_detection_id}

    if image_scan_id:
        s = _get_image_score(image_scan_id)
        if s is not None:
            fetched["image"] = {"raw": s, "weight": w["image"], "scan_id": image_scan_id}

    if not fetched:
        return {
            "error":       "No valid scan IDs provided or no records found.",
            "final_score": 0.0,
            "verdict":     "UNKNOWN",
            "action":      "WARN",
            "phases_used": [],
            "breakdown":   {},
            "explanation": "No valid scan records found for the provided IDs.",
        }

    # ── Weighted average ──────────────────────────────────────────────────
    # Re-normalise weights to only the phases that were actually fetched
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

    return {
        "final_score": final_score,
        "verdict":     verdict,
        "action":      action,
        "phases_used": phases_used,
        "breakdown":   breakdown,
        "explanation": _build_explanation(final_score, verdict, breakdown, phases_used),
        "weights_used": {k: round(v, 4) for k, v in w.items()},
        "error":       None,
    }