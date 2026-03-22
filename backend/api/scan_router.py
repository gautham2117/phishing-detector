# backend/api/scan_router.py
# FastAPI route handlers for all scan endpoints.
# Phases 1–16 fully integrated with auto-alert hooks.
#
# FIXES APPLIED:
#   1. All _save_* helpers now wrap DB ops in _flask_ctx()
#   2. scan_url / scan_url_batch / extension_scan now correctly extract
#      risk_score + label from url_intelligence result
#   3. _save_url_scan now uses correct field names
#   4. _build_url_explanation now uses correct fields
#   5. scan_url_batch now calls analyze_url() per-URL
#   6. _save_email_scan wrapped in _flask_ctx()
#   7. Phase 10 — Added missing FastAPI routes:
#        GET  /risk/status         → probe_module_status()
#        POST /risk/aggregate/auto → aggregate_risk_scores_auto()
#
# EXPLANATION UPGRADE:
#   8. _build_file_explanation() returns structured dict with sections.
#
# CAPA INTEGRATION (Task 1):
#   9. _build_file_explanation() includes capa_analysis section.
#
# PHASE FEATURE ADDITIONS (Task 2):
#  10. Phase 1 — _calculate_phase1_risk(): +15pts per DNSBL zone hit
#      (capped at +30 total), +20pts if BEC suspect.
#      _build_email_explanation(): surfaces DNSBL zones hit and BEC signals.
#  11. Phase 2 — _build_url_explanation(): surfaces typosquatting closest
#      brand + edit distance, and cert transparency freshness flag.
#  12. Phase 3 — _build_network_explanation(): surfaces CVE critical findings
#      from port-level cve_data dicts.

import io as _io
import json
import logging
import datetime
from typing import Optional, List

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Query, Request # pyright: ignore[reportMissingImports]
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel as PydanticBase

from backend.modules.email_parser       import parse_email
from backend.modules.url_intelligence   import analyze_url
from backend.modules.network_scanner    import scan_target, is_demo_target
from backend.modules.rule_engine        import (
    analyze_url_rules, analyze_email_rules, get_all_rules
)
from backend.modules.ml_url_classifier  import classify_url, classify_url_batch
from backend.modules.file_analyzer      import analyze_file
from backend.modules.image_analyzer     import analyze_image
from backend.modules.ai_detector        import (
    detect_ai_content,
    extract_text_from_url,
    extract_text_from_file,
)
from backend.modules.platform_monitor   import (
    scan_target_full, extract_domain,
    get_due_targets, get_unified_feed
)
from backend.modules.risk_engine        import aggregate_risk_scores
from backend.modules.risk_engine    import (
    aggregate_risk_scores_auto,
    probe_module_status,
)
from backend.modules.model_manager      import (
    add_feedback_label, get_feedback_queue,
    get_model_versions, get_training_state,
    trigger_retrain, get_huggingface_finetune_plan,
)
from backend.modules.alert_engine       import (
    create_alert, get_alerts, get_alert_detail,
    acknowledge_alert, dismiss_alert,
    export_alerts_csv, export_alert_pdf,
    get_audit_log, get_alert_stats,
)

from backend.app.database import db
from backend.app.models   import (
    EmailScan, URLScan, NetworkScan, PortResult,
    AttachmentScan, AIDetectionScan, ImageAnalysisScan,
    MonitoredTarget, MonitorScanResult,
    AggregatedRiskScore, FeedbackSample, ModelVersion,
    ExtensionScan
)
from backend.app.utils.response import build_response, error_response
from backend.modules.system_health import (
    check_module_health,
    get_system_metrics,
    get_db_stats,
    get_requests_per_minute,
    get_request_rate_history,
    get_migration_plan,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Flask app context helper
# ─────────────────────────────────────────────────────────────────────────────

def _flask_ctx():
    from backend.app import create_app as _cfa
    return _cfa().app_context()


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic request models
# ─────────────────────────────────────────────────────────────────────────────

class EmailScanRequest(PydanticBase):
    raw_email:  str
    submitter:  Optional[str] = "anonymous"


class URLScanRequest(PydanticBase):
    url:        str
    submitter:  Optional[str] = "anonymous"


class SMSScanRequest(PydanticBase):
    message:    str
    submitter:  Optional[str] = "anonymous"


class NetworkScanRequest(PydanticBase):
    target:             str
    scan_type:          str  = "top100"
    consent_confirmed:  bool = False
    url_scan_id:        Optional[int] = None
    email_scan_id:      Optional[int] = None


class RuleScanURLRequest(PydanticBase):
    url:       str
    submitter: Optional[str] = "anonymous"


class RuleScanEmailRequest(PydanticBase):
    subject:      str          = ""
    body_text:    str          = ""
    body_html:    str          = ""
    urls:         List[dict]   = []
    submitter:    Optional[str] = "anonymous"


class MLScanRequest(PydanticBase):
    url:         str
    rf_weight:   float = 0.45
    bert_weight: float = 0.55
    submitter:   Optional[str] = "anonymous"


class AddTargetRequest(PydanticBase):
    url:              str
    label:            Optional[str] = ""
    interval_minutes: int           = 60
    alert_threshold:  float         = 50.0


class AggregateRequest(PydanticBase):
    email_scan_id:   Optional[int]  = None
    url_scan_id:     Optional[int]  = None
    network_scan_id: Optional[int]  = None
    attachment_id:   Optional[int]  = None
    ai_detection_id: Optional[int]  = None
    image_scan_id:   Optional[int]  = None
    weights:         Optional[dict] = None


class AutoAggregateRequest(PydanticBase):
    weights: Optional[dict] = None


class FeedbackLabelRequest(PydanticBase):
    url:            str
    label_type:     str
    feedback_label: str
    original_label: Optional[str] = ""
    url_scan_id:    Optional[int] = None
    admin_note:     Optional[str] = ""


class CreateAlertRequest(PydanticBase):
    module:             str
    input_type:         str
    scan_id:            Optional[int]  = None
    risk_score:         float          = 0.0
    verdict:            str            = "SUSPICIOUS"
    recommended_action: str            = "WARN"
    triggered_rules:    Optional[list] = []
    ml_verdicts:        Optional[dict] = {}
    raw_findings:       Optional[dict] = {}
    actor:              Optional[str]  = "admin"


class AcknowledgeRequest(PydanticBase):
    actor: Optional[str] = "admin"


class DismissRequest(PydanticBase):
    reason: Optional[str] = ""
    actor:  Optional[str] = "admin"


class AIDetectTextRequest(PydanticBase):
    text:       str
    source_ref: Optional[str] = ""


class AIDetectURLRequest(PydanticBase):
    url: str


# ─────────────────────────────────────────────────────────────────────────────
# Shared scoring helpers
# ─────────────────────────────────────────────────────────────────────────────

def _score_to_label(score: float) -> str:
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


def _label_to_action(label: str) -> str:
    return {
        "SAFE":       "ALLOW",
        "BENIGN":     "ALLOW",
        "SUSPICIOUS": "WARN",
        "MALICIOUS":  "QUARANTINE",
    }.get(label, "WARN")


def _risk_level_to_label(risk_level: str) -> str:
    return {
        "LOW":      "SAFE",
        "MEDIUM":   "SUSPICIOUS",
        "HIGH":     "SUSPICIOUS",
        "CRITICAL": "MALICIOUS",
        "UNKNOWN":  "SUSPICIOUS",
    }.get(risk_level, "SUSPICIOUS")


# ─────────────────────────────────────────────────────────────────────────────
# URL result score/label extractor
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Trusted domain allowlist
# ─────────────────────────────────────────────────────────────────────────────
# Apex domains with established, well-known reputations.
# When the scanned domain matches one of these exactly (or is a direct
# subdomain), the ML model score is ignored and the final risk score is
# capped at 15 (always SAFE).
#
# Rationale: the ML model (elftsdmr/malware-url-detect) is a small
# HuggingFace model with known high false-positive rates on short, common
# URLs like "https://linkedin.com/feed". Structural heuristics (young domain,
# bad SSL, suspicious TLD, redirect chains) are far more reliable signals
# than this model alone for well-known domains.
#
# This list only contains domains whose ownership and reputation are
# definitively established. Do NOT add arbitrary domains here.

_TRUSTED_DOMAINS: frozenset = frozenset({
    # Professional / social networks
    "linkedin.com", "twitter.com", "x.com", "facebook.com",
    "instagram.com", "reddit.com", "tiktok.com", "youtube.com",
    "pinterest.com", "snapchat.com", "discord.com", "slack.com",
    "whatsapp.com", "telegram.org", "signal.org",
    # Search / cloud / productivity
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "gmail.com", "outlook.com", "office.com", "microsoft.com",
    "apple.com", "icloud.com",
    "amazon.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    # Developer / infra
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "npmjs.com", "pypi.org",
    "docker.com", "kubernetes.io", "digitalocean.com",
    # Finance (major institutions only)
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    # News / reference
    "wikipedia.org", "bbc.com", "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com",
})


def _is_trusted_domain(domain: str) -> bool:
    """
    Return True if `domain` is in the trusted allowlist OR is a direct
    subdomain of a trusted apex.

    e.g. "mail.google.com"  → True  (subdomain of google.com)
         "evil-google.com"  → False (not a subdomain)
         "linkedin.com"     → True  (exact match)
    """
    d = domain.lower().lstrip("www.").split(":")[0]
    if d in _TRUSTED_DOMAINS:
        return True
    for apex in _TRUSTED_DOMAINS:
        if d.endswith("." + apex):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# URL result score/label extractor  ← FIXED (3 false-positive safeguards)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_url_risk(result: dict) -> tuple:
    """
    Compute a 0–100 risk score and SAFE/SUSPICIOUS/MALICIOUS label.

    Three safeguards against ML model false positives
    (e.g. linkedin.com scoring 98.7 as MALICIOUS):

    Fix 1 — Trusted domain cap:
        Well-known apex domains (linkedin.com, google.com, etc.) have their
        score hard-capped at 15 regardless of ML output. Structural heuristics
        (SSL, domain age, redirect chain, suspicious TLD) still apply but the
        ML score is ignored for these domains.

    Fix 2 — ML weight reduction when no corroborating flags fire:
        If the ML model says MALICIOUS but zero flags are present AND the
        domain age flag is not set, the ML base score is reduced by 40%.
        A model claiming near-certain maliciousness on a URL with no
        structural anomalies should not be trusted at face value.

    Fix 3 — MALICIOUS requires corroboration:
        After all penalties are applied, a MALICIOUS label (score >= 70)
        is only kept if at least one of these corroborating signals exists:
          - At least 1 flag fired (any severity)
          - Domain age flag is set (young domain)
          - Typosquatting was detected
          - Cert transparency fresh flag is set
        If none of these exist, the label is downgraded to SUSPICIOUS and
        the score is capped at 69.0. The ML model alone cannot convict.
    """
    domain = result.get("domain", "")
    ml     = result.get("ml_result", {})

    # ── Fix 1: Trusted domain — ignore ML, cap score at 15 ───────────────
    if _is_trusted_domain(domain):
        flags        = result.get("flags", [])
        flag_penalty = 0.0
        for f in flags:
            sev = f.get("severity", "low")
            if sev == "high":
                flag_penalty += 4.0    # halved weights for trusted domains
            elif sev == "medium":
                flag_penalty += 2.0
            else:
                flag_penalty += 0.5
        flag_penalty = min(flag_penalty, 10.0)
        risk_score   = min(round(5.0 + flag_penalty, 2), 15.0)
        return risk_score, _score_to_label(risk_score)

    # ── Normal scoring path ───────────────────────────────────────────────
    ml_score  = float(ml.get("score", 0.0))
    flags     = result.get("flags", [])
    has_flags = len(flags) > 0
    age_flag  = result.get("domain_age_flag", False)

    # ── Fix 2: Reduce ML weight when no corroborating evidence ───────────
    # If the model screams MALICIOUS but nothing else is wrong structurally,
    # apply a 40% penalty to its contribution.
    if ml.get("label") == "MALICIOUS" and not has_flags and not age_flag:
        ml_score = ml_score * 0.60

    base_score = round(ml_score * 100, 2)

    flag_penalty = 0.0
    for f in flags:
        sev = f.get("severity", "low")
        if sev == "high":
            flag_penalty += 8.0
        elif sev == "medium":
            flag_penalty += 4.0
        else:
            flag_penalty += 1.0
    flag_penalty = min(flag_penalty, 20.0)

    age_penalty = 5.0 if age_flag else 0.0
    risk_score  = min(round(base_score + flag_penalty + age_penalty, 2), 100.0)
    label       = _score_to_label(risk_score)

    # ── Fix 3: MALICIOUS requires at least one corroborating signal ───────
    if label == "MALICIOUS":
        typo_suspect = result.get("typosquatting", {}).get(
            "is_typosquatting_suspect", False
        )
        ct_fresh = result.get("cert_transparency", {}).get(
            "is_freshly_certified", False
        )
        has_corroboration = has_flags or age_flag or typo_suspect or ct_fresh

        if not has_corroboration:
            risk_score = min(risk_score, 69.0)
            label      = "SUSPICIOUS"
            logger.info(
                "URL %s: ML MALICIOUS downgraded to SUSPICIOUS "
                "(no corroborating structural signals)", domain
            )

    return risk_score, label

# ─────────────────────────────────────────────────────────────────────────────
# Phase 13 — Auto-alert helper
# ─────────────────────────────────────────────────────────────────────────────

def _auto_alert(
    module:      str,
    input_type:  str,
    scan_id:     Optional[int],
    risk_score:  float,
    verdict:     str,
    action:      str,
    findings:    dict = None,
    rules:       list = None,
    ml_verdicts: dict = None,
) -> None:
    if verdict.upper() not in (
        "SUSPICIOUS", "MALICIOUS", "PHISHING",
        "AI_GENERATED", "HIGH", "CRITICAL"
    ) and risk_score < 35:
        return
    try:
        with _flask_ctx():
            create_alert(
                module             = module,
                input_type         = input_type,
                scan_id            = scan_id,
                risk_score         = risk_score,
                verdict            = verdict,
                recommended_action = action,
                triggered_rules    = rules       or [],
                ml_verdicts        = ml_verdicts or {},
                raw_findings       = findings    or {},
                actor              = "system",
            )
    except Exception as ex:
        logger.warning("Auto-alert failed for %s: %s", module, ex)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Email scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/email", summary="Scan raw email text", tags=["Email Scanning"])
async def scan_email_text(request: EmailScanRequest):
    try:
        parsed     = parse_email(request.raw_email)
        risk_score = _calculate_phase1_risk(parsed)
        label      = _score_to_label(risk_score)
        action     = _label_to_action(label)
        scan_id    = _save_email_scan(parsed, risk_score, label)

        _auto_alert(
            "Email", "email", scan_id, risk_score, label, action,
            findings={
                "anomalies": parsed.get("anomalies", []),
                "urls":      parsed.get("urls", []),
            },
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={
                "email_parser": {
                    "sender":           parsed["sender"],
                    "recipient":        parsed["recipient"],
                    "reply_to":         parsed["reply_to"],
                    "subject":          parsed["subject"],
                    "date":             parsed["date"],
                    "auth_results":     parsed["auth_results"],
                    "anomalies":        parsed["anomalies"],
                    "url_count":        len(parsed["urls"]),
                    "attachment_count": len(parsed["attachments"]),
                    "urls":             parsed["urls"],
                    "distilbert":       parsed["distilbert_result"],
                    "dnsbl_result":     parsed.get("dnsbl_result", {}),
                    "bec_result":       parsed.get("bec_result", {}),
                }
            },
            explanation=_build_email_explanation(parsed, label),
            recommended_action=action,
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"Email scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"Email scan error: {str(e)}")
        )


@router.post("/scan/email/upload", summary="Upload and scan a .eml file",
             tags=["Email Scanning"])
async def scan_email_file(
    file:      UploadFile    = File(...),
    submitter: Optional[str] = Form(default="anonymous"),
):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files accepted.")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB).")

    try:
        parsed     = parse_email(file_bytes)
        risk_score = _calculate_phase1_risk(parsed)
        label      = _score_to_label(risk_score)
        action     = _label_to_action(label)
        scan_id    = _save_email_scan(parsed, risk_score, label,
                                      filename=file.filename)

        _auto_alert(
            "Email", "email_upload", scan_id, risk_score, label, action,
            findings={"anomalies": parsed.get("anomalies", [])},
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={
                "email_parser": {
                    "filename":         file.filename,
                    "sender":           parsed["sender"],
                    "recipient":        parsed["recipient"],
                    "reply_to":         parsed["reply_to"],
                    "subject":          parsed["subject"],
                    "date":             parsed["date"],
                    "auth_results":     parsed["auth_results"],
                    "anomalies":        parsed["anomalies"],
                    "url_count":        len(parsed["urls"]),
                    "attachment_count": len(parsed["attachments"]),
                    "urls":             parsed["urls"],
                    "distilbert":       parsed["distilbert_result"],
                    "dnsbl_result":     parsed.get("dnsbl_result", {}),
                    "bec_result":       parsed.get("bec_result", {}),
                }
            },
            explanation=_build_email_explanation(parsed, label),
            recommended_action=action,
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"EML upload scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — URL scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/url", summary="Full URL intelligence analysis",
             tags=["URL Scanning"])
async def scan_url(request: URLScanRequest):
    try:
        result               = analyze_url(request.url)
        risk_score, label    = _extract_url_risk(result)
        action               = _label_to_action(label)
        result["risk_score"] = risk_score
        result["label"]      = label
        scan_id              = _save_url_scan(result, email_id=None)

        _auto_alert(
            "URL", "url", scan_id, risk_score, label, action,
            findings={
                "flags": [f.get("flag", "") for f in result.get("flags", [])]
            },
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={"url_intelligence": result},
            explanation=_build_url_explanation(result),
            recommended_action=action,
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"URL scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"URL scan error: {str(e)}")
        )


@router.post("/scan/url/batch", summary="Scan multiple URLs",
             tags=["URL Scanning"])
async def scan_url_batch(
    urls: List[str],
    email_scan_id: Optional[int] = Query(default=None),
):
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty.")
    if len(urls) > 50:
        raise HTTPException(status_code=400, detail="Batch limit is 50 URLs.")

    try:
        results = []
        for url in urls:
            r                = analyze_url(url)
            rs, lbl          = _extract_url_risk(r)
            r["risk_score"]  = rs
            r["label"]       = lbl
            results.append(r)
            _save_url_scan(r, email_id=email_scan_id)

        max_score = max((r["risk_score"] for r in results), default=0.0)
        max_label = _score_to_label(max_score)

        return build_response(
            status="success",
            risk_score=max_score,
            label=max_label,
            module_results={
                "url_batch": {
                    "total_urls": len(results),
                    "malicious":  sum(1 for r in results if r["label"] == "MALICIOUS"),
                    "suspicious": sum(1 for r in results if r["label"] == "SUSPICIOUS"),
                    "safe":       sum(1 for r in results if r["label"] == "SAFE"),
                    "results":    results,
                }
            },
            explanation=(
                f"Analyzed {len(results)} URL(s). "
                f"Highest risk score: {max_score:.1f}/100."
            ),
            recommended_action=_label_to_action(max_label),
        )

    except Exception as e:
        logger.error(f"Batch URL scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Network scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/network", summary="Network port scan",
             tags=["Network Scanning"])
async def scan_network(request: NetworkScanRequest):
    try:
        result  = scan_target(
            target            = request.target,
            scan_type         = request.scan_type,
            consent_confirmed = request.consent_confirmed,
            url_scan_id       = request.url_scan_id,
            email_scan_id     = request.email_scan_id,
        )
        scan_id = _save_network_scan(result)
        label   = _risk_level_to_label(result["risk_level"])
        score   = {
            "LOW": 10, "MEDIUM": 35, "HIGH": 65,
            "CRITICAL": 90, "UNKNOWN": 0,
        }.get(result["risk_level"], 0)

        _auto_alert(
            "Network", "network", scan_id, score, label,
            _label_to_action(label),
            findings={"risk_flags": result.get("risk_flags", [])},
        )

        return build_response(
            status="success" if result.get("authorized") else "blocked",
            risk_score=score,
            label=label,
            module_results={"network_scan": result},
            explanation=_build_network_explanation(result),
            recommended_action=_label_to_action(label),
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"Network scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Rule engine
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/rules/url", summary="Rule engine — URL",
             tags=["Rule Engine"])
async def scan_url_rules(request: RuleScanURLRequest):
    try:
        result = analyze_url_rules(request.url)
        label  = _score_to_label(result["rule_score"])
        action = _label_to_action(label)

        _auto_alert(
            "Rules", "url", None,
            result["rule_score"], label, action,
            rules=[h.get("name", "") for h in result.get("hits", [])],
        )

        return build_response(
            status="success",
            risk_score=result["rule_score"],
            label=label,
            module_results={"rule_engine": result},
            explanation=_build_rules_explanation(result),
            recommended_action=action,
        )

    except Exception as e:
        logger.error(f"URL rule scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


@router.post("/scan/rules/email", summary="Rule engine — Email",
             tags=["Rule Engine"])
async def scan_email_rules(request: RuleScanEmailRequest):
    try:
        result = analyze_email_rules(
            subject=request.subject,
            body_text=request.body_text,
            body_html=request.body_html,
            urls=request.urls,
        )
        label  = _score_to_label(result["rule_score"])
        action = _label_to_action(label)

        _auto_alert(
            "Rules", "email", None,
            result["rule_score"], label, action,
            rules=[h.get("name", "") for h in result.get("hits", [])],
        )

        return build_response(
            status="success",
            risk_score=result["rule_score"],
            label=label,
            module_results={"rule_engine": result},
            explanation=_build_rules_explanation(result),
            recommended_action=action,
        )

    except Exception as e:
        logger.error(f"Email rule scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


@router.get("/rules/list", summary="List all heuristic rules",
            tags=["Rule Engine"])
async def list_all_rules():
    all_rules = get_all_rules()
    return {
        "status": "success",
        "rules":  all_rules,
        "total":  len(all_rules),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — ML Classifier
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/ml/url", summary="RF + BERT ensemble classifier",
             tags=["ML Classifier"])
async def scan_ml_url(request: MLScanRequest):
    try:
        result     = classify_url(
            url         = request.url,
            rf_weight   = request.rf_weight,
            bert_weight = request.bert_weight,
        )
        risk_score = round(result["ensemble_score"] * 100, 2)
        label      = (
            "MALICIOUS"  if risk_score >= 70 else
            "SUSPICIOUS" if risk_score >= 30 else
            "SAFE"
        )
        action = _label_to_action(label)

        _auto_alert(
            "ML Classifier", "url", None,
            risk_score, label, action,
            ml_verdicts={"ensemble_score": result.get("ensemble_score", 0)},
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={"ml_classifier": result},
            explanation=result["explanation"],
            recommended_action=action,
        )

    except Exception as e:
        logger.error(f"ML classifier error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


@router.post("/scan/ml/url/batch", summary="ML batch classification",
             tags=["ML Classifier"])
async def scan_ml_url_batch(urls: List[str]):
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty.")
    if len(urls) > 30:
        raise HTTPException(status_code=400, detail="Batch limit is 30 URLs.")

    try:
        results    = classify_url_batch(urls)
        max_score  = max(r["ensemble_score"] for r in results)
        risk_score = round(max_score * 100, 2)
        label      = (
            "MALICIOUS"  if risk_score >= 70 else
            "SUSPICIOUS" if risk_score >= 30 else
            "SAFE"
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={
                "ml_classifier_batch": {
                    "total":   len(results),
                    "results": results,
                }
            },
            explanation=(
                f"Classified {len(results)} URLs. "
                f"Highest ensemble score: {max_score:.2f}."
            ),
            recommended_action=_label_to_action(label),
        )

    except Exception as e:
        logger.error(f"ML batch error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — File / Attachment analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/file", summary="Analyse uploaded file",
             tags=["File Analysis"])
async def scan_file(
    file:          UploadFile    = File(...),
    email_scan_id: Optional[int] = Form(default=None),
):
    try:
        file_bytes = await file.read()
        filename   = file.filename or "unknown_file"

        if not file_bytes:
            raise HTTPException(status_code=400, detail="Empty file received.")

        result  = analyze_file(file_bytes, filename)
        score   = result.get("risk_score", 5.0)
        verdict = result.get("verdict", "CLEAN")

        label_map = {
            "CLEAN":      "SAFE",
            "SUSPICIOUS": "SUSPICIOUS",
            "MALICIOUS":  "MALICIOUS",
        }
        label  = label_map.get(verdict, "SUSPICIOUS")
        action = _label_to_action(label)

        explanation = _build_file_explanation(result, filename, score, verdict, action)

        db_id = _save_attachment_scan(result, filename, email_scan_id)
        result["email_scan_id"] = email_scan_id
        result["db_id"]         = db_id

        _auto_alert(
            "Attachment", "file", db_id,
            score, label, action,
            findings=result,
            rules=result.get("yara_matches", []),
        )

        return build_response(
            status="success",
            risk_score=score,
            label=label,
            module_results={"file_analysis": result},
            explanation=explanation,
            recommended_action=action,
        ) | {"scan_id": db_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"File analysis failed: {str(e)[:200]}")
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 — Image analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/image", summary="Analyse uploaded image",
             tags=["Image Analysis"])
async def scan_image(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        filename   = file.filename or "unknown_image"

        if not file_bytes:
            raise HTTPException(status_code=400, detail="Empty file received.")

        result  = analyze_image(file_bytes, filename)
        verdict = result.get("verdict", "CLEAN")
        score   = result.get("risk_score", 5.0)

        label_map = {
            "CLEAN":      "SAFE",
            "SUSPICIOUS": "SUSPICIOUS",
            "MALICIOUS":  "MALICIOUS",
        }
        label  = label_map.get(verdict, "SUSPICIOUS")
        action = _label_to_action(label)

        db_id           = _save_image_scan(result, filename)
        result["db_id"] = db_id

        _auto_alert(
            "Image", "image", db_id,
            score, label, action,
            findings={
                "detected_brands":   result.get("detected_brands", []),
                "phishing_keywords": result.get("phishing_keywords", []),
            },
            ml_verdicts={
                "classifier": result.get(
                    "classifier_result", {}
                ).get("label", ""),
            },
        )

        return build_response(
            status="success",
            risk_score=score,
            label=label,
            module_results={"image_analysis": result},
            explanation=result.get("explanation", "Image analysis complete."),
            recommended_action=action,
        ) | {"scan_id": db_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"Image analysis failed: {str(e)[:200]}")
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — AI-Generated Content Detection
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/scan/ai/text", summary="AI content detection — text",
             tags=["AI Detection"])
async def scan_ai_text(request: AIDetectTextRequest):
    try:
        result = detect_ai_content(
            text       = request.text,
            source_ref = request.source_ref or "",
            input_type = "text",
        )
        db_id  = _save_ai_detection_scan(result)
        label  = _ai_verdict_to_label(result["verdict"])
        action = _label_to_action(label)

        _auto_alert(
            "AI Detection", "text", db_id,
            result["risk_score"], result["verdict"], action,
            findings={"ai_probability": result.get("ai_probability")},
        )

        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=label,
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=action,
        ) | {"scan_id": db_id}

    except Exception as e:
        logger.error(f"AI text detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


@router.post("/scan/ai/url", summary="AI content detection — URL",
             tags=["AI Detection"])
async def scan_ai_url(request: AIDetectURLRequest):
    try:
        text = extract_text_from_url(request.url)
        if not text.strip():
            return JSONResponse(
                status_code=422,
                content=error_response("Could not extract text from URL.")
            )
        result = detect_ai_content(
            text       = text,
            source_ref = request.url,
            input_type = "url",
        )
        db_id  = _save_ai_detection_scan(result)
        label  = _ai_verdict_to_label(result["verdict"])
        action = _label_to_action(label)

        _auto_alert(
            "AI Detection", "url", db_id,
            result["risk_score"], result["verdict"], action,
            findings={"source_ref": result.get("source_ref", "")},
        )

        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=label,
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=action,
        ) | {"scan_id": db_id}

    except Exception as e:
        logger.error(f"AI URL detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


@router.post("/scan/ai/file", summary="AI content detection — file",
             tags=["AI Detection"])
async def scan_ai_file(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        filename   = file.filename or "unknown"

        if not file_bytes:
            raise HTTPException(status_code=400, detail="Empty file.")

        text = extract_text_from_file(file_bytes, filename)
        if not text.strip():
            return JSONResponse(
                status_code=422,
                content=error_response(
                    "Could not extract text from file. "
                    "Supported: txt, html, eml, pdf, docx."
                )
            )
        result = detect_ai_content(
            text       = text,
            source_ref = filename,
            input_type = "file",
        )
        db_id  = _save_ai_detection_scan(result)
        label  = _ai_verdict_to_label(result["verdict"])
        action = _label_to_action(label)

        _auto_alert(
            "AI Detection", "file", db_id,
            result["risk_score"], result["verdict"], action,
            findings={"source_ref": result.get("source_ref", "")},
        )

        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=label,
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=action,
        ) | {"scan_id": db_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI file detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500, content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9 — Platform Monitor
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/platform/targets", summary="Add URL to watchlist",
             tags=["Platform Monitor"])
async def add_monitor_target(req: AddTargetRequest):
    try:
        with _flask_ctx():
            domain = extract_domain(req.url)
            target = MonitoredTarget(
                url              = req.url[:2048],
                domain           = domain[:255],
                label            = (req.label or domain)[:255],
                interval_minutes = max(1, req.interval_minutes),
                alert_threshold  = max(0.0, min(100.0, req.alert_threshold)),
                is_active        = True,
                created_at       = datetime.datetime.utcnow(),
            )
            db.session.add(target)
            db.session.commit()
            return {
                "status":    "success",
                "target_id": target.id,
                "message":   f"Target '{target.label}' added to watchlist.",
            }
    except Exception as e:
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        logger.error(f"Add monitor target error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.delete("/platform/targets/{target_id}",
               summary="Remove target from watchlist",
               tags=["Platform Monitor"])
async def remove_monitor_target(target_id: int):
    try:
        with _flask_ctx():
            target = db.session.get(MonitoredTarget, target_id)
            if not target:
                raise HTTPException(status_code=404, detail="Target not found.")
            db.session.delete(target)
            db.session.commit()
        return {"status": "success", "message": "Target removed."}
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post("/platform/targets/{target_id}/scan",
             summary="Manual scan of monitored target",
             tags=["Platform Monitor"])
async def manual_scan_target(target_id: int):
    try:
        with _flask_ctx():
            target = db.session.get(MonitoredTarget, target_id)
            if not target:
                raise HTTPException(status_code=404, detail="Target not found.")

            result      = scan_target_full(target.url)
            alert_fired = result["risk_score"] >= target.alert_threshold

            scan = MonitorScanResult(
                target_id    = target.id,
                risk_score   = result["risk_score"],
                verdict      = result["verdict"],
                url_score    = result["url_score"],
                rules_score  = result["rules_score"],
                ml_score     = result["ml_score"],
                alert_fired  = alert_fired,
                scan_summary = result["summary"],
                scanned_at   = datetime.datetime.utcnow(),
            )
            db.session.add(scan)
            target.last_scanned    = scan.scanned_at
            target.last_risk_score = result["risk_score"]
            target.last_verdict    = result["verdict"]
            db.session.commit()

        return {
            "status":      "success",
            "target_id":   target_id,
            "risk_score":  result["risk_score"],
            "verdict":     result["verdict"],
            "alert_fired": alert_fired,
            "summary":     result["summary"],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Manual scan error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/platform/targets", summary="List monitored targets",
            tags=["Platform Monitor"])
async def list_monitor_targets():
    try:
        with _flask_ctx():
            targets = MonitoredTarget.query.order_by(
                MonitoredTarget.created_at.desc()
            ).all()
            return {
                "status":  "success",
                "targets": [_serialize_target(t) for t in targets],
            }
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/platform/targets/{target_id}/history",
            summary="Scan history for target",
            tags=["Platform Monitor"])
async def target_scan_history(target_id: int, limit: int = 20):
    try:
        with _flask_ctx():
            rows = (
                MonitorScanResult.query
                .filter_by(target_id=target_id)
                .order_by(MonitorScanResult.scanned_at.desc())
                .limit(limit)
                .all()
            )
            return {
                "status":  "success",
                "history": [_serialize_scan_result(r) for r in rows],
            }
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/platform/feed", summary="Unified threat feed",
            tags=["Platform Monitor"])
async def unified_feed(limit: int = 50):
    try:
        with _flask_ctx():
            feed = get_unified_feed(limit=limit)
        return {"status": "success", "feed": feed, "total": len(feed)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post("/platform/poll", summary="Poll due targets",
             tags=["Platform Monitor"])
async def poll_due_targets():
    try:
        with _flask_ctx():
            now     = datetime.datetime.utcnow()
            targets = MonitoredTarget.query.filter_by(is_active=True).all()
            scanned = []
            alerts  = []

            for t in targets:
                due = t.last_scanned is None or (
                    (now - t.last_scanned).total_seconds() / 60
                    >= t.interval_minutes
                )
                if not due:
                    continue

                result      = scan_target_full(t.url)
                alert_fired = result["risk_score"] >= t.alert_threshold

                scan = MonitorScanResult(
                    target_id    = t.id,
                    risk_score   = result["risk_score"],
                    verdict      = result["verdict"],
                    url_score    = result["url_score"],
                    rules_score  = result["rules_score"],
                    ml_score     = result["ml_score"],
                    alert_fired  = alert_fired,
                    scan_summary = result["summary"],
                    scanned_at   = now,
                )
                db.session.add(scan)
                t.last_scanned    = now
                t.last_risk_score = result["risk_score"]
                t.last_verdict    = result["verdict"]

                scanned.append({
                    "target_id":  t.id,
                    "label":      t.label,
                    "risk_score": result["risk_score"],
                })
                if alert_fired:
                    alerts.append({
                        "target_id":  t.id,
                        "label":      t.label,
                        "risk_score": result["risk_score"],
                        "verdict":    result["verdict"],
                    })

            db.session.commit()

        return {
            "status":        "success",
            "scanned_count": len(scanned),
            "alert_count":   len(alerts),
            "scanned":       scanned,
            "alerts":        alerts,
        }
    except Exception as e:
        logger.error(f"Poll due targets error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 10 — Risk Score Aggregator
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/risk/aggregate", summary="Aggregate risk scores — manual",
             tags=["Risk Score Aggregator"])
async def aggregate_risk(req: AggregateRequest):
    try:
        ids = [
            req.email_scan_id, req.url_scan_id, req.network_scan_id,
            req.attachment_id, req.ai_detection_id, req.image_scan_id,
        ]
        if not any(ids):
            raise HTTPException(
                status_code=400,
                detail="At least one scan ID must be provided."
            )

        with _flask_ctx():
            result = aggregate_risk_scores(
                email_scan_id   = req.email_scan_id,
                url_scan_id     = req.url_scan_id,
                network_scan_id = req.network_scan_id,
                attachment_id   = req.attachment_id,
                ai_detection_id = req.ai_detection_id,
                image_scan_id   = req.image_scan_id,
                weights         = req.weights,
            )

            if result.get("error"):
                return JSONResponse(
                    status_code=422,
                    content=error_response(result["error"])
                )

            verdict = result["verdict"]
            label   = {
                "CLEAN":      "SAFE",
                "SUSPICIOUS": "SUSPICIOUS",
                "MALICIOUS":  "MALICIOUS",
            }.get(verdict, "SUSPICIOUS")

            db_id = _save_aggregated_score(result, req)

        return build_response(
            status="success",
            risk_score=result["final_score"],
            label=label,
            module_results={"risk_aggregator": result},
            explanation=result["explanation"],
            recommended_action=result["action"],
        ) | {"scan_id": db_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Risk aggregation error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post(
    "/risk/aggregate/auto",
    summary="Aggregate risk scores — auto",
    tags=["Risk Score Aggregator"],
)
async def aggregate_risk_auto(req: AutoAggregateRequest):
    try:
        with _flask_ctx():
            result = aggregate_risk_scores_auto(weights=req.weights)

        if result.get("error"):
            return JSONResponse(
                status_code=422,
                content=error_response(result["error"]),
            )

        verdict = result["verdict"]
        label   = {
            "CLEAN":      "SAFE",
            "SUSPICIOUS": "SUSPICIOUS",
            "MALICIOUS":  "MALICIOUS",
        }.get(verdict, "SUSPICIOUS")

        bd = result.get("breakdown", {})

        class _AutoReq:
            email_scan_id   = bd.get("email",      {}).get("scan_id")
            url_scan_id     = bd.get("url",        {}).get("scan_id")
            network_scan_id = bd.get("network",    {}).get("scan_id")
            attachment_id   = bd.get("attachment", {}).get("scan_id")
            ai_detection_id = bd.get("ai",         {}).get("scan_id")
            image_scan_id   = bd.get("image",      {}).get("scan_id")

        db_id = None
        try:
            with _flask_ctx():
                db_id = _save_aggregated_score(result, _AutoReq())
        except Exception as save_ex:
            logger.warning("Auto-agg DB save failed (non-fatal): %s", save_ex)

        return build_response(
            status="success",
            risk_score=result["final_score"],
            label=label,
            module_results={"risk_aggregator": result},
            explanation=result["explanation"],
            recommended_action=result["action"],
        ) | {"scan_id": db_id, "mode": "auto"}

    except Exception as e:
        logger.error("Risk auto-aggregate error: %s", e, exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e)),
        )


@router.get(
    "/risk/status",
    summary="Module status probe",
    tags=["Risk Score Aggregator"],
)
async def risk_status():
    try:
        with _flask_ctx():
            status = probe_module_status()
        return {"status": "success", "modules": status}
    except Exception as e:
        logger.error("Risk status probe error: %s", e, exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/risk/history", summary="Aggregation history",
            tags=["Risk Score Aggregator"])
async def risk_history(limit: int = 20):
    try:
        with _flask_ctx():
            rows = (
                AggregatedRiskScore.query
                .order_by(AggregatedRiskScore.created_at.desc())
                .limit(limit)
                .all()
            )
            return {
                "status":  "success",
                "records": [_serialize_agg(r) for r in rows],
            }
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/risk/history/{record_id}", summary="Aggregation detail",
            tags=["Risk Score Aggregator"])
async def risk_detail(record_id: int):
    try:
        with _flask_ctx():
            r = db.session.get(AggregatedRiskScore, record_id)
            if not r:
                raise HTTPException(status_code=404, detail="Record not found.")
            return {"status": "success", "record": _serialize_agg(r, full=True)}
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 12 — Model Management
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/models/feedback", summary="Submit feedback label",
             tags=["Model Management"])
async def submit_feedback(req: FeedbackLabelRequest):
    try:
        with _flask_ctx():
            result = add_feedback_label(
                url            = req.url,
                label_type     = req.label_type,
                feedback_label = req.feedback_label,
                original_label = req.original_label or "",
                url_scan_id    = req.url_scan_id,
                admin_note     = req.admin_note or "",
            )
        if "error" in result:
            return JSONResponse(
                status_code=400,
                content=error_response(result["error"])
            )
        return {"status": "success", "sample": result}
    except Exception as e:
        logger.error(f"Feedback submit error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/models/feedback", summary="List feedback queue",
            tags=["Model Management"])
async def list_feedback(limit: int = 50):
    try:
        with _flask_ctx():
            queue = get_feedback_queue(limit=limit)
        return {"status": "success", "queue": queue, "total": len(queue)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post("/models/retrain", summary="Trigger RF retraining",
             tags=["Model Management"])
async def retrain_model():
    try:
        from backend.app import create_app as _cfa
        flask_app = _cfa()
        result    = trigger_retrain(flask_app.app_context())
        return result
    except Exception as e:
        logger.error(f"Retrain trigger error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/models/retrain/status", summary="Live training log",
            tags=["Model Management"])
async def retrain_status():
    try:
        state = get_training_state()
        return {"status": "success", "training": state}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/models/versions", summary="Model version history",
            tags=["Model Management"])
async def list_model_versions():
    try:
        with _flask_ctx():
            versions = get_model_versions()
        return {"status": "success", "versions": versions, "total": len(versions)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/models/finetune-plan", summary="HuggingFace fine-tune plan",
            tags=["Model Management"])
async def hf_finetune_plan():
    try:
        plan = get_huggingface_finetune_plan()
        return {"status": "success", "plan": plan}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 13 — Alerting & Audit System
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/alerts", summary="Manually create an alert", tags=["Alerts"])
async def api_create_alert(req: CreateAlertRequest):
    try:
        with _flask_ctx():
            alert_id = create_alert(
                module             = req.module,
                input_type         = req.input_type,
                scan_id            = req.scan_id,
                risk_score         = req.risk_score,
                verdict            = req.verdict,
                recommended_action = req.recommended_action,
                triggered_rules    = req.triggered_rules or [],
                ml_verdicts        = req.ml_verdicts    or {},
                raw_findings       = req.raw_findings   or {},
                actor              = req.actor or "admin",
            )
        if alert_id is None:
            return JSONResponse(
                status_code=422,
                content=error_response(
                    "Alert not created — verdict/score below threshold."
                )
            )
        return {"status": "success", "alert_id": alert_id}
    except Exception as e:
        logger.error(f"Create alert error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/alerts/stats", summary="Alert statistics", tags=["Alerts"])
async def api_alert_stats():
    try:
        with _flask_ctx():
            stats = get_alert_stats()
        return {"status": "success", "stats": stats}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/alerts/export/csv", summary="Export alerts as CSV", tags=["Alerts"])
async def api_export_csv(
    severity:  Optional[str] = None,
    module:    Optional[str] = None,
    status:    Optional[str] = None,
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
):
    try:
        with _flask_ctx():
            csv_bytes = export_alerts_csv(
                severity=severity, module=module, status=status,
                date_from=date_from, date_to=date_to,
            )
        filename = (
            f"phishguard_alerts_"
            f"{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        return StreamingResponse(
            _io.BytesIO(csv_bytes),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/alerts/{alert_id}/export/pdf",
            summary="Export alert as PDF", tags=["Alerts"])
async def api_export_pdf(alert_id: int):
    try:
        with _flask_ctx():
            pdf_bytes = export_alert_pdf(alert_id)
        if not pdf_bytes:
            raise HTTPException(
                status_code=404,
                detail="Alert not found or PDF generation failed."
            )
        is_html = pdf_bytes.startswith(b"<!DOCTYPE")
        if is_html:
            return StreamingResponse(
                _io.BytesIO(pdf_bytes),
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename=alert_{alert_id}.html"},
            )
        return StreamingResponse(
            _io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=alert_{alert_id}_report.pdf"},
        )
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/alerts/{alert_id}", summary="Get alert detail", tags=["Alerts"])
async def api_get_alert(alert_id: int):
    try:
        with _flask_ctx():
            alert = get_alert_detail(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")
        return {"status": "success", "alert": alert}
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/alerts", summary="List alerts with filters", tags=["Alerts"])
async def api_list_alerts(
    severity:  Optional[str] = None,
    module:    Optional[str] = None,
    status:    Optional[str] = None,
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
    limit:     int           = 100,
):
    try:
        with _flask_ctx():
            alerts = get_alerts(
                severity=severity, module=module, status=status,
                date_from=date_from, date_to=date_to, limit=limit,
            )
        return {"status": "success", "alerts": alerts, "total": len(alerts)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post("/alerts/{alert_id}/acknowledge",
             summary="Acknowledge alert", tags=["Alerts"])
async def api_acknowledge_alert(alert_id: int, req: AcknowledgeRequest):
    try:
        with _flask_ctx():
            result = acknowledge_alert(alert_id, actor=req.actor or "admin")
        if "error" in result:
            return JSONResponse(status_code=400, content=error_response(result["error"]))
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post("/alerts/{alert_id}/dismiss",
             summary="Dismiss alert", tags=["Alerts"])
async def api_dismiss_alert(alert_id: int, req: DismissRequest):
    try:
        with _flask_ctx():
            result = dismiss_alert(
                alert_id,
                reason = req.reason or "",
                actor  = req.actor  or "admin",
            )
        if "error" in result:
            return JSONResponse(status_code=400, content=error_response(result["error"]))
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/audit/log", summary="Immutable audit trail", tags=["Alerts"])
async def api_audit_log(limit: int = 100):
    try:
        with _flask_ctx():
            logs = get_audit_log(limit=limit)
        return {"status": "success", "logs": logs, "total": len(logs)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 14 — Browser Extension endpoints
# ─────────────────────────────────────────────────────────────────────────────

class ExtensionScanRequest(PydanticBase):
    url:    str
    source: Optional[str] = "extension"


@router.post("/extension/scan", summary="Scan a URL from the browser extension",
             tags=["Extension"])
async def extension_scan(req: ExtensionScanRequest):
    try:
        result               = analyze_url(req.url)
        score, label         = _extract_url_risk(result)
        result["risk_score"] = score
        result["label"]      = label
        action               = _label_to_action(label)

        threat_summary = ""
        try:
            from backend.ml.model_loader import get_model
            pipeline = get_model("threat_summarizer")
            if pipeline:
                flags      = result.get("flags", [])
                domain     = result.get("domain", req.url)
                flag_names = [
                    f.get("flag", f.get("description", ""))
                    for f in flags[:5]
                ] if flags else []
                input_text = (
                    f"URL scan result. Domain: {domain}. "
                    f"Risk score: {score}/100. Label: {label}. "
                    f"Flags: {', '.join(flag_names) if flag_names else 'none'}. "
                    f"SSL valid: {result.get('ssl', {}).get('is_valid', False)}. "
                    f"Domain age days: {result.get('domain_age_days', 'unknown')}."
                )
                output = pipeline(
                    input_text[:512],
                    max_length=60,
                    min_length=15,
                    do_sample=False,
                )
                if isinstance(output, list) and output:
                    threat_summary = output[0].get("summary_text", "").strip()
        except Exception as bart_ex:
            logger.warning("Extension BART summary failed: %s", bart_ex)
            threat_summary = _build_url_explanation(result)

        if not threat_summary:
            threat_summary = (
                _build_url_explanation(result)
                or f"{label} — risk score {score:.1f}/100."
            )

        db_id = None
        try:
            with _flask_ctx():
                from urllib.parse import urlparse
                domain_parsed = urlparse(req.url).netloc or req.url

                record = ExtensionScan(
                    url                = req.url[:2048],
                    domain             = domain_parsed[:255],
                    risk_score         = score,
                    label              = label[:30],
                    verdict            = label[:30],
                    threat_summary     = threat_summary[:1000],
                    recommended_action = action[:30],
                    source             = (req.source or "extension")[:30],
                    scanned_at         = datetime.datetime.utcnow(),
                )
                db.session.add(record)
                db.session.commit()
                db_id = record.id
        except Exception as db_ex:
            logger.error("ExtensionScan DB save error: %s", db_ex)
            try:
                with _flask_ctx():
                    db.session.rollback()
            except Exception:
                pass

        _auto_alert(
            "Extension", "url", db_id,
            score, label, action,
            findings={
                "flags": [f.get("flag", "") for f in result.get("flags", [])]
            },
        )

        return {
            "status":             "success",
            "url":                req.url,
            "risk_score":         score,
            "label":              label,
            "verdict":            label,
            "threat_summary":     threat_summary,
            "recommended_action": action,
            "scan_id":            db_id,
            "details": {
                "domain":     result.get("domain", ""),
                "ssl_valid":  result.get("ssl", {}).get("is_valid", False),
                "domain_age": result.get("domain_age_days"),
                "flags":      [
                    f.get("flag", "") for f in result.get("flags", [])[:5]
                ],
            },
        }

    except Exception as e:
        logger.error(f"Extension scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"Extension scan failed: {str(e)[:150]}")
        )


@router.get("/extension/history", summary="Recent URLs scanned via extension",
            tags=["Extension"])
async def extension_history(limit: int = 50):
    try:
        with _flask_ctx():
            rows = (
                ExtensionScan.query
                .order_by(ExtensionScan.scanned_at.desc())
                .limit(limit)
                .all()
            )
            records = [
                {
                    "id":                 r.id,
                    "url":                r.url,
                    "domain":             r.domain,
                    "risk_score":         r.risk_score,
                    "label":              r.label,
                    "threat_summary":     r.threat_summary,
                    "recommended_action": r.recommended_action,
                    "source":             r.source,
                    "scanned_at":         r.scanned_at.isoformat() + "Z"
                                          if r.scanned_at else "",
                }
                for r in rows
            ]
        return {"status": "success", "scans": records, "total": len(records)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/extension/status", summary="Extension ping / health check",
            tags=["Extension"])
async def extension_status():
    return {
        "status":  "online",
        "version": "1.0.0",
        "message": "PhishGuard backend is running.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 15 — System Architecture & Health
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/architecture/health",
            summary="Live health check for all module endpoints",
            tags=["System Architecture"])
async def architecture_health():
    try:
        results  = check_module_health()
        online   = sum(1 for r in results if r["status"] == "online")
        degraded = sum(1 for r in results if r["status"] == "degraded")
        offline  = sum(1 for r in results if r["status"] == "offline")
        total    = len(results)

        overall = "online"
        if offline == total:
            overall = "offline"
        elif offline > 0 or degraded > 0:
            overall = "degraded"

        return {
            "status":  "success",
            "overall": overall,
            "summary": {
                "online":   online,
                "degraded": degraded,
                "offline":  offline,
                "total":    total,
            },
            "modules": results,
        }
    except Exception as e:
        logger.error(f"Health check error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/architecture/metrics",
            summary="CPU, memory, request rate, and DB stats",
            tags=["System Architecture"])
async def architecture_metrics():
    try:
        sys_metrics  = get_system_metrics()
        rate_history = get_request_rate_history(buckets=10)
        rpm          = get_requests_per_minute()

        with _flask_ctx():
            db_stats = get_db_stats()

        return {
            "status":           "success",
            "system":           sys_metrics,
            "requests_per_min": rpm,
            "rate_history":     rate_history,
            "database":         db_stats,
            "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Metrics error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get("/architecture/migration-plan",
            summary="SQLite to PostgreSQL migration plan",
            tags=["System Architecture"])
async def architecture_migration_plan():
    try:
        plan = get_migration_plan()
        return {"status": "success", "plan": plan}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 helpers  ← UPDATED: DNSBL + BEC scoring and explanation
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_phase1_risk(parsed: dict, submitter: str = "") -> float:
    score = 0.0

    distilbert = parsed.get("distilbert_result", {})
    if distilbert.get("label") == "PHISHING":
        score += distilbert.get("score", 0.5) * 60
    elif distilbert.get("label") == "SAFE":
        score += (1 - distilbert.get("score", 0.5)) * 10

    severity_weights = {"high": 10, "medium": 5, "low": 2}
    anomaly_score = sum(
        severity_weights.get(a.get("severity", "low"), 2)
        for a in parsed.get("anomalies", [])
    )
    score += min(anomaly_score, 30)

    if submitter != "extension":
        auth = parsed.get("auth_results", {})
        if auth.get("spf")   in ("fail", "softfail", "none"): score += 3
        if auth.get("dkim")  in ("fail", "none"):              score += 4
        if auth.get("dmarc") in ("fail", "none"):              score += 3

    # DNSBL: +15 per zone hit, capped at +30
    dnsbl = parsed.get("dnsbl_result", {})
    if dnsbl.get("listed"):
        zones_hit   = dnsbl.get("zones_hit", [])
        dnsbl_score = min(len(zones_hit) * 15, 30)
        score      += dnsbl_score

    # BEC: +20 if display name spoofing suspected
    bec = parsed.get("bec_result", {})
    if bec.get("is_bec_suspect"):
        score += 20

    return round(min(score, 100.0), 2)


def _build_email_explanation(parsed: dict, label: str) -> str:
    parts = []

    d = parsed.get("distilbert_result", {})
    if d.get("label") == "PHISHING":
        parts.append(
            f"DistilBERT classified body as phishing "
            f"({int(d.get('score', 0) * 100)}% confidence)."
        )

    highs = [a for a in parsed.get("anomalies", [])
             if a.get("severity") == "high"]
    if highs:
        parts.append(f"Header anomaly: {highs[0]['description']}")

    auth = parsed.get("auth_results", {})
    if auth.get("spf")  == "fail": parts.append("SPF failed.")
    if auth.get("dkim") == "fail": parts.append("DKIM failed.")

    n = len(parsed.get("urls", []))
    if n:
        parts.append(f"{n} URL(s) extracted for further analysis.")

    # DNSBL findings
    dnsbl = parsed.get("dnsbl_result", {})
    if dnsbl.get("listed"):
        zones = dnsbl.get("zones_hit", [])
        parts.append(
            f"Sender IP ({dnsbl.get('ip', '?')}) is listed on "
            f"{len(zones)} DNSBL zone(s): {', '.join(zones[:3])}."
        )

    # BEC findings
    bec = parsed.get("bec_result", {})
    if bec.get("is_bec_suspect"):
        signals = bec.get("risk_signals", [])
        kw      = bec.get("executive_keyword_found", "")
        msg     = "BEC spoofing suspected"
        if kw:
            msg += f" — display name contains executive keyword \"{kw}\""
        if signals:
            msg += f". Signal: {signals[0]}"
        parts.append(msg + ".")

    return " ".join(parts) or f"Email assessed as {label}."


def _save_email_scan(
    parsed: dict,
    risk_score: float,
    label: str,
    filename: str = ""
) -> Optional[int]:
    try:
        with _flask_ctx():
            scan = EmailScan(
                filename     = filename or "pasted_email",
                sender       = parsed.get("sender",    ""),
                recipient    = parsed.get("recipient", ""),
                subject      = parsed.get("subject",   ""),
                body_text    = parsed.get("body_text", "")[:5000],
                body_html    = parsed.get("body_html", "")[:10000],
                headers_raw  = json.dumps(parsed.get("headers", {})),
                spf_result   = parsed.get("auth_results", {}).get("spf",   "none"),
                dkim_result  = parsed.get("auth_results", {}).get("dkim",  "none"),
                dmarc_result = parsed.get("auth_results", {}).get("dmarc", "none"),
                risk_score   = risk_score,
                label        = label,
            )
            db.session.add(scan)
            db.session.flush()
            for url_data in parsed.get("urls", []):
                db.session.add(URLScan(
                    email_id       = scan.id,
                    raw_url        = url_data.get("raw",        "")[:2048],
                    normalized_url = url_data.get("normalized", "")[:2048],
                    domain         = url_data.get("domain",     "")[:255],
                ))
            db.session.commit()
            return scan.id
    except Exception as e:
        logger.error(f"EmailScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 helpers  ← UPDATED: typosquatting + cert transparency in explanation
# ─────────────────────────────────────────────────────────────────────────────

def _build_url_explanation(result: dict) -> str:
    parts = []

    ml = result.get("ml_result", {})
    if ml.get("label") == "MALICIOUS":
        parts.append(
            f"ML model classified URL as malicious "
            f"({int(ml.get('score', 0) * 100)}% confidence)."
        )

    if result.get("domain_age_flag"):
        age = result.get("domain_age_days", "unknown")
        parts.append(f"Domain is only {age} days old.")

    s = result.get("ssl", {})
    if not s.get("has_ssl"):
        parts.append("URL uses plain HTTP — no SSL.")
    elif s.get("is_self_signed"):
        parts.append("SSL certificate is self-signed.")
    elif s.get("is_expired"):
        parts.append("SSL certificate has expired.")

    hop_count = result.get("redirect_count", 0)
    if hop_count > 2:
        chain        = result.get("redirect_chain", [])
        final        = chain[-1] if chain else ""
        from urllib.parse import urlparse
        final_domain = urlparse(final).netloc if final else ""
        parts.append(
            f"Redirects through {hop_count} hops"
            + (f" (final: {final_domain})" if final_domain else "") + "."
        )

    # Typosquatting
    typo = result.get("typosquatting", {})
    if typo.get("is_typosquatting_suspect"):
        brand = typo.get("closest_brand", "")
        dist  = typo.get("edit_distance",  0)
        parts.append(
            f"Typosquatting suspected — closely resembles \"{brand}\" "
            f"(edit distance: {dist})."
        )

    # Cert transparency freshness
    cert = result.get("cert_transparency", {})
    if cert.get("is_freshly_certified"):
        days = cert.get("days_since_issued", 0)
        parts.append(
            f"SSL certificate issued only {days} day(s) ago — "
            f"freshly certified domains are a common phishing indicator."
        )

    flags = result.get("flags", [])
    if not parts and flags:
        flag_names = [f.get("flag", f.get("description", "")) for f in flags[:3]]
        parts.append(
            f"Risk flags: {', '.join(n for n in flag_names if n)}."
        )

    return " ".join(parts) or "URL analyzed — no high-risk indicators."


def _save_url_scan(
    result: dict,
    email_id: Optional[int] = None
) -> Optional[int]:
    try:
        with _flask_ctx():
            scan = URLScan(
                email_id        = email_id,
                raw_url         = result.get("raw_url",   "")[:2048],
                normalized_url  = result.get("final_url", "")[:2048],
                domain          = result.get("domain",    "")[:255],
                ip_address      = result.get("ip",        ""),
                country         = result.get("country",   ""),
                whois_data      = json.dumps(result.get("whois", {})),
                domain_age_days = result.get("domain_age_days"),
                ssl_valid       = result.get("ssl", {}).get("is_valid", False),
                ssl_issuer      = (
                    result.get("ssl", {}).get("issuer") or ""
                )[:255],
                redirect_chain  = json.dumps(
                    result.get("redirect_chain", [])
                ),
                ml_score        = result.get("ml_result", {}).get("score", 0.0),
                final_label     = result.get("label", "UNKNOWN"),
            )
            db.session.add(scan)
            db.session.commit()
            return scan.id
    except Exception as e:
        logger.error(f"URLScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 helpers  ← UPDATED: CVE critical findings in explanation
# ─────────────────────────────────────────────────────────────────────────────

def _build_network_explanation(result: dict) -> str:
    if not result.get("authorized"):
        return f"Scan blocked: {result.get('block_reason', 'authorization required')}"
    if result.get("error") and not result.get("ports"):
        return f"Scan error: {result['error']}"

    parts = [
        f"Found {result.get('open_port_count', 0)} open port(s) — "
        f"overall risk: {result.get('risk_level', 'UNKNOWN')}."
    ]

    dangerous = [p for p in result.get("ports", []) if p.get("is_dangerous")]
    if dangerous:
        top3 = ", ".join(
            f"port {p['port']} ({p['service_name']})"
            for p in dangerous[:3]
        )
        parts.append(f"Dangerous ports: {top3}.")

    admins = result.get("admin_exposures", [])
    if admins:
        parts.append(
            f"{len(admins)} admin panel(s) exposed on port(s): "
            f"{', '.join(str(a['port']) for a in admins)}."
        )

    if result.get("os_guess"):
        parts.append(f"OS: {result['os_guess']}.")

    # CVE critical findings
    cve_criticals = []
    for port in result.get("ports", []):
        cve_data = port.get("cve_data", {})
        for cve in cve_data.get("cves", []):
            cvss = cve.get("cvss_score", 0.0) or 0.0
            if cvss >= 9.0:
                cve_criticals.append(
                    f"{cve.get('cve_id', '?')} (CVSS {cvss:.1f}) "
                    f"on port {port.get('port', '?')}"
                )
    if cve_criticals:
        parts.append(
            f"Critical CVE(s) detected: {'; '.join(cve_criticals[:3])}."
        )
    elif any(
        (port.get("cve_data", {}).get("high_count", 0) or 0) > 0
        for port in result.get("ports", [])
    ):
        total_high = sum(
            port.get("cve_data", {}).get("high_count", 0) or 0
            for port in result.get("ports", [])
        )
        parts.append(f"{total_high} high-severity CVE(s) found across open ports.")

    return " ".join(parts)


def _save_network_scan(result: dict) -> Optional[int]:
    try:
        with _flask_ctx():
            scan = NetworkScan(
                url_scan_id      = result.get("url_scan_id"),
                email_scan_id    = result.get("email_scan_id"),
                target           = result.get("target",        "")[:255],
                ip_resolved      = (result.get("ip_resolved") or "")[:60],
                scan_type        = result.get("scan_type",     ""),
                nmap_version     = result.get("nmap_version",  ""),
                os_guess         = result.get("os_guess",      ""),
                total_open_ports = result.get("open_port_count", 0),
                risk_level       = result.get("risk_level",   "UNKNOWN"),
                risk_flags       = json.dumps(result.get("risk_flags", [])),
                raw_nmap_output  = result.get("raw_nmap_output", ""),
                scan_duration_s  = result.get("scan_duration_s",  0),
                authorized       = result.get("authorized",   False),
            )
            db.session.add(scan)
            db.session.flush()
            for p in result.get("ports", []):
                db.session.add(PortResult(
                    network_scan_id  = scan.id,
                    port             = p.get("port"),
                    protocol         = p.get("protocol",        "tcp"),
                    state            = p.get("state",           "open"),
                    service_name     = p.get("service_name",    "")[:100],
                    service_product  = p.get("service_product", "")[:255],
                    service_version  = p.get("service_version", "")[:255],
                    service_extra    = p.get("service_extra",   "")[:500],
                    is_dangerous     = p.get("is_dangerous",    False),
                    danger_reason    = p.get("danger_reason",   "")[:255],
                    cpe              = p.get("cpe",             "")[:255],
                ))
            db.session.commit()
            return scan.id
    except Exception as e:
        logger.error(f"NetworkScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_rules_explanation(result: dict) -> str:
    hits = result.get("hits", [])
    if not hits:
        return "No heuristic rules triggered — input appears clean."
    critical = [h for h in hits if h.get("severity") == "CRITICAL"]
    high     = [h for h in hits if h.get("severity") == "HIGH"]
    parts    = [f"{len(hits)} rule(s) triggered (score: {result['rule_score']}/100)."]
    if critical:
        parts.append(f"Critical: {critical[0]['name']}.")
    elif high:
        parts.append(f"High severity: {high[0]['name']}.")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 helpers — CAPA structured explanation (Task 1, unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _build_file_explanation(
    result:   dict,
    filename: str,
    score:    float,
    verdict:  str,
    action:   str,
) -> dict:
    file_type  = result.get("file_type",     "unknown")
    file_size  = result.get("file_size",     0)
    category   = result.get("file_category", "unknown")
    entropy    = result.get("entropy",       0.0)
    mismatch   = result.get("type_mismatch", False)
    yara_hits  = result.get("yara_matches",      [])
    str_hits   = result.get("suspicious_strings", [])
    pdf_data   = result.get("pdf_analysis",       {})
    risk_flags = result.get("risk_flags",         [])
    reasons    = result.get("verdict_reasons",    [])

    verdict_words = {
        "CLEAN":      "no malicious indicators were found",
        "SUSPICIOUS": "several suspicious indicators were detected",
        "MALICIOUS":  "strong malicious indicators were found",
    }
    summary = (
        f"PhishGuard completed a multi-layer static analysis of "
        f"\"{filename}\" ({file_type.upper()}, "
        f"{round(file_size / 1024, 1)} KB). "
        f"The risk score is {score:.1f}/100 — {verdict_words.get(verdict, 'analysis complete')}. "
        f"Recommended action: {action}."
    )
    if mismatch:
        summary += (
            " WARNING: The file extension does not match its magic bytes — "
            "this file may be disguised as a different type."
        )

    file_info = {
        "filename":      filename,
        "type":          file_type.upper(),
        "size_kb":       round(file_size / 1024, 2),
        "category":      category,
        "type_mismatch": mismatch,
    }

    static_analysis = {
        "label":       "Static String Analysis",
        "method":      "Byte-pattern scan against known-malicious string library "
                       "(with PDF FlateDecode decompression)",
        "hits":        str_hits,
        "hit_count":   len(str_hits),
        "explanation": (
            f"{len(str_hits)} suspicious string pattern(s) found."
            if str_hits else
            "No suspicious string patterns detected."
        ),
    }

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    yara_sorted = sorted(
        yara_hits,
        key=lambda m: severity_order.get((m.get("severity") or "MEDIUM").upper(), 2)
    )
    yara_analysis = {
        "label":       "YARA Signature Matching",
        "method":      "Compiled YARA ruleset scan (FlateDecode-aware for PDF)",
        "hits":        [
            {
                "rule":      m.get("rule",      "unknown"),
                "severity":  (m.get("severity") or "MEDIUM").upper(),
                "namespace": m.get("namespace", ""),
                "tags":      m.get("tags",      []),
            }
            for m in yara_sorted
        ],
        "hit_count":   len(yara_hits),
        "explanation": (
            f"{len(yara_hits)} YARA signature(s) matched. "
            f"Highest severity: {(yara_sorted[0].get('severity') or 'MEDIUM').upper()}."
            if yara_hits else
            "No YARA rules matched."
        ),
    }

    pdf_analysis_out = None
    if file_type == "pdf" and pdf_data:
        pdf_flags = []
        if pdf_data.get("has_javascript"):
            pdf_flags.append("Embedded JavaScript (/JS or /JavaScript action)")
        if pdf_data.get("has_openaction"):
            pdf_flags.append("OpenAction trigger — runs automatically on open")
        if pdf_data.get("has_launch"):
            pdf_flags.append("Launch action — can execute external programs")
        if pdf_data.get("has_embedded_file"):
            pdf_flags.append("Embedded file attachment inside PDF structure")
        url_count = len(pdf_data.get("embedded_urls", []))
        pdf_analysis_out = {
            "label":       "PDF Structure Analysis",
            "flags":       pdf_flags,
            "urls_found":  url_count,
            "explanation": (
                f"PDF structure analysis found {len(pdf_flags)} dangerous action(s)."
                if pdf_flags else
                "No dangerous PDF actions detected."
            ) + (f" {url_count} embedded URL(s) extracted." if url_count else ""),
        }

    if entropy >= 7.2:
        entropy_colour = "red"
        entropy_interp = f"Very high entropy ({entropy:.4f}/8.0) — likely packed or encrypted."
    elif entropy >= 6.5:
        entropy_colour = "amber"
        entropy_interp = f"Moderately elevated entropy ({entropy:.4f}/8.0)."
    else:
        entropy_colour = "green"
        entropy_interp = f"Normal entropy ({entropy:.4f}/8.0)."

    entropy_analysis = {
        "label":          "Shannon Entropy Analysis",
        "value":          entropy,
        "interpretation": entropy_interp,
        "bar_pct":        min(int((entropy / 8.0) * 100), 100),
        "colour":         entropy_colour,
    }

    # CAPA section
    capa_raw         = result.get("capa_analysis", {})
    capa_available   = capa_raw.get("available", False)
    capa_error       = capa_raw.get("error", "")
    _capa_types      = {"exe", "elf", "dll"}
    is_capa_eligible = file_type.lower() in _capa_types

    if capa_available and capa_raw.get("capabilities"):
        cap_list      = capa_raw["capabilities"]
        cap_count     = len(cap_list)
        highest_sev   = capa_raw.get("highest_severity", "NONE")
        tactics       = capa_raw.get("attack_tactics",    [])
        mbc_objectives = capa_raw.get("mbc_objectives",  [])
        ns_summary    = capa_raw.get("namespace_summary", {})
        risk_contrib  = capa_raw.get("risk_contribution", 0.0)
        top5 = [
            {
                "name":     c.get("name",     ""),
                "severity": c.get("severity", "LOW"),
                "tactics":  c.get("attack_tactics", []),
                "mbc":      c.get("mbc",      []),
                "namespace":c.get("namespace", ""),
            }
            for c in cap_list[:5]
        ]
        sev_phrase   = {"CRITICAL":"critically dangerous","HIGH":"highly suspicious",
                        "MEDIUM":"moderately suspicious","LOW":"low-risk"}.get(highest_sev,"notable")
        tactic_str   = ", ".join(tactics[:3]) if tactics else "unclassified behaviors"
        capa_section = {
            "label":             "CAPA Behavioral Capability Detection",
            "available":         True,
            "capability_count":  cap_count,
            "highest_severity":  highest_sev,
            "attack_tactics":    tactics,
            "mbc_objectives":    mbc_objectives,
            "top_capabilities":  top5,
            "namespace_summary": ns_summary,
            "risk_contribution": risk_contrib,
            "explanation": (
                f"CAPA identified {cap_count} behavioral capability(-ies) rated as "
                f"{sev_phrase} (highest severity: {highest_sev}). "
                f"Top ATT&CK tactics: {tactic_str}. "
                f"CAPA contributed {risk_contrib:.1f} points to the risk score."
            ),
            "setup_message": "",
        }
    elif is_capa_eligible and not capa_available:
        capa_section = {
            "label":             "CAPA Behavioral Capability Detection",
            "available":         False,
            "capability_count":  0,
            "highest_severity":  "NONE",
            "attack_tactics":    [],
            "mbc_objectives":    [],
            "top_capabilities":  [],
            "namespace_summary": {},
            "risk_contribution": 0.0,
            "explanation":       (
                "CAPA by Mandiant identifies WHAT a binary can DO. "
                "This PE/ELF file is eligible once CAPA is installed."
            ),
            "setup_message": capa_error or (
                "pip install flare-capa && "
                "git clone https://github.com/mandiant/capa-rules backend/capa_rules"
            ),
        }
    else:
        capa_section = {
            "label":             "CAPA Behavioral Capability Detection",
            "available":         False,
            "capability_count":  0,
            "highest_severity":  "NONE",
            "attack_tactics":    [],
            "mbc_objectives":    [],
            "top_capabilities":  [],
            "namespace_summary": {},
            "risk_contribution": 0.0,
            "explanation":       (
                "CAPA only analyses PE (EXE/DLL) and ELF binaries. "
                "Non-executable files are covered by the other analysis layers."
            ),
            "setup_message": "",
        }

    out = {
        "verdict":          verdict,
        "risk_score":       score,
        "action":           action,
        "summary":          summary,
        "file_info":        file_info,
        "static_analysis":  static_analysis,
        "yara_analysis":    yara_analysis,
        "entropy_analysis": entropy_analysis,
        "capa_analysis":    capa_section,
        "risk_flags":       risk_flags,
        "verdict_reasons":  reasons,
    }
    if pdf_analysis_out:
        out["pdf_analysis"] = pdf_analysis_out
    return out


def _save_attachment_scan(
    result: dict,
    filename: str,
    email_scan_id: Optional[int]
) -> Optional[int]:
    try:
        with _flask_ctx():
            hashes = result.get("hashes", {})
            record = AttachmentScan(
                email_id     = email_scan_id,
                filename     = filename[:255],
                file_type    = result.get("file_type",  "")[:255],
                md5          = hashes.get("md5",   "")[:64],
                sha256       = hashes.get("sha256","")[:64],
                file_size    = result.get("file_size",   0),
                entropy      = result.get("entropy",     0.0),
                yara_matches = json.dumps(result.get("yara_matches",      [])),
                static_finds = json.dumps(result.get("suspicious_strings",[])),
                verdict      = result.get("verdict", "CLEAN"),
                scanned_at   = datetime.datetime.utcnow(),
            )
            db.session.add(record)
            db.session.commit()
            return record.id
    except Exception as e:
        logger.error(f"AttachmentScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 helpers
# ─────────────────────────────────────────────────────────────────────────────

def _save_image_scan(result: dict, filename: str) -> Optional[int]:
    try:
        with _flask_ctx():
            record = ImageAnalysisScan(
                filename          = filename[:255],
                file_size         = result.get("file_size",       0),
                image_width       = result.get("image_width",     0),
                image_height      = result.get("image_height",    0),
                image_format      = result.get("image_format",    "")[:20],
                ocr_text          = result.get("ocr_text",        "")[:10000],
                ocr_word_count    = result.get("ocr_word_count",  0),
                detected_brands   = json.dumps(result.get("detected_brands",   [])),
                phishing_keywords = json.dumps(result.get("phishing_keywords", [])),
                classifier_label  = result.get(
                    "classifier_result", {}
                ).get("label", "")[:30],
                classifier_score  = result.get(
                    "classifier_result", {}
                ).get("score", 0.0),
                verdict           = result.get("verdict",    "CLEAN"),
                risk_score        = result.get("risk_score",   5.0),
                scanned_at        = datetime.datetime.utcnow(),
            )
            db.session.add(record)
            db.session.commit()
            return record.id
    except Exception as e:
        logger.error(f"ImageAnalysisScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ai_verdict_to_label(verdict: str) -> str:
    return {
        "HUMAN":        "SAFE",
        "MIXED":        "SUSPICIOUS",
        "AI_GENERATED": "MALICIOUS",
    }.get(verdict, "SUSPICIOUS")


def _save_ai_detection_scan(result: dict) -> Optional[int]:
    try:
        with _flask_ctx():
            record = AIDetectionScan(
                input_type      = result.get("input_type",     "text"),
                source_ref      = result.get("source_ref",     "")[:512],
                input_preview   = result.get("input_preview",  "")[:500],
                char_count      = result.get("char_count",     0),
                sentence_count  = result.get("sentence_count", 0),
                ai_probability  = result.get("ai_probability", 0.0),
                verdict         = result.get("verdict",        "HUMAN"),
                risk_score      = result.get("risk_score",     0.0),
                sentence_scores = json.dumps(result.get("sentence_scores", [])),
                scanned_at      = datetime.datetime.utcnow(),
            )
            db.session.add(record)
            db.session.commit()
            return record.id
    except Exception as e:
        logger.error(f"AIDetectionScan DB save error: {e}")
        try:
            with _flask_ctx():
                db.session.rollback()
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9 helpers
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_target(t) -> dict:
    return {
        "id":               t.id,
        "url":              t.url,
        "domain":           t.domain,
        "label":            t.label,
        "interval_minutes": t.interval_minutes,
        "alert_threshold":  t.alert_threshold,
        "last_scanned":     t.last_scanned.isoformat() + "Z"
                            if t.last_scanned else None,
        "last_risk_score":  t.last_risk_score,
        "last_verdict":     t.last_verdict,
        "is_active":        t.is_active,
        "created_at":       t.created_at.isoformat() + "Z"
                            if t.created_at else "",
    }


def _serialize_scan_result(r) -> dict:
    return {
        "id":           r.id,
        "target_id":    r.target_id,
        "risk_score":   r.risk_score,
        "verdict":      r.verdict,
        "url_score":    r.url_score,
        "rules_score":  r.rules_score,
        "ml_score":     r.ml_score,
        "alert_fired":  r.alert_fired,
        "scan_summary": r.scan_summary,
        "scanned_at":   r.scanned_at.isoformat() + "Z"
                        if r.scanned_at else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 10 helpers
# ─────────────────────────────────────────────────────────────────────────────

def _save_aggregated_score(result: dict, req) -> Optional[int]:
    """NOTE: must be called inside an active _flask_ctx() block."""
    try:
        bd = result.get("breakdown", {})
        record = AggregatedRiskScore(
            email_scan_id     = req.email_scan_id,
            url_scan_id       = req.url_scan_id,
            network_scan_id   = req.network_scan_id,
            attachment_id     = req.attachment_id,
            ai_detection_id   = req.ai_detection_id,
            image_scan_id     = req.image_scan_id,
            email_score       = bd.get("email",      {}).get("raw"),
            url_score         = bd.get("url",        {}).get("raw"),
            network_score     = bd.get("network",    {}).get("raw"),
            attachment_score  = bd.get("attachment", {}).get("raw"),
            ai_score          = bd.get("ai",         {}).get("raw"),
            image_score       = bd.get("image",      {}).get("raw"),
            email_weight      = result["weights_used"].get("email",      0.20),
            url_weight        = result["weights_used"].get("url",        0.25),
            network_weight    = result["weights_used"].get("network",    0.15),
            attachment_weight = result["weights_used"].get("attachment", 0.20),
            ai_weight         = result["weights_used"].get("ai",         0.10),
            image_weight      = result["weights_used"].get("image",      0.10),
            final_score       = result["final_score"],
            verdict           = result["verdict"],
            phases_used       = json.dumps(result["phases_used"]),
            breakdown         = json.dumps(result["breakdown"]),
            created_at        = datetime.datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        return record.id
    except Exception as e:
        logger.error(f"AggregatedRiskScore DB save error: {e}")
        db.session.rollback()
        return None


def _serialize_agg(r, full: bool = False) -> dict:
    try:
        phases = json.loads(r.phases_used or "[]")
    except Exception:
        phases = []
    base = {
        "id":               r.id,
        "final_score":      r.final_score,
        "verdict":          r.verdict,
        "phases_used":      phases,
        "email_scan_id":    r.email_scan_id,
        "url_scan_id":      r.url_scan_id,
        "network_scan_id":  r.network_scan_id,
        "attachment_id":    r.attachment_id,
        "ai_detection_id":  r.ai_detection_id,
        "image_scan_id":    r.image_scan_id,
        "email_score":      r.email_score,
        "url_score":        r.url_score,
        "network_score":    r.network_score,
        "attachment_score": r.attachment_score,
        "ai_score":         r.ai_score,
        "image_score":      r.image_score,
        "created_at":       r.created_at.isoformat() + "Z"
                            if r.created_at else "",
    }
    if full:
        try:
            base["breakdown"] = json.loads(r.breakdown or "{}")
        except Exception:
            base["breakdown"] = {}
    return base