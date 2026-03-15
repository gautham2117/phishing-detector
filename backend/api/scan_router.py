# scan_router.py
# FastAPI route handlers for all scan endpoints — Phases 1 through 6.
# Every endpoint follows the same pattern:
#   1. Validate input (Pydantic)
#   2. Call the relevant module
#   3. Save results to database
#   4. Return standardized JSON response via build_response()

import json
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel as PydanticBase

# ── Module imports ────────────────────────────────────────────────────────────
from backend.modules.email_parser import parse_email
from backend.modules.url_intelligence import analyze_url, analyze_url_batch
from backend.modules.network_scanner import scan_target, is_demo_target
from backend.modules.rule_engine import (
    analyze_url_rules, analyze_email_rules, get_all_rules
)
from backend.modules.ml_url_classifier import classify_url, classify_url_batch
from backend.modules.file_analyzer import analyze_file

# ── DB + response helpers ─────────────────────────────────────────────────────
from backend.app.database import db
from backend.app.models import (
    EmailScan, URLScan, NetworkScan,
    PortResult, AttachmentScan
)
from backend.app.utils.response import build_response, error_response
from backend.modules.image_detector import analyze_image
from backend.modules.ai_detector import (
    detect_ai_content,
    extract_text_from_url,
    extract_text_from_file,
)
from backend.modules.image_analyzer import analyze_image
from backend.modules.platform_monitor import (
    scan_target_full, extract_domain, get_due_targets, get_unified_feed
)


logger = logging.getLogger(__name__)
router = APIRouter()


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
    url:        str
    submitter:  Optional[str] = "anonymous"


class RuleScanEmailRequest(PydanticBase):
    subject:    str          = ""
    body_text:  str          = ""
    body_html:  str          = ""
    urls:       List[dict]   = []
    submitter:  Optional[str] = "anonymous"


class MLScanRequest(PydanticBase):
    url:         str
    rf_weight:   float = 0.45
    bert_weight: float = 0.55
    submitter:   Optional[str] = "anonymous"


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Email scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/email",
    summary="Scan raw email text for phishing",
    tags=["Phase 1 — Email"]
)
async def scan_email_text(request: EmailScanRequest):
    """
    Accept raw email text, parse all headers/body/URLs/attachments,
    run DistilBERT classification, and return a structured risk result.
    """
    try:
        parsed     = parse_email(request.raw_email)
        risk_score = _calculate_phase1_risk(parsed)
        label      = _score_to_label(risk_score)
        action     = _label_to_action(label)
        scan_id    = _save_email_scan(parsed, risk_score, label)

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
                }
            },
            explanation=_build_email_explanation(parsed, label),
            recommended_action=action
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"Email scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"Email scan error: {str(e)}")
        )


@router.post(
    "/scan/email/upload",
    summary="Upload and scan a .eml file",
    tags=["Phase 1 — Email"]
)
async def scan_email_file(
    file:      UploadFile    = File(...),
    submitter: Optional[str] = Form(default="anonymous")
):
    """Accept a .eml file upload and run the full parsing + ML pipeline."""
    if not file.filename.endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted."
        )

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
        scan_id    = _save_email_scan(
            parsed, risk_score, label, filename=file.filename
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
                }
            },
            explanation=_build_email_explanation(parsed, label),
            recommended_action=action
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"EML upload error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — URL intelligence
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/url",
    summary="Full intelligence analysis on a URL",
    tags=["Phase 2 — URL"]
)
async def scan_url(request: URLScanRequest):
    """
    WHOIS → SSL → IP/Geo → DNS → Redirects → BERT model → risk score.
    """
    try:
        result  = analyze_url(request.url)
        scan_id = _save_url_scan(result, email_id=None)

        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=result["label"],
            module_results={"url_intelligence": result},
            explanation=_build_url_explanation(result),
            recommended_action=_label_to_action(result["label"])
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"URL scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"URL scan error: {str(e)}")
        )


@router.post(
    "/scan/url/batch",
    summary="Scan multiple URLs from one email",
    tags=["Phase 2 — URL"]
)
async def scan_url_batch(
    urls:          List[str],
    email_scan_id: Optional[int] = Query(default=None)
):
    """Analyze a list of URLs — deduplicates by domain to avoid redundant lookups."""
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty.")
    if len(urls) > 50:
        raise HTTPException(status_code=400, detail="Batch limit is 50 URLs.")

    try:
        results = analyze_url_batch(urls)
        for result in results:
            _save_url_scan(result, email_id=email_scan_id)

        max_score = max((r["risk_score"] for r in results), default=0)
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
                    "benign":     sum(1 for r in results if r["label"] == "BENIGN"),
                    "results":    results
                }
            },
            explanation=(
                f"Analyzed {len(results)} URL(s). "
                f"Highest risk: {max_score:.1f}/100."
            ),
            recommended_action=_label_to_action(max_label)
        )

    except Exception as e:
        logger.error(f"Batch URL error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Network scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/network",
    summary="Nmap port scan against a target domain",
    tags=["Phase 3 — Network"]
)
async def scan_network(request: NetworkScanRequest):
    """
    Ethics gate → Nmap scan → port classification → risk level.
    Only demo/allowlisted targets scan without consent_confirmed=True.
    """
    try:
        result  = scan_target(
            target=request.target,
            scan_type=request.scan_type,
            consent_confirmed=request.consent_confirmed,
            url_scan_id=request.url_scan_id,
            email_scan_id=request.email_scan_id
        )
        scan_id = _save_network_scan(result)
        label   = _risk_level_to_label(result["risk_level"])
        score   = {
            "LOW": 10, "MEDIUM": 35, "HIGH": 65,
            "CRITICAL": 90, "UNKNOWN": 0
        }.get(result["risk_level"], 0)

        return build_response(
            status="success" if result.get("authorized") else "blocked",
            risk_score=score,
            label=label,
            module_results={"network_scan": result},
            explanation=_build_network_explanation(result),
            recommended_action=_label_to_action(label)
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"Network scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — Rule engine
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/rules/url",
    summary="Run heuristic rule engine against a URL",
    tags=["Phase 4 — Rules"]
)
async def scan_url_rules(request: RuleScanURLRequest):
    """Apply all 18 heuristic rules to a URL and return triggered rule hits."""
    try:
        result = analyze_url_rules(request.url)
        label  = _score_to_label(result["rule_score"])

        return build_response(
            status="success",
            risk_score=result["rule_score"],
            label=label,
            module_results={"rule_engine": result},
            explanation=_build_rules_explanation(result),
            recommended_action=_label_to_action(label)
        )

    except Exception as e:
        logger.error(f"URL rule scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


@router.post(
    "/scan/rules/email",
    summary="Run heuristic rule engine against email content",
    tags=["Phase 4 — Rules"]
)
async def scan_email_rules(request: RuleScanEmailRequest):
    """Apply email and URL heuristic rules to email subject, body, and URLs."""
    try:
        result = analyze_email_rules(
            subject=request.subject,
            body_text=request.body_text,
            body_html=request.body_html,
            urls=request.urls
        )
        label = _score_to_label(result["rule_score"])

        return build_response(
            status="success",
            risk_score=result["rule_score"],
            label=label,
            module_results={"rule_engine": result},
            explanation=_build_rules_explanation(result),
            recommended_action=_label_to_action(label)
        )

    except Exception as e:
        logger.error(f"Email rule scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


@router.get(
    "/rules/list",
    summary="Return full list of all heuristic rules",
    tags=["Phase 4 — Rules"]
)
async def list_all_rules():
    """Return metadata for every rule in the registry."""
    rules = get_all_rules()
    return {
        "status": "success",
        "rules":  rules,
        "total":  len(rules)
    }


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — ML classifier
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/ml/url",
    summary="Classify URL with RF + BERT soft-voting ensemble",
    tags=["Phase 5 — ML Classifier"]
)
async def scan_ml_url(request: MLScanRequest):
    """
    Random Forest (24 URL features) + BERT (raw URL string) combined
    via configurable soft-voting weights into a final phishing probability.
    """
    try:
        result     = classify_url(
            url=request.url,
            rf_weight=request.rf_weight,
            bert_weight=request.bert_weight
        )
        risk_score = round(result["ensemble_score"] * 100, 2)
        label      = (
            "MALICIOUS"  if risk_score >= 70 else
            "SUSPICIOUS" if risk_score >= 30 else
            "SAFE"
        )

        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={"ml_classifier": result},
            explanation=result["explanation"],
            recommended_action=_label_to_action(label)
        )

    except Exception as e:
        logger.error(f"ML classifier error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


@router.post(
    "/scan/ml/url/batch",
    summary="Classify multiple URLs with the ensemble",
    tags=["Phase 5 — ML Classifier"]
)
async def scan_ml_url_batch(urls: List[str]):
    """Classify a batch of URLs using the RF + BERT ensemble."""
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty.")
    if len(urls) > 30:
        raise HTTPException(
            status_code=400,
            detail="Batch limit is 30 URLs for the ML classifier."
        )

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
                    "results": results
                }
            },
            explanation=(
                f"Classified {len(results)} URLs. "
                f"Highest ensemble score: {max_score:.2f}."
            ),
            recommended_action=_label_to_action(label)
        )

    except Exception as e:
        logger.error(f"ML batch error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — File & attachment analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/file",
    summary="Analyze an uploaded file for malware and phishing",
    tags=["Phase 6 — File Analysis"]
)
async def scan_file(
    file:         UploadFile    = File(...),
    email_scan_id:Optional[int] = Form(default=None),
    submitter:    Optional[str] = Form(default="anonymous")
):
    """
    Compute file hashes, run YARA rules, calculate Shannon entropy,
    extract strings/macros, analyze HTML attachments.
    Accepts: PDF, DOCX, ZIP, EXE, HTML, JS, image files.
    """
    # Validate file size — max 25 MB for attachment analysis
    MAX_SIZE = 25 * 1024 * 1024

    file_bytes = await file.read()

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(file_bytes) > MAX_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File too large (max 25 MB for attachment analysis)."
        )

    try:
        result  = analyze_file(
            file_bytes=file_bytes,
            filename=file.filename or "unknown",
            email_scan_id=email_scan_id
        )
        scan_id = _save_attachment_scan(result, email_id=email_scan_id)

        # Map verdict to standard label
        verdict_map = {
            "Clean":      ("SAFE",      10),
            "Suspicious": ("SUSPICIOUS",55),
            "Malicious":  ("MALICIOUS", 85),
            "Unknown":    ("SUSPICIOUS",40),
        }
        label, risk_score = verdict_map.get(
            result.get("verdict", "Unknown"),
            ("SUSPICIOUS", 40)
        )

        return build_response(
            status="success",
            risk_score=float(risk_score),
            label=label,
            module_results={"file_analysis": result},
            explanation=_build_file_explanation(result),
            recommended_action=_label_to_action(label)
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"File scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/scan/file/batch",
    summary="Analyze multiple file attachments from one email",
    tags=["Phase 6 — File Analysis"]
)
async def scan_file_batch(
    files:        List[UploadFile] = File(...),
    email_scan_id:Optional[int]    = Form(default=None)
):
    """Analyze multiple attachments in one request."""
    if not files:
        raise HTTPException(status_code=400, detail="No files provided.")
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Max 10 files per batch.")

    results    = []
    max_score  = 0
    max_label  = "SAFE"

    verdict_map = {
        "Clean":      ("SAFE",      10),
        "Suspicious": ("SUSPICIOUS",55),
        "Malicious":  ("MALICIOUS", 85),
        "Unknown":    ("SUSPICIOUS",40),
    }

    for upload in files:
        try:
            file_bytes = await upload.read()
            if len(file_bytes) == 0:
                continue

            result  = analyze_file(
                file_bytes=file_bytes,
                filename=upload.filename or "unknown",
                email_scan_id=email_scan_id
            )
            _save_attachment_scan(result, email_id=email_scan_id)
            results.append(result)

            label, score = verdict_map.get(
                result.get("verdict", "Unknown"), ("SUSPICIOUS", 40)
            )
            if score > max_score:
                max_score = score
                max_label = label

        except Exception as e:
            logger.error(f"Batch file error for {upload.filename}: {e}")
            results.append({
                "filename": upload.filename,
                "error":    str(e),
                "verdict":  "Unknown"
            })

    return build_response(
        status="success",
        risk_score=float(max_score),
        label=max_label,
        module_results={
            "file_batch": {
                "total":   len(results),
                "results": results
            }
        },
        explanation=(
            f"Analyzed {len(results)} file(s). "
            f"Highest risk verdict: {max_label}."
        ),
        recommended_action=_label_to_action(max_label)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Shared helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _score_to_label(score: float) -> str:
    """Convert a 0–100 risk score to a standard label."""
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


def _label_to_action(label: str) -> str:
    """Map a label to a recommended analyst action."""
    return {
        "SAFE":      "ALLOW",
        "BENIGN":    "ALLOW",
        "LEGITIMATE":"ALLOW",
        "SUSPICIOUS":"WARN",
        "MALICIOUS": "QUARANTINE"
    }.get(label, "WARN")


def _risk_level_to_label(risk_level: str) -> str:
    """Convert Nmap risk level to standard label."""
    return {
        "LOW":      "SAFE",
        "MEDIUM":   "SUSPICIOUS",
        "HIGH":     "SUSPICIOUS",
        "CRITICAL": "MALICIOUS",
        "UNKNOWN":  "SUSPICIOUS"
    }.get(risk_level, "SUSPICIOUS")


# ── Phase 1 helpers ───────────────────────────────────────────────────────────

def _calculate_phase1_risk(parsed: dict) -> float:
    """
    Compute a Phase 1 preliminary risk score (0–100).
    DistilBERT score contributes up to 60 pts,
    header anomalies up to 30 pts, auth failures up to 10 pts.
    """
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

    auth = parsed.get("auth_results", {})
    if auth.get("spf")   in ("fail", "softfail", "none"): score += 3
    if auth.get("dkim")  in ("fail", "none"):              score += 4
    if auth.get("dmarc") in ("fail", "none"):              score += 3

    return round(min(score, 100.0), 2)


def _build_email_explanation(parsed: dict, label: str) -> str:
    parts = []

    d = parsed.get("distilbert_result", {})
    if d.get("label") == "PHISHING":
        parts.append(
            f"DistilBERT classified body as phishing "
            f"({int(d.get('score', 0) * 100)}% confidence)."
        )

    highs = [
        a for a in parsed.get("anomalies", [])
        if a.get("severity") == "high"
    ]
    if highs:
        parts.append(f"Header anomaly: {highs[0]['description']}")

    auth = parsed.get("auth_results", {})
    if auth.get("spf")  == "fail": parts.append("SPF failed.")
    if auth.get("dkim") == "fail": parts.append("DKIM failed.")

    n = len(parsed.get("urls", []))
    if n:
        parts.append(f"{n} URL(s) extracted for further analysis.")

    return " ".join(parts) or f"Email assessed as {label}."


def _save_email_scan(
    parsed: dict,
    risk_score: float,
    label: str,
    filename: str = ""
) -> Optional[int]:
    """Persist a parsed email result to the EmailScan table."""
    try:
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
            label        = label
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
        db.session.rollback()
        return None


# ── Phase 2 helpers ───────────────────────────────────────────────────────────

def _build_url_explanation(result: dict) -> str:
    from urllib.parse import urlparse
    parts = []

    ml = result.get("ml_result", {})
    if ml.get("label") == "MALICIOUS":
        parts.append(
            f"ML model classified URL as malicious "
            f"({int(ml.get('score', 0) * 100)}% confidence)."
        )

    w = result.get("whois", {})
    if w.get("is_young_domain"):
        parts.append(
            f"Domain is only {w.get('domain_age_days')} days old."
        )

    s = result.get("ssl", {})
    if not s.get("has_ssl"):
        parts.append("URL uses plain HTTP — no SSL.")
    elif s.get("is_self_signed"):
        parts.append("SSL certificate is self-signed.")
    elif s.get("is_expired"):
        parts.append("SSL certificate has expired.")

    r = result.get("redirects", {})
    if r.get("hop_count", 0) > 2:
        final = urlparse(r.get("final_url", "")).netloc
        parts.append(
            f"Redirects through {r['hop_count']} hops "
            f"(final: {final})."
        )

    flags = result.get("flags", [])
    if not parts and flags:
        parts.append(f"Risk flags: {', '.join(flags[:3])}.")

    return " ".join(parts) or "URL analyzed — no high-risk indicators."


def _save_url_scan(
    result: dict,
    email_id: Optional[int] = None
) -> Optional[int]:
    """Persist a URL intelligence result to the URLScan table."""
    try:
        scan = URLScan(
            email_id        = email_id,
            raw_url         = result.get("original_url",   "")[:2048],
            normalized_url  = result.get("normalized_url", "")[:2048],
            domain          = result.get("domain",         "")[:255],
            ip_address      = result.get("ip", {}).get("ip_address", ""),
            country         = result.get("ip", {}).get("country",    ""),
            whois_data      = json.dumps(result.get("whois", {})),
            domain_age_days = result.get("whois", {}).get("domain_age_days"),
            ssl_valid       = result.get("ssl",  {}).get("valid",  False),
            ssl_issuer      = (result.get("ssl", {}).get("issuer") or "")[:255],
            redirect_chain  = json.dumps(
                result.get("redirects", {}).get("chain", [])
            ),
            ml_score        = result.get("ml_result", {}).get("score", 0.0),
            final_label     = result.get("label", "UNKNOWN")
        )
        db.session.add(scan)
        db.session.commit()
        return scan.id

    except Exception as e:
        logger.error(f"URLScan DB save error: {e}")
        db.session.rollback()
        return None


# ── Phase 3 helpers ───────────────────────────────────────────────────────────

def _build_network_explanation(result: dict) -> str:
    if not result.get("authorized"):
        return f"Scan blocked: {result.get('block_reason', 'authorization required')}"

    if result.get("error") and not result.get("ports"):
        return f"Scan error: {result['error']}"

    parts = [
        f"Found {result.get('open_port_count', 0)} open port(s) — "
        f"risk level: {result.get('risk_level', 'UNKNOWN')}."
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

    return " ".join(parts)


def _save_network_scan(result: dict) -> Optional[int]:
    """Persist a NetworkScan and its PortResult rows."""
    try:
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
            scan_duration_s  = result.get("scan_duration_s", 0),
            authorized       = result.get("authorized",   False)
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
                cpe              = p.get("cpe",             "")[:255]
            ))

        db.session.commit()
        return scan.id

    except Exception as e:
        logger.error(f"NetworkScan DB save error: {e}")
        db.session.rollback()
        return None


# ── Phase 4 helpers ───────────────────────────────────────────────────────────

def _build_rules_explanation(result: dict) -> str:
    hits = result.get("hits", [])
    if not hits:
        return "No heuristic rules triggered — input appears clean."

    critical = [h for h in hits if h.get("severity") == "CRITICAL"]
    high     = [h for h in hits if h.get("severity") == "HIGH"]

    parts = [f"{len(hits)} rule(s) triggered (score: {result['rule_score']}/100)."]

    if critical:
        parts.append(f"Critical: {critical[0]['name']}.")
    elif high:
        parts.append(f"High severity: {high[0]['name']}.")

    return " ".join(parts)


# ── Phase 6 helpers ───────────────────────────────────────────────────────────

def _build_file_explanation(result: dict) -> str:
    parts = []

    verdict = result.get("verdict", "Unknown")
    parts.append(f"File verdict: {verdict}.")

    yara = result.get("yara_matches", [])
    if yara:
        parts.append(
            f"YARA rules matched: {', '.join(yara[:3])}."
        )

    entropy = result.get("entropy")
    if entropy and entropy > 7.0:
        parts.append(
            f"High entropy ({entropy:.2f}) suggests "
            f"packed or encrypted content."
        )

    hashes = result.get("hashes", {})
    if hashes.get("sha256"):
        parts.append(
            f"SHA-256: {hashes['sha256'][:16]}..."
        )

    static = result.get("static_findings", [])
    if static:
        parts.append(
            f"{len(static)} suspicious string(s) found in static analysis."
        )

    return " ".join(parts) or f"File analyzed — verdict: {verdict}."


def _save_attachment_scan(
    result: dict,
    email_id: Optional[int] = None
) -> Optional[int]:
    """Persist a file analysis result to the AttachmentScan table."""
    try:
        hashes = result.get("hashes", {})
        scan = AttachmentScan(
            email_id     = email_id,
            filename     = result.get("filename",    "unknown")[:255],
            file_type    = result.get("file_type",   "unknown")[:50],
            md5          = hashes.get("md5",         "")[:32],
            sha256       = hashes.get("sha256",      "")[:64],
            file_size    = result.get("file_size",   0),
            entropy      = result.get("entropy",     0.0),
            yara_matches = json.dumps(result.get("yara_matches",    [])),
            static_finds = json.dumps(result.get("static_findings", [])),
            verdict      = result.get("verdict",     "Unknown")
        )
        db.session.add(scan)
        db.session.commit()
        return scan.id

    except Exception as e:
        logger.error(f"AttachmentScan DB save error: {e}")
        db.session.rollback()
        return None

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — Image analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/image",
    summary="Analyze an image for phishing indicators",
    tags=["Phase 7 — Image Analysis"]
)
async def scan_image(
    file:         UploadFile    = File(...),
    email_scan_id:Optional[int] = Form(default=None),
    submitter:    Optional[str] = Form(default="anonymous")
):
    """
    Run the full image phishing detection pipeline:
      Tesseract OCR → DistilBERT → OpenCV form detection → ViT classifier.

    Accepted formats: PNG, JPG, JPEG, BMP, WEBP, GIF.
    Max file size: 20 MB.
    """
    # Validate file type
    allowed_extensions = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif"}
    filename  = file.filename or "image.png"
    extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{extension}'. "
                f"Accepted: {', '.join(allowed_extensions)}"
            )
        )

    # Read and validate file size
    image_bytes = await file.read()

    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(image_bytes) > 20 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Image too large (max 20 MB)."
        )

    try:
        # Run the full image analysis pipeline
        result = analyze_image(
            image_bytes=image_bytes,
            filename=filename
        )

        # Map verdict to standard label and risk score
        verdict_map = {
            "Malicious":  ("MALICIOUS",  result["risk_score"]),
            "Suspicious": ("SUSPICIOUS", result["risk_score"]),
            "Clean":      ("SAFE",       result["risk_score"]),
            "Unknown":    ("SUSPICIOUS", 30.0),
        }
        label, risk_score = verdict_map.get(
            result.get("verdict", "Unknown"),
            ("SUSPICIOUS", 30.0)
        )

        return build_response(
            status="success",
            risk_score=float(risk_score),
            label=label,
            module_results={"image_analysis": result},
            explanation=result.get("explanation", ""),
            recommended_action=_label_to_action(label)
        )

    except Exception as e:
        logger.error(f"Image scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))



#temporary

@router.get("/debug/email", tags=["Debug"])
async def debug_email():
    """Quick health check — confirms email_parser imports correctly."""
    try:
        from backend.modules.email_parser import parse_email
        return {"status": "ok", "message": "email_parser imported successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 — Image Analysis
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/image",
    summary="Analyse an uploaded image for phishing indicators",
    tags=["Image Analysis"]
)
async def scan_image(
    file: UploadFile = File(...),
):
    """
    Accepts PNG, JPG, GIF, BMP, or WEBP image uploads.

    Runs:
      • OCR text extraction via Tesseract
      • Known brand / logo detection in OCR text
      • Phishing keyword pattern matching
      • DistilBERT email phishing classifier on extracted text
      • Risk scoring and verdict (CLEAN / SUSPICIOUS / MALICIOUS)
      • Persists result to ImageAnalysisScan table
    """
    try:
        file_bytes = await file.read()
        filename   = file.filename or "unknown_image"

        if not file_bytes:
            raise HTTPException(status_code=400, detail="Empty file received.")

        result  = analyze_image(file_bytes, filename)
        verdict = result.get("verdict", "CLEAN")
        score   = result.get("risk_score", 5.0)

        label_map = {
            "CLEAN":     "SAFE",
            "SUSPICIOUS":"SUSPICIOUS",
            "MALICIOUS": "MALICIOUS",
        }
        label  = label_map.get(verdict, "SUSPICIOUS")
        action = _label_to_action(label)

        db_id = _save_image_scan(result, filename)
        result["db_id"] = db_id

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


# ── Phase 7 DB helper ─────────────────────────────────────────────────────────

def _save_image_scan(result: dict, filename: str) -> Optional[int]:
    try:
        import json as _json
        import datetime
        from backend.app.models import ImageAnalysisScan

        record = ImageAnalysisScan(
            filename          = filename[:255],
            file_size         = result.get("file_size",       0),
            image_width       = result.get("image_width",     0),
            image_height      = result.get("image_height",    0),
            image_format      = result.get("image_format",    "")[:20],
            ocr_text          = result.get("ocr_text",        "")[:10000],
            ocr_word_count    = result.get("ocr_word_count",  0),
            detected_brands   = _json.dumps(result.get("detected_brands",   [])),
            phishing_keywords = _json.dumps(result.get("phishing_keywords", [])),
            classifier_label  = result.get("classifier_result",{}).get("label","")[:30],
            classifier_score  = result.get("classifier_result",{}).get("score", 0.0),
            verdict           = result.get("verdict",   "CLEAN"),
            risk_score        = result.get("risk_score",  5.0),
            scanned_at        = datetime.datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        return record.id

    except Exception as e:
        logger.error(f"ImageAnalysisScan DB save error: {e}")
        db.session.rollback()
        return None
    

# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — AI-Generated Content Detection
# ─────────────────────────────────────────────────────────────────────────────

class AIDetectTextRequest(PydanticBase):
    text:       str
    source_ref: Optional[str] = ""


class AIDetectURLRequest(PydanticBase):
    url:        str


@router.post(
    "/scan/ai/text",
    summary="Detect AI-generated text (plain text input)",
    tags=["AI Detection"]
)
async def scan_ai_text(request: AIDetectTextRequest):
    """
    Run chatgpt-detector-roberta against plain text.
    Returns overall AI probability, per-sentence scores, and verdict.
    """
    try:
        result = detect_ai_content(
            text=request.text,
            source_ref=request.source_ref or "",
            input_type="text",
        )
        db_id = _save_ai_detection_scan(result)
        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=_ai_verdict_to_label(result["verdict"]),
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=_label_to_action(
                _ai_verdict_to_label(result["verdict"])
            ),
        ) | {"scan_id": db_id}

    except Exception as e:
        logger.error(f"AI text detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


@router.post(
    "/scan/ai/url",
    summary="Detect AI-generated content from a URL",
    tags=["AI Detection"]
)
async def scan_ai_url(request: AIDetectURLRequest):
    """
    Fetch URL, extract plain text, then run AI detection.
    """
    try:
        text = extract_text_from_url(request.url)
        if not text.strip():
            return JSONResponse(
                status_code=422,
                content=error_response("Could not extract text from URL.")
            )
        result = detect_ai_content(
            text=text,
            source_ref=request.url,
            input_type="url",
        )
        db_id = _save_ai_detection_scan(result)
        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=_ai_verdict_to_label(result["verdict"]),
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=_label_to_action(
                _ai_verdict_to_label(result["verdict"])
            ),
        ) | {"scan_id": db_id}

    except Exception as e:
        logger.error(f"AI URL detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


@router.post(
    "/scan/ai/file",
    summary="Detect AI-generated content from an uploaded file",
    tags=["AI Detection"]
)
async def scan_ai_file(
    file: UploadFile = File(...),
):
    """
    Extract text from uploaded file (txt, html, eml, pdf, docx),
    then run AI detection.
    """
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
            text=text,
            source_ref=filename,
            input_type="file",
        )
        db_id = _save_ai_detection_scan(result)
        return build_response(
            status="success",
            risk_score=result["risk_score"],
            label=_ai_verdict_to_label(result["verdict"]),
            module_results={"ai_detection": result},
            explanation=result["explanation"],
            recommended_action=_label_to_action(
                _ai_verdict_to_label(result["verdict"])
            ),
        ) | {"scan_id": db_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI file detect error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


# ── Phase 8 helpers ───────────────────────────────────────────────────────────

def _ai_verdict_to_label(verdict: str) -> str:
    return {
        "HUMAN":        "SAFE",
        "MIXED":        "SUSPICIOUS",
        "AI_GENERATED": "MALICIOUS",
    }.get(verdict, "SUSPICIOUS")


def _save_ai_detection_scan(result: dict) -> Optional[int]:
    try:
        import json as _json
        import datetime
        from backend.app.models import AIDetectionScan

        record = AIDetectionScan(
            input_type     = result.get("input_type",     "text"),
            source_ref     = result.get("source_ref",     "")[:512],
            input_preview  = result.get("input_preview",  "")[:500],
            char_count     = result.get("char_count",     0),
            sentence_count = result.get("sentence_count", 0),
            ai_probability = result.get("ai_probability", 0.0),
            verdict        = result.get("verdict",        "HUMAN"),
            risk_score     = result.get("risk_score",     0.0),
            sentence_scores= _json.dumps(result.get("sentence_scores", [])),
            scanned_at     = datetime.datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        return record.id

    except Exception as e:
        logger.error(f"AIDetectionScan DB save error: {e}")
        db.session.rollback()
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Phase 9 — Platform Monitor
# ─────────────────────────────────────────────────────────────────────────────

class AddTargetRequest(PydanticBase):
    url:              str
    label:            Optional[str] = ""
    interval_minutes: int           = 60
    alert_threshold:  float         = 50.0


@router.post(
    "/platform/targets",
    summary="Add a URL to the monitoring watchlist",
    tags=["Platform Monitor"]
)
async def add_monitor_target(req: AddTargetRequest):
    try:
        import datetime
        from backend.app.models import MonitoredTarget

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
        return {"status": "success", "target_id": target.id,
                "message": f"Target '{target.label}' added to watchlist."}
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add monitor target error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.delete(
    "/platform/targets/{target_id}",
    summary="Remove a target from the watchlist",
    tags=["Platform Monitor"]
)
async def remove_monitor_target(target_id: int):
    try:
        from backend.app.models import MonitoredTarget
        target = db.session.get(MonitoredTarget, target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found.")
        db.session.delete(target)
        db.session.commit()
        return {"status": "success", "message": "Target removed."}
    except HTTPException:
        raise
    except Exception as e:
        db.session.rollback()
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post(
    "/platform/targets/{target_id}/scan",
    summary="Manually trigger a scan for a monitored target",
    tags=["Platform Monitor"]
)
async def manual_scan_target(target_id: int):
    try:
        import datetime
        from backend.app.models import MonitoredTarget, MonitorScanResult

        target = db.session.get(MonitoredTarget, target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found.")

        result     = scan_target_full(target.url)
        alert_fired= result["risk_score"] >= target.alert_threshold

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
        db.session.rollback()
        logger.error(f"Manual scan error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get(
    "/platform/targets",
    summary="List all monitored targets",
    tags=["Platform Monitor"]
)
async def list_monitor_targets():
    try:
        from backend.app.models import MonitoredTarget
        targets = MonitoredTarget.query.order_by(
            MonitoredTarget.created_at.desc()
        ).all()
        return {
            "status":  "success",
            "targets": [_serialize_target(t) for t in targets],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.get(
    "/platform/targets/{target_id}/history",
    summary="Get scan history for a monitored target",
    tags=["Platform Monitor"]
)
async def target_scan_history(target_id: int, limit: int = 20):
    try:
        from backend.app.models import MonitorScanResult
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


@router.get(
    "/platform/feed",
    summary="Unified threat feed from all modules",
    tags=["Platform Monitor"]
)
async def unified_feed(limit: int = 50):
    try:
        feed = get_unified_feed(limit=limit)
        return {"status": "success", "feed": feed, "total": len(feed)}
    except Exception as e:
        return JSONResponse(status_code=500, content=error_response(str(e)))


@router.post(
    "/platform/poll",
    summary="Check for due targets and rescan them",
    tags=["Platform Monitor"]
)
async def poll_due_targets():
    """
    Called by the dashboard JS every 30 seconds.
    Finds targets that are due for rescanning and runs them.
    Returns count of targets scanned and any alerts fired.
    """
    try:
        import datetime
        from backend.app.models import MonitoredTarget, MonitorScanResult

        now      = datetime.datetime.utcnow()
        targets  = MonitoredTarget.query.filter_by(is_active=True).all()
        scanned  = []
        alerts   = []

        for t in targets:
            due = False
            if t.last_scanned is None:
                due = True
            else:
                delta = (now - t.last_scanned).total_seconds() / 60
                if delta >= t.interval_minutes:
                    due = True

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

            scanned.append({"target_id": t.id, "label": t.label,
                            "risk_score": result["risk_score"]})
            if alert_fired:
                alerts.append({"target_id": t.id, "label": t.label,
                               "risk_score": result["risk_score"],
                               "verdict": result["verdict"]})

        db.session.commit()
        return {
            "status":         "success",
            "scanned_count":  len(scanned),
            "alert_count":    len(alerts),
            "scanned":        scanned,
            "alerts":         alerts,
        }
    except Exception as e:
        db.session.rollback()
        logger.error(f"Poll due targets error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content=error_response(str(e)))


# ── Phase 9 serializers ───────────────────────────────────────────────────────

def _serialize_target(t) -> dict:
    return {
        "id":               t.id,
        "url":              t.url,
        "domain":           t.domain,
        "label":            t.label,
        "interval_minutes": t.interval_minutes,
        "alert_threshold":  t.alert_threshold,
        "last_scanned":     t.last_scanned.isoformat() + "Z" if t.last_scanned else None,
        "last_risk_score":  t.last_risk_score,
        "last_verdict":     t.last_verdict,
        "is_active":        t.is_active,
        "created_at":       t.created_at.isoformat() + "Z" if t.created_at else "",
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
        "scanned_at":   r.scanned_at.isoformat() + "Z" if r.scanned_at else "",
    }