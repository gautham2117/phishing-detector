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