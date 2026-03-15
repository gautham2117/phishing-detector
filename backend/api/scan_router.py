# scan_router.py
# FastAPI route handlers for all scan endpoints.
# Covers Phase 1 (email), Phase 2 (URL), Phase 3 (network).

import json
import logging
from datetime import datetime
from typing import Optional, List                          # ← fixes NameError

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel as PydanticBase

from backend.modules.email_parser import parse_email
from backend.modules.url_intelligence import analyze_url, analyze_url_batch
from backend.modules.network_scanner import scan_target, is_demo_target
from backend.app.database import db
from backend.app.models import EmailScan, URLScan, NetworkScan, PortResult
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
    scan_type:          str  = "top100"    # quick | top100 | top1000 | full
    consent_confirmed:  bool = False
    url_scan_id:        Optional[int] = None
    email_scan_id:      Optional[int] = None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Email scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/email",
    summary="Scan a raw email text for phishing",
    tags=["Email Scanning"]
)
async def scan_email_text(request: EmailScanRequest):
    """
    Accept raw email text, parse it, run DistilBERT,
    and return a structured risk result.
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
    tags=["Email Scanning"]
)
async def scan_email_file(
    file:      UploadFile        = File(...),
    submitter: Optional[str]     = Form(default="anonymous")
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
        scan_id    = _save_email_scan(parsed, risk_score, label,
                                      filename=file.filename)

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
        logger.error(f"EML upload scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — URL scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/url",
    summary="Run full intelligence analysis on a URL",
    tags=["URL Scanning"]
)
async def scan_url(request: URLScanRequest):
    """
    Run WHOIS → SSL → IP/Geo → DNS → Redirects → BERT model
    against a single URL and return a structured risk result.
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
    summary="Scan multiple URLs (e.g. all URLs from one email)",
    tags=["URL Scanning"]
)
async def scan_url_batch(
    urls: List[str],
    email_scan_id: Optional[int] = Query(default=None)
):
    """
    Analyze a list of URLs in one request.
    Domains are deduplicated to avoid redundant WHOIS/DNS lookups.
    """
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty.")

    if len(urls) > 50:
        raise HTTPException(
            status_code=400,
            detail="Batch limit is 50 URLs per request."
        )

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
                f"Highest risk score: {max_score:.1f}/100."
            ),
            recommended_action=_label_to_action(max_label)
        )

    except Exception as e:
        logger.error(f"Batch URL scan error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(str(e))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Network scanning
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/network",
    summary="Run an Nmap port scan against a target domain",
    tags=["Network Scanning"]
)
async def scan_network(request: NetworkScanRequest):
    """
    Run a network scan against a domain or IP address.

    Ethics gate: only demo/allowlisted targets are scanned without
    additional consent. For any other target set consent_confirmed=True
    AND have SCAN_AUTHORIZED=1 in your .env file.
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
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _score_to_label(score: float) -> str:
    if score < 30:  return "SAFE"
    if score < 70:  return "SUSPICIOUS"
    return "MALICIOUS"


def _label_to_action(label: str) -> str:
    return {
        "SAFE":      "ALLOW",
        "BENIGN":    "ALLOW",
        "SUSPICIOUS":"WARN",
        "MALICIOUS": "QUARANTINE"
    }.get(label, "WARN")


def _risk_level_to_label(risk_level: str) -> str:
    return {
        "LOW":      "SAFE",
        "MEDIUM":   "SUSPICIOUS",
        "HIGH":     "SUSPICIOUS",
        "CRITICAL": "MALICIOUS",
        "UNKNOWN":  "SUSPICIOUS"
    }.get(risk_level, "SUSPICIOUS")


# ── Phase 1 helpers ───────────────────────────────────────────────────────────

def _calculate_phase1_risk(parsed: dict) -> float:
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

    return " ".join(parts) or f"Email assessed as {label}. No critical indicators."


def _save_email_scan(parsed: dict, risk_score: float,
                     label: str, filename: str = "") -> Optional[int]:
    try:
        scan = EmailScan(
            filename     = filename or "pasted_email",
            sender       = parsed.get("sender", ""),
            recipient    = parsed.get("recipient", ""),
            subject      = parsed.get("subject", ""),
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
                raw_url        = url_data.get("raw", "")[:2048],
                normalized_url = url_data.get("normalized", "")[:2048],
                domain         = url_data.get("domain", "")[:255],
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
            f"(final destination: {final})."
        )

    flags = result.get("flags", [])
    if not parts and flags:
        parts.append(f"Risk flags: {', '.join(flags[:3])}.")

    return " ".join(parts) or "URL analyzed — no high-risk indicators."


def _save_url_scan(result: dict,
                   email_id: Optional[int] = None) -> Optional[int]:
    try:
        scan = URLScan(
            email_id        = email_id,
            raw_url         = result.get("original_url",  "")[:2048],
            normalized_url  = result.get("normalized_url","")[:2048],
            domain          = result.get("domain",        "")[:255],
            ip_address      = result.get("ip", {}).get("ip_address", ""),
            country         = result.get("ip", {}).get("country",    ""),
            whois_data      = json.dumps(result.get("whois", {})),
            domain_age_days = result.get("whois", {}).get("domain_age_days"),
            ssl_valid       = result.get("ssl",  {}).get("valid",  False),
            ssl_issuer      = (result.get("ssl",  {}).get("issuer") or "")[:255],
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

    parts = []
    parts.append(
        f"Found {result.get('open_port_count', 0)} open port(s) — "
        f"overall risk: {result.get('risk_level', 'UNKNOWN')}."
    )

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