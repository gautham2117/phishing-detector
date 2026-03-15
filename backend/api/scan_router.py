# scan_router.py
# FastAPI route handlers for all scan endpoints.
# These are the endpoints the Flask dashboard calls via fetch(),
# and what the Chrome extension calls directly.
#
# All endpoints follow the same pattern:
#   1. Validate input (Pydantic handles this automatically)
#   2. Call the relevant module
#   3. Save results to the database
#   4. Return a standardized JSON response

import json
import logging
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse
from typing import Optional

from .schemas import EmailScanRequest, EmailScanResponse
from backend.modules.email_parser import parse_email
from backend.app.database import db
from backend.app.models import EmailScan, URLScan
from backend.app.utils.response import build_response, error_response

logger = logging.getLogger(__name__)

# All routes in this file are prefixed with /api (set in main.py)
router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/scan/email  — scan a raw email text body
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/email",
    response_model=EmailScanResponse,
    summary="Scan a raw email text for phishing",
    tags=["Email Scanning"]
)
async def scan_email_text(request: EmailScanRequest):
    """
    Accept raw email text, parse it, run DistilBERT, and return results.
    This endpoint is called by the dashboard's paste-email form.
    """
    try:
        # Parse the email — this runs all 8 steps in email_parser.py
        parsed = parse_email(request.raw_email)

        # Calculate a preliminary risk score from this phase only.
        # The full Risk Scoring Engine (Module 10) will combine all modules.
        # For now: DistilBERT score × 70 (max 70 points from email body)
        # + anomaly count × 5 (up to 30 from header checks)
        risk_score = _calculate_phase1_risk(parsed)
        label      = _score_to_label(risk_score)
        action     = _label_to_action(label)

        # Save to database
        scan_id = _save_email_scan(parsed, risk_score, label)

        # Build the standard response
        return build_response(
            status="success",
            risk_score=risk_score,
            label=label,
            module_results={
                "email_parser": {
                    "sender":         parsed["sender"],
                    "recipient":      parsed["recipient"],
                    "reply_to":       parsed["reply_to"],
                    "subject":        parsed["subject"],
                    "date":           parsed["date"],
                    "auth_results":   parsed["auth_results"],
                    "anomalies":      parsed["anomalies"],
                    "url_count":      len(parsed["urls"]),
                    "attachment_count": len(parsed["attachments"]),
                    "urls":           parsed["urls"],
                    "distilbert":     parsed["distilbert_result"],
                }
            },
            explanation=_build_explanation(parsed, label),
            recommended_action=action
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"Email scan endpoint error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=error_response(f"Internal error during email scan: {str(e)}")
        )


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/scan/email/upload  — scan an uploaded .eml file
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/scan/email/upload",
    summary="Upload and scan a .eml file",
    tags=["Email Scanning"]
)
async def scan_email_file(
    file: UploadFile = File(..., description=".eml file to scan"),
    submitter: Optional[str] = Form(default="anonymous")
):
    """
    Accept a .eml file upload, parse it, run analysis, return results.
    Called by the dashboard's file upload form.

    FastAPI handles multipart form parsing automatically via UploadFile.
    """
    # Validate file type
    if not file.filename.endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted. Use the text endpoint for raw email."
        )

    # Read the file bytes (max 10MB — reasonable for email files)
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    try:
        file_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read uploaded file: {e}")

    if len(file_bytes) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        # Parse the .eml bytes
        parsed = parse_email(file_bytes)

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
                    "filename":       file.filename,
                    "sender":         parsed["sender"],
                    "recipient":      parsed["recipient"],
                    "reply_to":       parsed["reply_to"],
                    "subject":        parsed["subject"],
                    "date":           parsed["date"],
                    "auth_results":   parsed["auth_results"],
                    "anomalies":      parsed["anomalies"],
                    "url_count":      len(parsed["urls"]),
                    "attachment_count": len(parsed["attachments"]),
                    "urls":           parsed["urls"],
                    "distilbert":     parsed["distilbert_result"],
                }
            },
            explanation=_build_explanation(parsed, label),
            recommended_action=action
        ) | {"scan_id": scan_id}

    except Exception as e:
        logger.error(f"EML file scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_phase1_risk(parsed: dict) -> float:
    """
    Calculate a Phase 1 risk score (0–100) using only the data we have now:
      - DistilBERT phishing score → up to 60 points
      - Header anomaly count → up to 30 points
      - Auth failures (SPF/DKIM/DMARC fail) → up to 10 points

    The full Risk Engine (Module 10) will recalculate this when all
    modules have run. This is the "quick score" for Phase 1 only.
    """
    score = 0.0

    # DistilBERT contribution (0–60)
    distilbert = parsed.get("distilbert_result", {})
    if distilbert.get("label") == "PHISHING":
        # Scale the confidence score (0–1) to a 0–60 range
        score += distilbert.get("score", 0.5) * 60
    elif distilbert.get("label") == "SAFE":
        # For SAFE predictions, add a small base score in case other signals disagree
        score += (1 - distilbert.get("score", 0.5)) * 10

    # Anomaly contribution (up to 30 points)
    anomalies = parsed.get("anomalies", [])
    severity_weights = {"high": 10, "medium": 5, "low": 2}
    anomaly_score = sum(severity_weights.get(a.get("severity", "low"), 2) for a in anomalies)
    score += min(anomaly_score, 30)  # Cap at 30

    # Auth failure contribution (up to 10 points)
    auth = parsed.get("auth_results", {})
    auth_score = 0
    if auth.get("spf")  in ("fail", "softfail", "none"): auth_score += 3
    if auth.get("dkim") in ("fail", "none"):              auth_score += 4
    if auth.get("dmarc") in ("fail", "none"):             auth_score += 3
    score += min(auth_score, 10)

    return round(min(score, 100.0), 2)


def _score_to_label(score: float) -> str:
    """Convert a 0–100 risk score to a human-readable label."""
    if score < 30:   return "SAFE"
    if score < 70:   return "SUSPICIOUS"
    return "MALICIOUS"


def _label_to_action(label: str) -> str:
    """Map a label to a recommended action for the analyst."""
    return {
        "SAFE":      "ALLOW",
        "SUSPICIOUS":"WARN",
        "MALICIOUS": "QUARANTINE"
    }.get(label, "WARN")


def _build_explanation(parsed: dict, label: str) -> str:
    """
    Build a plain-language explanation string from the parsed results.
    In Phase 1 we construct this manually. In Module 13 (Alerting),
    the BART model will generate a richer version.
    """
    parts = []

    distilbert = parsed.get("distilbert_result", {})
    if distilbert.get("label") == "PHISHING":
        conf = int(distilbert.get("score", 0) * 100)
        parts.append(f"DistilBERT classified the email body as phishing with {conf}% confidence.")

    anomalies = parsed.get("anomalies", [])
    if anomalies:
        high = [a for a in anomalies if a["severity"] == "high"]
        if high:
            parts.append(f"High-severity header anomaly detected: {high[0]['description']}")

    auth = parsed.get("auth_results", {})
    if auth.get("spf") == "fail":
        parts.append("SPF authentication failed — sender domain may be spoofed.")
    if auth.get("dkim") == "fail":
        parts.append("DKIM signature failed — email may have been tampered with.")

    url_count = len(parsed.get("urls", []))
    if url_count > 0:
        parts.append(f"{url_count} URL(s) extracted for further analysis.")

    if not parts:
        return f"Email scanned and assessed as {label}. No critical indicators found."

    return " ".join(parts)


def _save_email_scan(parsed: dict, risk_score: float,
                      label: str, filename: str = "") -> Optional[int]:
    """
    Persist the parsed email results to the database.
    Returns the new EmailScan.id, or None if the save failed.

    We use a try/except so that a DB failure doesn't break the API response —
    the scan result is still returned to the user.
    """
    try:
        scan = EmailScan(
            filename     = filename or "pasted_email",
            sender       = parsed.get("sender", ""),
            recipient    = parsed.get("recipient", ""),
            subject      = parsed.get("subject", ""),
            body_text    = parsed.get("body_text", "")[:5000],  # truncate for DB
            body_html    = parsed.get("body_html", "")[:10000],
            headers_raw  = json.dumps(parsed.get("headers", {})),
            spf_result   = parsed.get("auth_results", {}).get("spf", "none"),
            dkim_result  = parsed.get("auth_results", {}).get("dkim", "none"),
            dmarc_result = parsed.get("auth_results", {}).get("dmarc", "none"),
            risk_score   = risk_score,
            label        = label
        )
        db.session.add(scan)
        db.session.flush()   # flush to get the auto-incremented scan.id

        # Save each extracted URL as a URLScan row linked to this email
        for url_data in parsed.get("urls", []):
            url_scan = URLScan(
                email_id       = scan.id,
                raw_url        = url_data.get("raw", "")[:2048],
                normalized_url = url_data.get("normalized", "")[:2048],
                domain         = url_data.get("domain", "")[:255],
            )
            db.session.add(url_scan)

        db.session.commit()
        return scan.id

    except Exception as e:
        logger.error(f"Database save error: {e}")
        db.session.rollback()
        return None