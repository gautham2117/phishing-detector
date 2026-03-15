# schemas.py
# Pydantic request and response models for the FastAPI detection API.
#
# Why Pydantic?
#   - Automatic input validation (wrong type → clear error message)
#   - Automatic Swagger UI documentation (visit /docs to see these)
#   - Serialization: converts Python objects to JSON-safe dicts

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Request models — what the client sends TO the API
# ─────────────────────────────────────────────────────────────────────────────

class EmailScanRequest(BaseModel):
    """
    Request body for POST /api/scan/email (raw text input).
    Used when the user pastes raw email text instead of uploading a file.
    """
    raw_email: str = Field(
        ...,
        min_length=20,
        description="Raw email text (paste the full email including headers)"
    )
    submitter: Optional[str] = Field(
        default="anonymous",
        description="Username of the analyst submitting this scan"
    )

    @field_validator("raw_email")
    @classmethod
    def must_look_like_email(cls, v: str) -> str:
        """Basic check: raw email must contain at least one header-like line."""
        if ":" not in v[:500]:
            raise ValueError("Input doesn't appear to be a valid email (no headers found)")
        return v


class URLScanRequest(BaseModel):
    """Request body for POST /api/scan/url"""
    url: str = Field(..., min_length=4, description="URL to analyze")
    submitter: Optional[str] = Field(default="anonymous")


class SMSScanRequest(BaseModel):
    """Request body for POST /api/scan/sms"""
    message: str = Field(..., min_length=1, max_length=2000, description="SMS text to scan")
    submitter: Optional[str] = Field(default="anonymous")


# ─────────────────────────────────────────────────────────────────────────────
# Response models — what the API sends BACK to the client
# These must match the build_response() schema from utils/response.py
# ─────────────────────────────────────────────────────────────────────────────

class AuthResultSchema(BaseModel):
    spf:   str = "none"
    dkim:  str = "none"
    dmarc: str = "none"


class AnomalySchema(BaseModel):
    type:        str
    description: str
    severity:    str = "medium"


class URLFlagSchema(BaseModel):
    raw:          str
    normalized:   str
    domain:       str
    is_shortener: bool = False
    flags:        list[str] = []


class AttachmentSchema(BaseModel):
    filename:     str
    content_type: str
    size_bytes:   int = 0
    md5_hash:     str = ""


class DistilBERTResultSchema(BaseModel):
    label: str     # "PHISHING", "SAFE", or "UNKNOWN"
    score: float   # 0.0 – 1.0
    model: str


class EmailScanResponse(BaseModel):
    """
    Full response returned after scanning an email.
    This is the standard response envelope + email-specific module_results.
    """
    status:             str
    risk_score:         float       # 0.0 – 100.0 (Phase 1 only uses DistilBERT score)
    label:              str         # "SAFE" / "SUSPICIOUS" / "MALICIOUS"
    recommended_action: str         # "ALLOW" / "WARN" / "QUARANTINE" / "BLOCK"
    explanation:        str
    timestamp:          str

    # Email-specific results nested inside module_results
    module_results: dict            # contains "email_parser" key with full parsed data

    # Database record ID for linking to other modules
    scan_id: Optional[int] = None