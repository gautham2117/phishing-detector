# email_parser.py
# Core email parsing engine — Phase 1.
# Handles .eml bytes, raw text strings, and file paths.

import re
import json
import email
import logging
import hashlib
from email import policy
from email.message import EmailMessage
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime

from bs4 import BeautifulSoup
from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns
# ─────────────────────────────────────────────────────────────────────────────

URL_PATTERN    = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
IP_URL_PATTERN = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clck.ru"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga",
    ".cf", ".pw", ".work", ".loan", ".click", ".link"
}

BRAND_KEYWORDS = [
    "paypal", "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "github", "dropbox",
    "bank", "secure", "account", "verify", "update", "login", "signin"
]

URGENCY_KEYWORDS = [
    "urgent", "verify now", "verify your", "account suspended",
    "action required", "immediate", "expire", "expires soon",
    "unusual activity", "unauthorized", "click here", "confirm identity",
    "update payment", "update your", "limited time", "act now",
    "security alert", "your account has been", "suspicious login",
    "we detected", "important notice", "final notice", "last chance"
]


# ─────────────────────────────────────────────────────────────────────────────
# Main parsing function
# ─────────────────────────────────────────────────────────────────────────────

def parse_email(source) -> dict:
    """
    Parse an email from .eml bytes, raw string, or file path.

    Args:
        source: bytes (.eml content) or str (raw email text or file path)

    Returns:
        Structured dict with all parsed fields.
    """
    msg = _parse_raw(source)
    if msg is None:
        return _error_result("Failed to parse email input")

    # Extract headers
    sender    = _clean_header(msg.get("From",     ""))
    recipient = _clean_header(msg.get("To",       ""))
    reply_to  = _clean_header(msg.get("Reply-To", ""))
    subject   = _clean_header(msg.get("Subject",  ""))
    date_raw  = _clean_header(msg.get("Date",     ""))
    message_id = _clean_header(msg.get("Message-ID", ""))

    headers_dict = _extract_all_headers(msg)
    auth_results = _extract_auth_results(headers_dict)
    body_text, body_html = _extract_body(msg)
    urls         = _extract_urls(body_text, body_html)
    attachments  = _extract_attachments(msg)
    anomalies    = _detect_anomalies(sender, reply_to, headers_dict, urls)

    classify_text = body_text.strip() if body_text.strip() else _strip_html(body_html)
    distilbert_result = _classify_with_distilbert(classify_text)

    return {
        "sender":            sender,
        "recipient":         recipient,
        "reply_to":          reply_to,
        "subject":           subject,
        "date":              date_raw,
        "message_id":        message_id,
        "headers":           headers_dict,
        "body_text":         body_text,
        "body_html":         body_html,
        "urls":              urls,
        "attachments":       attachments,
        "auth_results":      auth_results,
        "anomalies":         anomalies,
        "distilbert_result": distilbert_result,
        "parsed_at":         datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Raw input → EmailMessage
# ─────────────────────────────────────────────────────────────────────────────

def _parse_raw(source) -> Optional[EmailMessage]:
    """Convert bytes, string, or file path to an EmailMessage object."""
    try:
        if isinstance(source, bytes):
            return email.message_from_bytes(source, policy=policy.default)

        elif isinstance(source, str):
            # Check if it looks like a file path
            if len(source) < 300 and source.strip().endswith(".eml"):
                try:
                    with open(source.strip(), "rb") as f:
                        return email.message_from_bytes(
                            f.read(), policy=policy.default
                        )
                except (FileNotFoundError, OSError):
                    pass
            # Treat as raw email text
            return email.message_from_string(source, policy=policy.default)

        else:
            logger.error(f"Unsupported source type: {type(source)}")
            return None

    except Exception as e:
        logger.error(f"Email parse failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Header helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clean_header(value: str) -> str:
    """Decode and clean a single header value (handles UTF-8/Base64 encoding)."""
    if not value:
        return ""
    try:
        from email.header import decode_header, make_header
        decoded = str(make_header(decode_header(value)))
        return " ".join(decoded.split())
    except Exception:
        return str(value).strip()


def _extract_all_headers(msg: EmailMessage) -> dict:
    """Build a dict of all headers — multi-value headers stored as lists."""
    headers = {}
    for key, val in msg.items():
        clean_val = _clean_header(val)
        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(clean_val)
            else:
                headers[key] = [headers[key], clean_val]
        else:
            headers[key] = clean_val
    return headers


def _extract_auth_results(headers_dict: dict) -> dict:
    """Parse SPF, DKIM, DMARC results from the Authentication-Results header."""
    auth_header = headers_dict.get("Authentication-Results", "")
    if isinstance(auth_header, list):
        auth_header = " ".join(auth_header)

    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_header:
        return result

    auth_lower = auth_header.lower()
    for field in ("spf", "dkim", "dmarc"):
        match = re.search(rf'{field}=(\w+)', auth_lower)
        if match:
            result[field] = match.group(1)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Body extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_body(msg: EmailMessage) -> tuple:
    """Extract plain text and HTML body from a (possibly multipart) email."""
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get_content_disposition() or "")

            if "attachment" in disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")

                if content_type == "text/plain":
                    body_text += decoded
                elif content_type == "text/html":
                    body_html += decoded
            except Exception as e:
                logger.warning(f"Body part decode error ({content_type}): {e}")
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            content_type = msg.get_content_type()
            if payload:
                decoded = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    body_html = decoded
                else:
                    body_text = decoded
        except Exception as e:
            logger.warning(f"Single-part body decode error: {e}")

    return body_text, body_html


def _strip_html(html: str) -> str:
    """Remove HTML tags and return plain text."""
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "lxml")
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return re.sub(r'<[^>]+>', ' ', html)


# ─────────────────────────────────────────────────────────────────────────────
# URL extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_urls(body_text: str, body_html: str) -> list:
    """Extract all unique URLs from plain text and HTML body."""
    found_urls = set()

    for match in URL_PATTERN.finditer(body_text or ""):
        url = match.group(0).rstrip(".,;!?)")
        found_urls.add(url)

    if body_html:
        try:
            soup = BeautifulSoup(body_html, "lxml")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if href.startswith(("http://", "https://")):
                    found_urls.add(href.rstrip(".,;!?)'\""))
        except Exception as e:
            logger.warning(f"HTML URL extraction error: {e}")

    url_list = []
    for raw_url in found_urls:
        try:
            parsed       = urlparse(raw_url.lower())
            domain       = parsed.netloc
            domain_clean = domain.lstrip("www.")
            flags        = []

            if IP_URL_PATTERN.match(raw_url):
                flags.append("ip_address_in_url")

            tld = "." + domain_clean.split(".")[-1] if "." in domain_clean else ""
            if tld in SUSPICIOUS_TLDS:
                flags.append(f"suspicious_tld_{tld}")

            for brand in BRAND_KEYWORDS:
                if brand in domain_clean and not domain_clean.endswith(f"{brand}.com"):
                    flags.append(f"brand_keyword_{brand}")
                    break

            url_list.append({
                "raw":          raw_url,
                "normalized":   raw_url.lower(),
                "domain":       domain,
                "is_shortener": domain_clean in URL_SHORTENERS,
                "flags":        flags
            })
        except Exception as e:
            logger.warning(f"URL parse error for {raw_url}: {e}")

    return url_list


# ─────────────────────────────────────────────────────────────────────────────
# Attachment extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_attachments(msg: EmailMessage) -> list:
    """Collect metadata for all file attachments."""
    attachments = []

    for part in msg.walk():
        disposition = str(part.get_content_disposition() or "")
        if "attachment" not in disposition:
            continue

        filename = part.get_filename() or "unnamed_attachment"

        try:
            payload  = part.get_payload(decode=True)
            size     = len(payload) if payload else 0
            md5_hash = hashlib.md5(payload).hexdigest() if payload else ""

            attachments.append({
                "filename":     filename,
                "content_type": part.get_content_type(),
                "size_bytes":   size,
                "md5_hash":     md5_hash
            })
        except Exception as e:
            logger.warning(f"Attachment metadata error ({filename}): {e}")
            attachments.append({
                "filename":     filename,
                "content_type": part.get_content_type(),
                "size_bytes":   0,
                "md5_hash":     ""
            })

    return attachments


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_anomalies(
    sender:       str,
    reply_to:     str,
    headers_dict: dict,
    urls:         list
) -> list:
    """Detect suspicious header patterns."""
    anomalies = []

    # Check 1: Reply-To domain mismatch
    if reply_to and sender:
        from_domain    = _extract_domain_from_addr(sender)
        replyto_domain = _extract_domain_from_addr(reply_to)
        if from_domain and replyto_domain and from_domain != replyto_domain:
            anomalies.append({
                "type":        "reply_to_mismatch",
                "description": (
                    f"Reply-To domain ({replyto_domain}) differs "
                    f"from From domain ({from_domain})"
                ),
                "severity": "high"
            })

    # Check 2: Excessive relay hops
    received = headers_dict.get("Received", [])
    if isinstance(received, str):
        received = [received]
    if len(received) > 5:
        anomalies.append({
            "type":        "excessive_relay_hops",
            "description": f"Email passed through {len(received)} relay servers",
            "severity":    "medium"
        })

    # Check 3: Return-Path mismatch
    return_path = headers_dict.get("Return-Path", "")
    if isinstance(return_path, list):
        return_path = return_path[0] if return_path else ""
    if return_path and sender:
        from_domain = _extract_domain_from_addr(sender)
        rp_domain   = _extract_domain_from_addr(return_path)
        if from_domain and rp_domain and from_domain != rp_domain:
            anomalies.append({
                "type":        "return_path_mismatch",
                "description": (
                    f"Return-Path ({rp_domain}) doesn't match "
                    f"From ({from_domain})"
                ),
                "severity": "high"
            })

    # Check 4: Urgency keywords in subject
    subject = headers_dict.get("Subject", "")
    if isinstance(subject, list):
        subject = subject[0] if subject else ""
    subject_lower = (subject or "").lower()
    matched = [kw for kw in URGENCY_KEYWORDS if kw in subject_lower]
    if matched:
        anomalies.append({
            "type":        "urgent_subject_language",
            "description": f"Urgency keywords found: {matched[:3]}",
            "severity":    "medium"
        })

    # Check 5: IP addresses in URLs
    ip_url_count = sum(
        1 for u in urls if "ip_address_in_url" in u.get("flags", [])
    )
    if ip_url_count > 0:
        anomalies.append({
            "type":        "ip_address_in_url",
            "description": f"{ip_url_count} URL(s) use raw IP address",
            "severity":    "high"
        })

    return anomalies


def _extract_domain_from_addr(addr: str) -> Optional[str]:
    """Extract domain from an email address like 'Name <user@domain.com>'."""
    clean = re.sub(r'.*<(.+)>.*', r'\1', addr).strip()
    if "@" not in clean:
        clean = addr
    if "@" in clean:
        return clean.split("@")[-1].lower().strip(">")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DistilBERT classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_distilbert(text: str) -> dict:
    """Run the DistilBERT phishing classifier on email body text."""
    fallback = {
        "label": "UNKNOWN",
        "score": 0.0,
        "model": "fallback_rule_based"
    }

    if not text or len(text.strip()) < 10:
        return {**fallback, "note": "body_too_short"}

    model = get_model("email_classifier")
    if model is None:
        logger.warning("email_classifier not loaded — returning fallback")
        return fallback

    try:
        truncated  = text[:1500]
        results    = model(truncated)
        top        = results[0]
        raw_label  = top["label"].upper()

        if "PHISH" in raw_label or raw_label in ("LABEL_1", "1"):
            normalized = "PHISHING"
        elif (
            "SAFE" in raw_label or
            "LEGIT" in raw_label or
            raw_label in ("LABEL_0", "0")
        ):
            normalized = "SAFE"
        else:
            normalized = raw_label

        return {
            "label": normalized,
            "score": round(float(top["score"]), 4),
            "model": "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        }

    except Exception as e:
        logger.error(f"DistilBERT inference error: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Error result
# ─────────────────────────────────────────────────────────────────────────────

def _error_result(message: str) -> dict:
    return {
        "sender": "", "recipient": "", "reply_to": "", "subject": "",
        "date": "", "message_id": "", "headers": {},
        "body_text": "", "body_html": "", "urls": [], "attachments": [],
        "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "anomalies": [{
            "type":        "parse_error",
            "description": message,
            "severity":    "high"
        }],
        "distilbert_result": {
            "label": "UNKNOWN", "score": 0.0, "model": "none"
        },
        "parsed_at": datetime.utcnow().isoformat() + "Z",
        "error":     message
    }