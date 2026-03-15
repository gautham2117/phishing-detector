# email_parser.py
# Core email parsing engine.
#
# Responsibilities:
#   1. Accept .eml bytes, raw text string, or file path
#   2. Parse with Python's built-in email library
#   3. Extract every header, body variant, URL, and attachment
#   4. Run authentication checks (SPF/DKIM/DMARC from headers)
#   5. Detect header anomalies (spoofed sender, relay hops, reply-to mismatch)
#   6. Run DistilBERT classification on the body text
#   7. Return a structured ParsedEmail dict

import re
import json
import email
import logging
import hashlib
from email import policy
from email.message import EmailMessage
from typing import Optional
from urllib.parse import urlparse, unquote
from datetime import datetime

# BeautifulSoup parses the HTML body to extract URLs from <a href> tags
from bs4 import BeautifulSoup

# Our model registry
from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns compiled once at import time (faster than per-call compile)
# ─────────────────────────────────────────────────────────────────────────────

# Matches URLs in plain text bodies.
# Handles http/https/ftp with or without www, including query strings.
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Detects IP-literal URLs like http://192.168.1.1/login
IP_URL_PATTERN = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}'
)

# Known URL shortener domains — we'll flag these for redirect following
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clck.ru"
}

# Suspicious TLDs associated with free/throwaway domain registrations
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga",
    ".cf", ".pw", ".work", ".loan", ".click", ".link"
}

# Brand keywords that phishers commonly embed in fake domains
BRAND_KEYWORDS = [
    "paypal", "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "github", "dropbox",
    "bank", "secure", "account", "verify", "update", "login", "signin"
]


# ─────────────────────────────────────────────────────────────────────────────
# Main parsing function
# ─────────────────────────────────────────────────────────────────────────────

def parse_email(source) -> dict:
    """
    Parse an email from multiple input formats and return structured results.

    Args:
        source: One of:
            - bytes   (.eml file content read with open(f, 'rb').read())
            - str     (raw email text, or a file path ending in .eml)

    Returns:
        A dict matching the ParsedEmail schema with keys:
          sender, recipient, reply_to, subject, date,
          headers, body_text, body_html, urls, attachments,
          auth_results, anomalies, distilbert_result
    """

    # ── Step 1: Parse the raw email into a Python EmailMessage object ─────
    msg = _parse_raw(source)
    if msg is None:
        return _error_result("Failed to parse email input")

    # ── Step 2: Extract core header fields ────────────────────────────────
    sender    = _clean_header(msg.get("From", ""))
    recipient = _clean_header(msg.get("To", ""))
    reply_to  = _clean_header(msg.get("Reply-To", ""))
    subject   = _clean_header(msg.get("Subject", ""))
    date_raw  = _clean_header(msg.get("Date", ""))
    message_id = _clean_header(msg.get("Message-ID", ""))

    # Collect ALL headers as a dict (some headers appear multiple times,
    # e.g. Received headers — we store as list of values per key)
    headers_dict = _extract_all_headers(msg)

    # ── Step 3: Extract email authentication results ───────────────────────
    # SPF, DKIM, DMARC results are embedded in the Authentication-Results
    # header added by the receiving mail server.
    # Example: "Authentication-Results: mx.google.com; spf=pass; dkim=fail"
    auth_results = _extract_auth_results(headers_dict)

    # ── Step 4: Extract body (both plain text and HTML) ────────────────────
    body_text, body_html = _extract_body(msg)

    # ── Step 5: Extract all URLs from body and HTML ────────────────────────
    urls = _extract_urls(body_text, body_html)

    # ── Step 6: Extract attachments metadata ──────────────────────────────
    attachments = _extract_attachments(msg)

    # ── Step 7: Detect header anomalies ────────────────────────────────────
    anomalies = _detect_anomalies(
        sender=sender,
        reply_to=reply_to,
        headers_dict=headers_dict,
        urls=urls
    )

    # ── Step 8: Run DistilBERT classification on body text ─────────────────
    # We use body_text (plain text). If empty, fall back to stripped HTML text.
    classify_text = body_text.strip() if body_text.strip() else _strip_html(body_html)
    distilbert_result = _classify_with_distilbert(classify_text)

    return {
        "sender":           sender,
        "recipient":        recipient,
        "reply_to":         reply_to,
        "subject":          subject,
        "date":             date_raw,
        "message_id":       message_id,
        "headers":          headers_dict,
        "body_text":        body_text,
        "body_html":        body_html,
        "urls":             urls,
        "attachments":      attachments,
        "auth_results":     auth_results,
        "anomalies":        anomalies,
        "distilbert_result":distilbert_result,
        "parsed_at":        datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Raw input → EmailMessage
# ─────────────────────────────────────────────────────────────────────────────

def _parse_raw(source) -> Optional[EmailMessage]:
    """
    Convert raw input (bytes, string, or file path) into an EmailMessage.
    Returns None if parsing fails completely.
    """
    try:
        if isinstance(source, bytes):
            # .eml file loaded as bytes: email.message_from_bytes
            # policy.default gives us modern EmailMessage API
            return email.message_from_bytes(source, policy=policy.default)

        elif isinstance(source, str):
            if source.endswith(".eml") and len(source) < 300:
                # Looks like a file path — try to open it
                with open(source, "rb") as f:
                    return email.message_from_bytes(f.read(), policy=policy.default)
            else:
                # Treat as raw email text (pasted content)
                return email.message_from_string(source, policy=policy.default)
        else:
            logger.error(f"Unsupported email source type: {type(source)}")
            return None

    except Exception as e:
        logger.error(f"Email parse failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Header extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clean_header(value: str) -> str:
    """
    Decode and clean a single header value.
    Email headers can be encoded (=?UTF-8?B?...?= or =?UTF-8?Q?...?=).
    email.header.decode_header handles these encodings.
    """
    if not value:
        return ""

    # email.header.decode_header returns a list of (bytes_or_str, charset) pairs
    from email.header import decode_header, make_header
    try:
        decoded = str(make_header(decode_header(value)))
        # Remove extra whitespace and newlines sometimes present in folded headers
        return " ".join(decoded.split())
    except Exception:
        # If decoding fails, return the raw value stripped of whitespace
        return value.strip()


def _extract_all_headers(msg: EmailMessage) -> dict:
    """
    Build a dict of ALL headers from the email.
    Headers that appear multiple times (like Received) are stored as lists.

    Returns:
        {"From": "...", "Received": ["hop1", "hop2", ...], ...}
    """
    headers = {}
    for key, val in msg.items():
        clean_val = _clean_header(val)
        if key in headers:
            # Header already seen — convert to list or append
            if isinstance(headers[key], list):
                headers[key].append(clean_val)
            else:
                headers[key] = [headers[key], clean_val]
        else:
            headers[key] = clean_val
    return headers


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Authentication results (SPF / DKIM / DMARC)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_auth_results(headers_dict: dict) -> dict:
    """
    Parse the Authentication-Results header to extract SPF/DKIM/DMARC verdicts.

    Real email servers (Gmail, Outlook) add this header automatically.
    Test emails may not have it — we return "none" in that case.

    Example header:
        Authentication-Results: mx.google.com;
            dkim=pass header.i=@example.com;
            spf=pass smtp.mailfrom=example.com;
            dmarc=pass (p=NONE) header.from=example.com

    Returns:
        {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    """
    auth_header = headers_dict.get("Authentication-Results", "")

    # auth_header might be a list if there are multiple Authentication-Results headers
    if isinstance(auth_header, list):
        auth_header = " ".join(auth_header)

    result = {"spf": "none", "dkim": "none", "dmarc": "none"}

    if not auth_header:
        return result

    auth_lower = auth_header.lower()

    # Extract SPF result — looks for "spf=pass" or "spf=fail" etc.
    spf_match = re.search(r'spf=(\w+)', auth_lower)
    if spf_match:
        result["spf"] = spf_match.group(1)

    # Extract DKIM result
    dkim_match = re.search(r'dkim=(\w+)', auth_lower)
    if dkim_match:
        result["dkim"] = dkim_match.group(1)

    # Extract DMARC result
    dmarc_match = re.search(r'dmarc=(\w+)', auth_lower)
    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Body extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_body(msg: EmailMessage) -> tuple[str, str]:
    """
    Extract both the plain text and HTML versions of the email body.

    Multi-part emails (Content-Type: multipart/alternative) contain
    both text/plain and text/html parts. We extract both separately.
    Single-part emails just have one body.

    Returns:
        (body_text: str, body_html: str)
    """
    body_text = ""
    body_html  = ""

    if msg.is_multipart():
        # Walk ALL parts of the MIME tree
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get_content_disposition() or "")

            # Skip attachments — we handle those separately
            if "attachment" in disposition:
                continue

            try:
                # get_payload(decode=True) handles base64/quoted-printable decoding
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                # Detect charset — default to utf-8 if not specified
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")

                if content_type == "text/plain":
                    body_text += decoded
                elif content_type == "text/html":
                    body_html += decoded

            except Exception as e:
                logger.warning(f"Could not decode body part ({content_type}): {e}")

    else:
        # Single-part email
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
    """Remove all HTML tags and return plain text — used as fallback."""
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "lxml")
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        # Regex fallback if BeautifulSoup fails
        return re.sub(r'<[^>]+>', ' ', html)


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: URL extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_urls(body_text: str, body_html: str) -> list[dict]:
    """
    Extract all unique URLs from both plain text body and HTML body.
    For HTML, we parse <a href="..."> tags with BeautifulSoup.
    For plain text, we use the URL_PATTERN regex.

    For each URL we note:
      - raw: exactly as found
      - normalized: lowercase, stripped of tracking params
      - domain: the registered domain
      - is_shortener: whether it's a known URL shortener
      - flags: quick pre-flight flags (ip_url, suspicious_tld, brand_keyword)

    Returns:
        List of URL detail dicts. Duplicates are removed.
    """
    found_urls = set()   # Use a set for deduplication

    # ── Extract from plain text ──
    for match in URL_PATTERN.finditer(body_text or ""):
        url = match.group(0).rstrip(".,;!?)")  # strip trailing punctuation
        found_urls.add(url)

    # ── Extract from HTML <a href> tags ──
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "lxml")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                # Only include http/https URLs, not mailto:// etc.
                if href.startswith(("http://", "https://")):
                    found_urls.add(href.rstrip(".,;!?)'\""))
        except Exception as e:
            logger.warning(f"HTML URL extraction error: {e}")

    # ── Build structured URL objects ──
    url_list = []
    for raw_url in found_urls:
        try:
            parsed = urlparse(raw_url.lower())
            domain = parsed.netloc

            # Remove www. prefix for cleaner comparison
            domain_clean = domain.lstrip("www.")

            # Check for suspicious characteristics
            flags = []

            if IP_URL_PATTERN.match(raw_url):
                flags.append("ip_address_in_url")

            tld = "." + domain_clean.split(".")[-1] if "." in domain_clean else ""
            if tld in SUSPICIOUS_TLDS:
                flags.append(f"suspicious_tld_{tld}")

            for brand in BRAND_KEYWORDS:
                if brand in domain_clean and not domain_clean.endswith(f"{brand}.com"):
                    flags.append(f"brand_keyword_{brand}")
                    break  # One brand flag per URL is enough

            url_list.append({
                "raw":          raw_url,
                "normalized":   raw_url.lower(),
                "domain":       domain,
                "is_shortener": domain_clean in URL_SHORTENERS,
                "flags":        flags
            })
        except Exception as e:
            logger.warning(f"URL parse error for {raw_url}: {e}")
            continue

    return url_list


# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Attachment extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_attachments(msg: EmailMessage) -> list[dict]:
    """
    Walk the MIME tree and collect metadata about all attachments.
    We DO NOT save attachment bytes here — that's the job of Module 6
    (File & Attachment Analysis). Here we just record what's present.

    Returns:
        List of attachment metadata dicts:
          {filename, content_type, size_bytes, md5_hash}
    """
    attachments = []

    for part in msg.walk():
        disposition = str(part.get_content_disposition() or "")
        if "attachment" not in disposition:
            continue

        filename = part.get_filename() or "unnamed_attachment"

        try:
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            # Compute MD5 for quick hash lookup even at this early stage
            md5 = hashlib.md5(payload).hexdigest() if payload else ""

            attachments.append({
                "filename":     filename,
                "content_type": part.get_content_type(),
                "size_bytes":   size,
                "md5_hash":     md5
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
# Step 7: Header anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_anomalies(sender: str, reply_to: str,
                       headers_dict: dict, urls: list) -> list[dict]:
    """
    Apply heuristic checks to detect suspicious patterns in the email headers.

    Each anomaly is returned as:
      {"type": str, "description": str, "severity": "low"/"medium"/"high"}

    Checks performed:
      1. Reply-To domain differs from From domain (reply hijacking)
      2. Excessive Received hops (> 5 relay servers — unusual for legit email)
      3. From domain doesn't match Return-Path domain (spoofing signal)
      4. Mismatched X-Originating-IP vs From domain
      5. Subject contains urgent keywords (classic phishing pattern)
      6. Registration email from unknown/suspicious platform
    """
    anomalies = []

    # ── Check 1: Reply-To mismatch ────────────────────────────────────────
    # Legitimate emails: Reply-To domain == From domain
    # Phishing emails: Reply-To points to attacker's domain to capture replies
    if reply_to and sender:
        from_domain   = _extract_domain_from_addr(sender)
        replyto_domain = _extract_domain_from_addr(reply_to)

        if from_domain and replyto_domain and from_domain != replyto_domain:
            anomalies.append({
                "type":        "reply_to_mismatch",
                "description": f"Reply-To domain ({replyto_domain}) differs from From domain ({from_domain})",
                "severity":    "high"
            })

    # ── Check 2: Excessive relay hops ────────────────────────────────────
    # Each "Received:" header = one mail relay hop.
    # Legitimate email: 2–4 hops. More than 5 is suspicious.
    received_headers = headers_dict.get("Received", [])
    if isinstance(received_headers, str):
        received_headers = [received_headers]
    hop_count = len(received_headers)
    if hop_count > 5:
        anomalies.append({
            "type":        "excessive_relay_hops",
            "description": f"Email passed through {hop_count} relay servers (normal is 2–4)",
            "severity":    "medium"
        })

    # ── Check 3: From / Return-Path mismatch ─────────────────────────────
    # Return-Path is where bounces go — should match the From domain.
    return_path = headers_dict.get("Return-Path", "")
    if isinstance(return_path, list):
        return_path = return_path[0] if return_path else ""

    if return_path and sender:
        from_domain = _extract_domain_from_addr(sender)
        rp_domain   = _extract_domain_from_addr(return_path)
        if from_domain and rp_domain and from_domain != rp_domain:
            anomalies.append({
                "type":        "return_path_mismatch",
                "description": f"Return-Path ({rp_domain}) doesn't match From ({from_domain})",
                "severity":    "high"
            })

    # ── Check 4: Urgent/fear language in subject ─────────────────────────
    # Phishing emails frequently use urgency to pressure victims.
    urgent_keywords = [
        "urgent", "verify now", "account suspended", "action required",
        "immediate", "expire", "unusual activity", "unauthorized",
        "click here", "confirm identity", "update payment"
    ]
    subject = headers_dict.get("Subject", "")
    if isinstance(subject, list):
        subject = subject[0] if subject else ""
    subject_lower = (subject or "").lower()

    matched_urgent = [kw for kw in urgent_keywords if kw in subject_lower]
    if matched_urgent:
        anomalies.append({
            "type":        "urgent_subject_language",
            "description": f"Subject contains urgency keywords: {matched_urgent}",
            "severity":    "medium"
        })

    # ── Check 5: IP addresses in URLs (already flagged by URL extractor) ──
    ip_url_count = sum(1 for u in urls if "ip_address_in_url" in u.get("flags", []))
    if ip_url_count > 0:
        anomalies.append({
            "type":        "ip_address_in_url",
            "description": f"{ip_url_count} URL(s) use raw IP address instead of domain",
            "severity":    "high"
        })

    return anomalies


def _extract_domain_from_addr(addr: str) -> Optional[str]:
    """
    Extract the domain part from an email address or display name + address.
    Handles: "Display Name <user@domain.com>", "user@domain.com", "<user@domain.com>"

    Returns: "domain.com" or None if no @ found.
    """
    # Strip angle brackets and whitespace
    clean = re.sub(r'.*<(.+)>.*', r'\1', addr).strip()

    # If still no @, try the raw value
    if "@" not in clean:
        clean = addr

    if "@" in clean:
        return clean.split("@")[-1].lower().strip(">")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Step 8: DistilBERT classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_distilbert(text: str) -> dict:
    """
    Run the DistilBERT phishing email classifier on the email body.

    The model returns a label ("PHISHING" or "SAFE") with a confidence score.
    We normalize the label names to "PHISHING" / "SAFE" regardless of the
    specific label strings the model uses (some models use 0/1 or LABEL_0/LABEL_1).

    Args:
        text: The email body text to classify.

    Returns:
        {"label": "PHISHING"/"SAFE"/"UNKNOWN", "score": float, "model": str}
    """
    fallback = {"label": "UNKNOWN", "score": 0.0, "model": "fallback_rule_based"}

    if not text or len(text.strip()) < 10:
        # Too short to classify meaningfully
        return {**fallback, "note": "body_too_short_for_classification"}

    # Retrieve the model from the registry
    model = get_model("email_classifier")
    if model is None:
        logger.warning("email_classifier not loaded — returning fallback")
        return fallback

    try:
        # Truncate to 512 tokens (DistilBERT's max input length).
        # We take the first 1500 characters as a rough proxy for tokens.
        truncated_text = text[:1500]

        # Run inference. Returns: [{"label": "...", "score": 0.xx}]
        results = model(truncated_text)
        top = results[0]

        # Normalize label: different model versions may return different strings.
        # cybersectony model returns "PHISHING EMAIL" or "SAFE EMAIL"
        raw_label = top["label"].upper()
        if "PHISH" in raw_label or raw_label in ("LABEL_1", "1"):
            normalized_label = "PHISHING"
        elif "SAFE" in raw_label or "LEGIT" in raw_label or raw_label in ("LABEL_0", "0"):
            normalized_label = "SAFE"
        else:
            normalized_label = raw_label  # keep raw if unrecognized

        return {
            "label": normalized_label,
            "score": round(float(top["score"]), 4),
            "model": "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        }

    except Exception as e:
        logger.error(f"DistilBERT inference error: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _error_result(message: str) -> dict:
    """Return an empty ParsedEmail-shaped dict when parsing fails entirely."""
    return {
        "sender": "", "recipient": "", "reply_to": "", "subject": "",
        "date": "", "message_id": "", "headers": {},
        "body_text": "", "body_html": "", "urls": [], "attachments": [],
        "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "anomalies": [{"type": "parse_error", "description": message, "severity": "high"}],
        "distilbert_result": {"label": "UNKNOWN", "score": 0.0, "model": "none"},
        "parsed_at": datetime.utcnow().isoformat() + "Z",
        "error": message
    }