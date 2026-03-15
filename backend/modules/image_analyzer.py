"""
backend/modules/image_analyzer.py
Phase 7 — Image Analysis Engine
Performs OCR, brand detection, phishing keyword scanning,
and runs extracted text through the email phishing classifier.
"""

import io
import re
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional deps — graceful fallback if not installed ────────────────────────
try:
    from PIL import Image, UnidentifiedImageError
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract

    # Windows: set explicit path if tesseract is not on system PATH
    _tess_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(_tess_path):
        pytesseract.pytesseract.tesseract_cmd = _tess_path

    TESS_AVAILABLE = True
except ImportError:
    TESS_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

MAX_IMAGE_BYTES = 20 * 1024 * 1024      # 20 MB
ALLOWED_FORMATS = {"PNG", "JPEG", "JPG", "GIF", "BMP", "WEBP"}

# Brand name → display name mapping
# Key = lowercase token to search for in OCR text
KNOWN_BRANDS = {
    "paypal":         "PayPal",
    "google":         "Google",
    "microsoft":      "Microsoft",
    "apple":          "Apple",
    "amazon":         "Amazon",
    "netflix":        "Netflix",
    "facebook":       "Facebook",
    "instagram":      "Instagram",
    "twitter":        "Twitter",
    "linkedin":       "LinkedIn",
    "dropbox":        "Dropbox",
    "onedrive":       "OneDrive",
    "icloud":         "iCloud",
    "chase":          "Chase Bank",
    "wellsfargo":     "Wells Fargo",
    "citibank":       "Citibank",
    "bankofamerica":  "Bank of America",
    "gmail":          "Gmail",
    "outlook":        "Outlook",
    "yahoo":          "Yahoo",
    "adobe":          "Adobe",
    "docusign":       "DocuSign",
    "steam":          "Steam",
    "discord":        "Discord",
    "whatsapp":       "WhatsApp",
    "coinbase":       "Coinbase",
    "binance":        "Binance",
    "blockchain":     "Blockchain",
    "dhl":            "DHL",
    "fedex":          "FedEx",
    "ups":            "UPS",
    "usps":           "USPS",
    "irs":            "IRS",
}

# Phishing keyword patterns — matched case-insensitively
PHISHING_KEYWORDS = [
    "verify your account",
    "confirm your identity",
    "account suspended",
    "unusual activity",
    "unusual sign-in",
    "update your password",
    "update your information",
    "update your payment",
    "click here to verify",
    "click here to login",
    "enter your password",
    "enter your credit card",
    "social security",
    "your account has been",
    "limited time",
    "act now",
    "urgent action required",
    "important notice",
    "your account will be",
    "login now",
    "sign in to continue",
    "confirm now",
    "expires soon",
    "immediately",
    "locked",
    "suspended",
    "compromised",
    "unauthorized access",
    "security alert",
    "validate your",
    "reactivate your",
]

# Minimum OCR text length worth analysing
MIN_OCR_CHARS = 20


# ══════════════════════════════════════════════════════════════════════════════
# IMAGE LOADING & METADATA
# ══════════════════════════════════════════════════════════════════════════════

def load_image(file_bytes: bytes, filename: str) -> Optional[object]:
    """Load image bytes into a PIL Image object. Returns None on failure."""
    if not PIL_AVAILABLE:
        logger.warning("Pillow not installed — cannot load image.")
        return None
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.load()
        return img
    except Exception as ex:
        logger.warning("Image load failed for %s: %s", filename, ex)
        return None


def get_image_metadata(img) -> dict:
    """Extract basic image metadata from a PIL Image."""
    try:
        fmt = (img.format or "UNKNOWN").upper()
        return {
            "width":  img.width,
            "height": img.height,
            "format": fmt,
            "mode":   img.mode,
        }
    except Exception:
        return {"width": 0, "height": 0, "format": "UNKNOWN", "mode": ""}


# ══════════════════════════════════════════════════════════════════════════════
# OCR
# ══════════════════════════════════════════════════════════════════════════════

def run_ocr(img) -> str:
    """
    Extract text from a PIL Image using Tesseract.
    Returns empty string if Tesseract is unavailable or fails.
    """
    if not TESS_AVAILABLE:
        logger.warning("pytesseract not installed — OCR skipped.")
        return ""
    try:
        # Convert to RGB for consistent OCR results
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        text = pytesseract.image_to_string(img, config="--psm 3")
        return text.strip()
    except Exception as ex:
        logger.warning("OCR failed: %s", ex)
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# BRAND DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_brands(text: str) -> list:
    """
    Search OCR text for known brand names.
    Returns list of display names found.
    """
    if not text:
        return []
    text_lower = text.lower()
    found = []
    for token, display in KNOWN_BRANDS.items():
        if re.search(r"\b" + re.escape(token) + r"\b", text_lower):
            if display not in found:
                found.append(display)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# PHISHING KEYWORD SCAN
# ══════════════════════════════════════════════════════════════════════════════

def detect_phishing_keywords(text: str) -> list:
    """
    Scan OCR text for known phishing phrases.
    Returns list of matched keyword strings.
    """
    if not text:
        return []
    text_lower = text.lower()
    found = []
    for kw in PHISHING_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# ML CLASSIFIER (email_classifier model)
# ══════════════════════════════════════════════════════════════════════════════

def run_classifier(text: str) -> dict:
    """
    Run the email phishing classifier (DistilBERT) on extracted OCR text.
    Returns {"label": str, "score": float} or fallback on error.
    """
    if not text or len(text.strip()) < MIN_OCR_CHARS:
        return {"label": "UNKNOWN", "score": 0.0}

    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("email_classifier")
        if pipeline is None:
            return {"label": "UNKNOWN", "score": 0.0}

        output = pipeline(text[:512], truncation=True, max_length=512)

        if isinstance(output, list):
            output = output[0]

        label = output.get("label", "UNKNOWN").upper()
        score = float(output.get("score", 0.0))

        # Normalise label → PHISHING or SAFE
        if any(kw in label for kw in ("PHISH", "SPAM", "MALICIOUS", "FAKE")):
            return {"label": "PHISHING", "score": score}
        elif any(kw in label for kw in ("SAFE", "LEGITIMATE", "BENIGN", "REAL")):
            return {"label": "SAFE", "score": score}
        else:
            return {"label": label, "score": score}

    except Exception as ex:
        logger.warning("Classifier failed on OCR text: %s", ex)
        return {"label": "UNKNOWN", "score": 0.0}


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _compute_risk_score(
    classifier_result: dict,
    brands: list,
    keywords: list,
    ocr_text: str,
) -> float:
    score = 5.0

    # ML classifier signal
    clf_label = classifier_result.get("label", "UNKNOWN")
    clf_score = classifier_result.get("score", 0.0)

    if clf_label == "PHISHING":
        score += clf_score * 50.0
    elif clf_label == "SAFE":
        score += (1.0 - clf_score) * 5.0

    # Brand spoofing: brands detected in image content → phishing risk
    score += min(len(brands) * 12.0, 24.0)

    # Phishing keywords
    score += min(len(keywords) * 8.0, 32.0)

    # URL patterns in OCR text (http links in screenshots)
    url_hits = len(re.findall(r"https?://", ocr_text, re.IGNORECASE))
    score += min(url_hits * 3.0, 12.0)

    return min(round(score, 1), 100.0)


def _determine_verdict(score: float) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "CLEAN"


def _build_explanation(
    verdict: str,
    score: float,
    brands: list,
    keywords: list,
    classifier_result: dict,
    ocr_available: bool,
) -> str:
    parts = []

    if not ocr_available:
        parts.append(
            "OCR is not available — install pytesseract and Tesseract "
            "for full text extraction."
        )

    clf_label = classifier_result.get("label", "UNKNOWN")
    clf_pct   = int(classifier_result.get("score", 0.0) * 100)
    if clf_label == "PHISHING":
        parts.append(
            f"Phishing classifier flagged extracted text "
            f"({clf_pct}% confidence)."
        )

    if brands:
        parts.append(
            f"Brand name(s) detected in image: {', '.join(brands)} — "
            f"possible spoofing attempt."
        )

    if keywords:
        parts.append(
            f"{len(keywords)} phishing keyword(s) found in image text."
        )

    if not parts:
        parts.append(
            f"No significant phishing indicators found in image "
            f"(risk score: {score}/100)."
        )

    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze_image(file_bytes: bytes, filename: str) -> dict:
    """
    Main entry point called by the FastAPI endpoint.
    Returns a flat dict compatible with the standard module_results schema.
    """
    result = {
        "filename":          filename,
        "file_size":         len(file_bytes),
        "image_width":       0,
        "image_height":      0,
        "image_format":      "",
        "ocr_text":          "",
        "ocr_word_count":    0,
        "detected_brands":   [],
        "phishing_keywords": [],
        "classifier_result": {"label": "UNKNOWN", "score": 0.0},
        "risk_score":        5.0,
        "verdict":           "CLEAN",
        "explanation":       "",
        "error":             None,
        "ocr_available":     TESS_AVAILABLE and PIL_AVAILABLE,
    }

    # ── Size guard ──
    if len(file_bytes) > MAX_IMAGE_BYTES:
        result["error"] = "File too large (max 20 MB)."
        result["explanation"] = result["error"]
        return result

    # ── Load image ──
    if not PIL_AVAILABLE:
        result["error"] = "Pillow not installed — cannot process image."
        result["explanation"] = result["error"]
        return result

    img = load_image(file_bytes, filename)
    if img is None:
        result["error"] = "Could not open image — unsupported format or corrupt file."
        result["explanation"] = result["error"]
        return result

    # ── Metadata ──
    meta = get_image_metadata(img)
    result["image_width"]  = meta["width"]
    result["image_height"] = meta["height"]
    result["image_format"] = meta["format"]

    # ── OCR ──
    ocr_text = run_ocr(img)
    result["ocr_text"]       = ocr_text
    result["ocr_word_count"] = len(ocr_text.split()) if ocr_text else 0

    # ── Brand detection ──
    result["detected_brands"]   = detect_brands(ocr_text)

    # ── Phishing keyword scan ──
    result["phishing_keywords"] = detect_phishing_keywords(ocr_text)

    # ── ML classifier ──
    result["classifier_result"] = run_classifier(ocr_text)

    # ── Risk score + verdict ──
    result["risk_score"] = _compute_risk_score(
        result["classifier_result"],
        result["detected_brands"],
        result["phishing_keywords"],
        ocr_text,
    )
    result["verdict"] = _determine_verdict(result["risk_score"])

    # ── Explanation ──
    result["explanation"] = _build_explanation(
        result["verdict"],
        result["risk_score"],
        result["detected_brands"],
        result["phishing_keywords"],
        result["classifier_result"],
        result["ocr_available"],
    )

    return result