"""
backend/modules/image_analyzer.py
Phase 7 — Image Analysis Engine  (FIXED + EXTENDED)

FIXES IN THIS VERSION:
  1. "UNKNOWN" / "LABEL_1" classifier label normalisation
  2. Verdict threshold fixed to >= 30 for SUSPICIOUS
  3. OCR preprocessing with grayscale + adaptive threshold
  4. _compute_risk_score incorporates all signal weights
  5. explanation returns structured dict

NEW IN THIS VERSION:
  6. QR Code detector
  7. Steganography detection
  8. Face / logo brand detection
  9. EXIF metadata extractor

PHASE 7 ADDITIONS (this version):
 10. _describe_with_gemini() — calls Gemini 1.5 Pro vision API to produce
     a natural-language description of the image content (what is actually
     depicted: people, objects, scene, text visible, layout, etc.).
     Reads GEMINI_API_KEY from environment first, falls back to Flask config.
     Result stored as "gemini_description" dict in analyze_image() return.
     Degrades gracefully if key is missing or API call fails.

 11. _run_ela_analysis() — Error Level Analysis for JPEG manipulation
     detection. Re-saves the image at quality=90, computes pixel-level
     absolute difference, scales by 10x, computes mean/max/std statistics.
     is_potentially_manipulated=True when mean_ela > 8.0 OR std_ela > 15.0.
     Returns base64-encoded PNG of the difference image for UI display.
     Only runs on JPEG images; returns available=False for other formats.
     Adds up to 10 points to risk score when manipulation is suspected.
"""

from inspect import _empty
import io
import re
import os
import math
import base64
import logging
import datetime
import requests as _requests
from typing import Optional
import time

logger = logging.getLogger(__name__)

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    from PIL import Image, UnidentifiedImageError, ExifTags, ImageChops, ImageEnhance
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    _tess_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(_tess_path):
        pytesseract.pytesseract.tesseract_cmd = _tess_path
    TESS_AVAILABLE = True
except ImportError:
    TESS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except (ImportError, OSError):
    PYZBAR_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

MAX_IMAGE_BYTES     = 20 * 1024 * 1024
ALLOWED_FORMATS     = {"PNG", "JPEG", "JPG", "GIF", "BMP", "WEBP"}
MIN_OCR_CHARS       = 20
STEGO_ENTROPY_HIGH  = 0.98
STEGO_CHISQ_UNIFORM = 0.45

# ELA thresholds
ELA_QUALITY         = 90     # JPEG re-save quality for ELA
ELA_SCALE           = 10     # pixel difference amplification factor
ELA_MEAN_THRESHOLD  = 8.0    # mean ELA above this → suspicious
ELA_STD_THRESHOLD   = 15.0   # std  ELA above this → suspicious

# Gemini API
GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)
KNOWN_BRANDS = {
    "paypal": "PayPal", "google": "Google", "microsoft": "Microsoft",
    "apple": "Apple", "amazon": "Amazon", "netflix": "Netflix",
    "facebook": "Facebook", "instagram": "Instagram", "twitter": "Twitter",
    "linkedin": "LinkedIn", "dropbox": "Dropbox", "onedrive": "OneDrive",
    "icloud": "iCloud", "chase": "Chase Bank", "wellsfargo": "Wells Fargo",
    "citibank": "Citibank", "bankofamerica": "Bank of America",
    "gmail": "Gmail", "outlook": "Outlook", "yahoo": "Yahoo",
    "adobe": "Adobe", "docusign": "DocuSign", "steam": "Steam",
    "discord": "Discord", "whatsapp": "WhatsApp", "coinbase": "Coinbase",
    "binance": "Binance", "blockchain": "Blockchain",
    "dhl": "DHL", "fedex": "FedEx", "ups": "UPS", "usps": "USPS", "irs": "IRS",
}

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "account suspended",
    "unusual activity", "unusual sign-in", "update your password",
    "update your information", "update your payment", "click here to verify",
    "click here to login", "enter your password", "enter your credit card",
    "social security", "your account has been", "limited time", "act now",
    "urgent action required", "important notice", "your account will be",
    "login now", "sign in to continue", "confirm now", "expires soon",
    "immediately", "locked", "suspended", "compromised", "unauthorized access",
    "security alert", "validate your", "reactivate your",
]


# ══════════════════════════════════════════════════════════════════════════════
# GEMINI VISION DESCRIPTION  ← Phase 7 NEW
# ══════════════════════════════════════════════════════════════════════════════

def _get_gemini_api_key() -> str:
    """
    Read Gemini API key: check GEMINI_API_KEY env var first,
    then fall back to Flask app config GEMINI_API_KEY.
    Returns empty string if neither is set.
    """
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return key
    try:
        from flask import current_app
        key = current_app.config.get("GEMINI_API_KEY", "").strip()
    except RuntimeError:
        pass
    return key


def _describe_with_gemini(file_bytes: bytes, filename: str) -> dict:
    """
    Call the Gemini 1.5 Pro vision API to generate a natural-language
    description of the image content.

    The prompt asks Gemini to describe:
      - What is actually depicted (people, objects, scene, activities)
      - Any visible text in the image (signs, labels, UI elements)
      - The overall layout / composition
      - Any security-relevant observations (login forms, brand logos,
        urgency language, phishing indicators visible in the image)

    Returns:
        {
          "available":    bool,
          "description":  str,    natural language description
          "model":        str,    "gemini-1.5-pro"
          "error":        str | None
        }

    Never raises — all failures are caught and returned in "error".
    """
    for attempt in range(3):
        resp = _requests.post(
            GEMINI_API_URL,
            params={"key": api_key},
            json=payload,
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 429:
            if attempt < 2:
                time.sleep(20 * (attempt + 1))  # 20s, 40s
                continue
            result = dict(_empty)
            result["error"] = (
                "Rate limit exceeded (429). Free tier allows 1500 req/day "
                "for gemini-2.0-flash. Try again in a minute."
            )
            return result
        break
    _empty = {
        "available":   False,
        "description": "",
        "model": "gemini-2.0-flash",
        "error":       None,
    }

    api_key = _get_gemini_api_key()
    if not api_key:
        result = dict(_empty)
        result["error"] = (
            "GEMINI_API_KEY not configured. Set it as an environment variable "
            "or in Flask app config to enable AI image description."
        )
        return result

    if not PIL_AVAILABLE:
        result = dict(_empty)
        result["error"] = "Pillow not available — cannot prepare image for Gemini."
        return result

    # Encode image as base64 for the Gemini API
    try:
        img = Image.open(io.BytesIO(file_bytes))
        fmt = (img.format or "JPEG").upper()

        # Resize very large images to reduce API payload (max 2048px on longest side)
        max_dim = 2048
        if max(img.width, img.height) > max_dim:
            ratio = max_dim / max(img.width, img.height)
            new_size = (int(img.width * ratio), int(img.height * ratio))
            img = img.resize(new_size, Image.LANCZOS)

        buf = io.BytesIO()
        save_fmt = "JPEG" if fmt in ("JPEG", "JPG") else "PNG"
        mime_type = "image/jpeg" if save_fmt == "JPEG" else "image/png"
        img.save(buf, format=save_fmt, quality=85)
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    except Exception as e:
        result = dict(_empty)
        result["error"] = f"Image preparation failed: {str(e)[:120]}"
        return result

    # Build Gemini API request
    prompt = (
        "Analyse this image and provide a detailed description covering:\n"
        "1. What is depicted — people, objects, scene, activities, environment\n"
        "2. Any visible text, UI elements, forms, buttons, or labels\n"
        "3. Brand logos, company names, or identity elements visible\n"
        "4. The overall layout and composition\n"
        "5. Any security-relevant observations — login forms, credential fields, "
        "urgency language, phishing indicators, suspicious URLs or QR codes visible\n\n"
        "Write in clear, concise prose. Be specific about what you see. "
        "If this appears to be a phishing screenshot or fake login page, say so explicitly."
    )

    payload = {
        "contents": [{
            "parts": [
                {"text": prompt},
                {
                    "inline_data": {
                        "mime_type": mime_type,
                        "data":      img_b64,
                    }
                }
            ]
        }],
        "generationConfig": {
            "temperature":     0.2,
            "maxOutputTokens": 600,
            "topP":            0.8,
        },
    }

    try:
        resp = _requests.post(
            GEMINI_API_URL,
            params={"key": api_key},
            json=payload,
            timeout=30,
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code != 200:
            result = dict(_empty)
            result["error"] = (
                f"Gemini API returned HTTP {resp.status_code}: "
                f"{resp.text[:200]}"
            )
            return result

        data        = resp.json()
        candidates  = data.get("candidates", [])
        if not candidates:
            result = dict(_empty)
            result["error"] = "Gemini returned no candidates."
            return result

        content = candidates[0].get("content", {})
        parts   = content.get("parts", [])
        text    = " ".join(p.get("text", "") for p in parts).strip()

        if not text:
            result = dict(_empty)
            result["error"] = "Gemini returned an empty description."
            return result

        return {
            "available":   True,
            "description": text,
            "model": "gemini-2.0-flash",
            "error":       None,
        }

    except _requests.exceptions.Timeout:
        result = dict(_empty)
        result["error"] = "Gemini API request timed out (>30s)."
        return result
    except Exception as e:
        result = dict(_empty)
        result["error"] = f"Gemini API error: {str(e)[:200]}"
        return result


# ══════════════════════════════════════════════════════════════════════════════
# ERROR LEVEL ANALYSIS (ELA)  ← Phase 7 NEW
# ══════════════════════════════════════════════════════════════════════════════

def _run_ela_analysis(img, file_bytes: bytes) -> dict:
    """
    Perform Error Level Analysis (ELA) to detect potential image manipulation.

    Algorithm:
      1. Re-save the image as JPEG at quality=90 using PIL.
      2. Compute the absolute pixel-level difference between the original
         and the re-saved version (using ImageChops.difference).
      3. Scale the difference image by ELA_SCALE (10×) for visibility.
      4. Compute statistics: mean, max, std of the scaled difference.
      5. High ELA values in localised regions suggest manipulation —
         copy-pasted or added elements re-compress differently from
         the surrounding content.

    Only runs on JPEG images (image_format in ("JPEG", "JPG")).
    Returns available=False for other formats with an explanation.

    Returns:
        {
          "available":               bool,
          "mean_ela":                float,
          "max_ela":                 float,
          "std_ela":                 float,
          "is_potentially_manipulated": bool,
          "ela_image_b64":           str,   base64 PNG of scaled diff image
          "explanation":             str,
          "error":                   str | None
        }
    """
    _empty = {
        "available":                  False,
        "mean_ela":                   0.0,
        "max_ela":                    0.0,
        "std_ela":                    0.0,
        "is_potentially_manipulated": False,
        "ela_image_b64":              "",
        "explanation":                "",
        "error":                      None,
    }

    if not PIL_AVAILABLE:
        result = dict(_empty)
        result["explanation"] = "Pillow not available — ELA skipped."
        return result

    # Only JPEG
    img_format = (img.format or "").upper()
    if img_format not in ("JPEG", "JPG"):
        result = dict(_empty)
        result["explanation"] = (
            f"Error Level Analysis only applies to JPEG images. "
            f"This image is {img_format or 'an unsupported format'}. "
            f"ELA exploits JPEG's lossy compression artefacts — "
            f"re-saving a JPEG at a fixed quality level reveals regions "
            f"that were edited (they compress differently from untouched areas)."
        )
        return result

    try:
        # Ensure RGB mode for consistent processing
        original = img.convert("RGB")

        # Re-save at quality=90 to a buffer, then reload
        resaved_buf = io.BytesIO()
        original.save(resaved_buf, format="JPEG", quality=ELA_QUALITY)
        resaved_buf.seek(0)
        resaved = Image.open(resaved_buf).convert("RGB")

        # Compute absolute difference
        diff = ImageChops.difference(original, resaved)

        # Scale difference for visibility
        if NUMPY_AVAILABLE:
            diff_arr    = np.array(diff, dtype=np.float32)
            scaled_arr  = np.clip(diff_arr * ELA_SCALE, 0, 255).astype(np.uint8)
            scaled_img  = Image.fromarray(scaled_arr, mode="RGB")

            mean_ela = float(diff_arr.mean())
            max_ela  = float(diff_arr.max())
            std_ela  = float(diff_arr.std())
        else:
            # Pillow-only fallback: use ImageEnhance for scaling
            enhancer   = ImageEnhance.Brightness(diff)
            scaled_img = enhancer.enhance(ELA_SCALE)

            # Compute stats via histogram
            hist = diff.histogram()
            total_pixels = sum(hist)
            if total_pixels > 0:
                mean_ela = sum(i * hist[i] for i in range(len(hist))) / total_pixels
                max_ela  = max(i for i in range(len(hist) - 1, -1, -1) if hist[i] > 0)
                variance = sum(hist[i] * (i - mean_ela) ** 2 for i in range(len(hist))) / total_pixels
                std_ela  = math.sqrt(variance)
            else:
                mean_ela = max_ela = std_ela = 0.0

        # Encode scaled diff image to base64 PNG
        ela_buf = io.BytesIO()
        scaled_img.save(ela_buf, format="PNG")
        ela_b64 = base64.b64encode(ela_buf.getvalue()).decode("utf-8")

        is_manipulated = mean_ela > ELA_MEAN_THRESHOLD or std_ela > ELA_STD_THRESHOLD

        if is_manipulated:
            explanation = (
                f"ELA detected potential image manipulation. "
                f"Mean error level: {mean_ela:.2f} (threshold: {ELA_MEAN_THRESHOLD}), "
                f"standard deviation: {std_ela:.2f} (threshold: {ELA_STD_THRESHOLD}). "
                f"Regions with high error levels (bright areas in the ELA visualisation) "
                f"compress differently from the surrounding content, suggesting they may "
                f"have been inserted or modified after the original image was created. "
                f"This is a common technique in forged phishing screenshots."
            )
        else:
            explanation = (
                f"ELA found no strong evidence of manipulation. "
                f"Mean error level: {mean_ela:.2f}, std: {std_ela:.2f}. "
                f"The error level distribution appears relatively uniform, "
                f"which is consistent with an unmodified JPEG image."
            )

        return {
            "available":                  True,
            "mean_ela":                   round(mean_ela, 4),
            "max_ela":                    round(max_ela,  4),
            "std_ela":                    round(std_ela,  4),
            "is_potentially_manipulated": is_manipulated,
            "ela_image_b64":              ela_b64,
            "explanation":                explanation,
            "error":                      None,
        }

    except Exception as e:
        logger.error("ELA analysis failed for image: %s", e)
        result = dict(_empty)
        result["error"]       = f"ELA failed: {str(e)[:150]}"
        result["explanation"] = f"Error Level Analysis could not be completed: {str(e)[:100]}"
        return result


# ══════════════════════════════════════════════════════════════════════════════
# IMAGE LOADING & METADATA
# ══════════════════════════════════════════════════════════════════════════════

def load_image(file_bytes: bytes, filename: str) -> Optional[object]:
    if not PIL_AVAILABLE:
        return None
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.load()
        return img
    except Exception as ex:
        logger.warning("Image load failed for %s: %s", filename, ex)
        return None


def get_image_metadata(img) -> dict:
    try:
        fmt = (img.format or "UNKNOWN").upper()
        return {"width": img.width, "height": img.height, "format": fmt, "mode": img.mode}
    except Exception:
        return {"width": 0, "height": 0, "format": "UNKNOWN", "mode": ""}


# ══════════════════════════════════════════════════════════════════════════════
# OCR
# ══════════════════════════════════════════════════════════════════════════════

def _preprocess_for_ocr(img):
    if CV2_AVAILABLE and NUMPY_AVAILABLE:
        try:
            arr    = np.array(img.convert("RGB"))
            gray   = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
            thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, blockSize=31, C=10,
            )
            return Image.fromarray(thresh)
        except Exception:
            pass
    try:
        return img.convert("L")
    except Exception:
        return img


def run_ocr(img) -> str:
    if not TESS_AVAILABLE:
        return ""
    try:
        processed = _preprocess_for_ocr(img)
        text = pytesseract.image_to_string(processed, config="--psm 3 --oem 3")
        return text.strip()
    except Exception as ex:
        logger.warning("OCR failed: %s", ex)
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# BRAND & KEYWORD DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_brands(text: str) -> list:
    if not text:
        return []
    text_lower = text.lower()
    return [
        display for token, display in KNOWN_BRANDS.items()
        if re.search(r"\b" + re.escape(token) + r"\b", text_lower)
    ]


def detect_phishing_keywords(text: str) -> list:
    if not text:
        return []
    text_lower = text.lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in text_lower]


# ══════════════════════════════════════════════════════════════════════════════
# QR CODE DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

def detect_qr_codes(img) -> dict:
    result = {
        "available": PYZBAR_AVAILABLE, "codes": [], "url_count": 0,
        "malicious_urls": [], "suspicious_urls": [], "risk_contribution": 0.0,
    }
    if not PYZBAR_AVAILABLE or not PIL_AVAILABLE:
        return result
    try:
        scan_img = img.convert("RGB") if img.mode != "RGB" else img
        symbols  = pyzbar.decode(scan_img)
    except Exception as ex:
        result["error"] = str(ex)
        return result

    risk = 0.0
    for sym in symbols:
        try:
            raw_data = sym.data.decode("utf-8", errors="replace").strip()
        except Exception:
            raw_data = ""
        is_url     = bool(re.match(r"https?://", raw_data, re.IGNORECASE))
        code_entry = {"type": sym.type, "data": raw_data, "is_url": is_url,
                      "url_label": None, "url_score": None}
        if is_url:
            result["url_count"] += 1
            try:
                from backend.modules.url_intelligence import _classify_url_with_bert
                ml    = _classify_url_with_bert(raw_data)
                label = ml.get("label", "UNKNOWN")
                score = float(ml.get("score", 0.0))
                code_entry["url_label"] = label
                code_entry["url_score"] = round(score, 4)
                if label == "MALICIOUS" and score > 0.5:
                    result["malicious_urls"].append(raw_data)
                    risk += 15.0
                elif label == "MALICIOUS" or score > 0.3:
                    result["suspicious_urls"].append(raw_data)
                    risk += 7.0
            except Exception as ex:
                logger.warning("QR URL scoring failed: %s", ex)
        result["codes"].append(code_entry)
    result["risk_contribution"] = round(min(risk, 20.0), 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# STEGANOGRAPHY DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_steganography(img) -> dict:
    result = {
        "available": NUMPY_AVAILABLE and PIL_AVAILABLE,
        "lsb_entropy": {}, "chi_scores": {}, "suspicious": False,
        "confidence": "low", "flags": [], "risk_contribution": 0.0,
    }
    if not NUMPY_AVAILABLE or not PIL_AVAILABLE:
        return result
    try:
        arr = np.array(img.convert("RGB"), dtype=np.uint8)
    except Exception as ex:
        result["error"] = str(ex)
        return result

    suspicious_channels = 0
    risk = 0.0
    for i, ch_name in enumerate(["R", "G", "B"]):
        channel  = arr[:, :, i].flatten()
        lsb_bits = channel & 1
        ones     = int(np.sum(lsb_bits))
        total    = len(lsb_bits)
        p1       = ones / total if total > 0 else 0.5
        p0       = 1.0 - p1
        entropy  = 0.0
        if p1 > 0: entropy -= p1 * math.log2(p1)
        if p0 > 0: entropy -= p0 * math.log2(p0)
        result["lsb_entropy"][ch_name] = round(entropy, 6)

        pairs     = channel.reshape(-1, 2) if len(channel) % 2 == 0 else channel[:-1].reshape(-1, 2)
        even_vals = pairs[:, 0] & 0xFE
        odd_vals  = pairs[:, 0] | 0x01
        ec        = np.bincount(even_vals, minlength=256).astype(float)
        oc        = np.bincount(odd_vals,  minlength=256).astype(float)
        expected  = (ec + oc) / 2.0
        nonzero   = expected > 0
        chi_raw   = float(np.sum(((ec[nonzero] - expected[nonzero]) ** 2) / expected[nonzero]))
        n         = int(nonzero.sum())
        chi_score = 1.0 - (chi_raw / (chi_raw + n)) if n > 0 else 0.0
        result["chi_scores"][ch_name] = round(chi_score, 6)

        ch_sus = False
        if entropy > STEGO_ENTROPY_HIGH:
            result["flags"].append(f"High LSB entropy on {ch_name} ({entropy:.4f})")
            ch_sus = True
        if chi_score > STEGO_CHISQ_UNIFORM:
            result["flags"].append(f"Near-uniform LSB on {ch_name} (chi={chi_score:.4f})")
            ch_sus = True
        if ch_sus:
            suspicious_channels += 1

    if suspicious_channels >= 2:
        result["suspicious"] = True
        result["confidence"] = "high" if suspicious_channels == 3 else "medium"
        risk = 12.0 if suspicious_channels == 3 else 7.0
    elif suspicious_channels == 1:
        result["suspicious"] = True
        result["confidence"] = "low"
        risk = 3.0
    result["risk_contribution"] = round(risk, 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# FACE & LOGO DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_faces_and_logos(img) -> dict:
    result = {
        "available": CV2_AVAILABLE and NUMPY_AVAILABLE and PIL_AVAILABLE,
        "face_count": 0, "faces": [], "logo_regions": [], "risk_contribution": 0.0,
    }
    if not CV2_AVAILABLE or not NUMPY_AVAILABLE or not PIL_AVAILABLE:
        return result
    try:
        arr  = np.array(img.convert("RGB"))
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
    except Exception as ex:
        result["error"] = str(ex)
        return result

    try:
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        if os.path.exists(cascade_path):
            face_cascade = cv2.CascadeClassifier(cascade_path)
            faces = face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5,
                minSize=(30, 30), flags=cv2.CASCADE_SCALE_IMAGE
            )
            if len(faces) > 0:
                result["face_count"] = len(faces)
                result["faces"] = [
                    {"x": int(x), "y": int(y), "w": int(w), "h": int(h)}
                    for x, y, w, h in faces
                ]
    except Exception as ex:
        logger.debug("Face detection failed: %s", ex)

    risk = 0.0
    if result["face_count"] > 0:
        risk += min(result["face_count"] * 3.0, 6.0)
    result["risk_contribution"] = round(risk, 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# EXIF METADATA EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def extract_exif(img, file_bytes: bytes) -> dict:
    result = {
        "available": PIL_AVAILABLE, "raw": {}, "flags": [], "gps": None,
        "software": "", "make": "", "model": "", "datetime_original": "",
        "risk_contribution": 0.0,
    }
    if not PIL_AVAILABLE:
        return result
    try:
        exif_data = img._getexif()
        if not exif_data:
            return result
        human = {}
        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if tag_name == "MakerNote":
                continue
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            human[tag_name] = str(value) if not isinstance(value, (int, float, str)) else value
        result["raw"] = human
    except Exception:
        return result

    software = str(human.get("Software", "")).strip()
    make     = str(human.get("Make",     "")).strip()
    model    = str(human.get("Model",    "")).strip()
    dt_orig  = str(human.get("DateTimeOriginal", "")).strip()
    dt_mod   = str(human.get("DateTime",         "")).strip()
    result.update({"software": software, "make": make, "model": model,
                   "datetime_original": dt_orig})

    gps_info = exif_data.get(34853)
    if gps_info:
        try:
            def _deg(vals):
                return float(vals[0]) + float(vals[1]) / 60.0 + float(vals[2]) / 3600.0
            lat = _deg(gps_info.get(2, [0, 0, 0]))
            lon = _deg(gps_info.get(4, [0, 0, 0]))
            if gps_info.get(1, "N") == "S": lat = -lat
            if gps_info.get(3, "E") == "W": lon = -lon
            result["gps"] = {"lat": round(lat, 6), "lon": round(lon, 6)}
            result["flags"].append("gps_present")
        except Exception:
            pass

    risk = 0.0
    if not make and not model:
        result["flags"].append("no_device_info")
    if software:
        result["flags"].append("software_edited")
        risk += 1.0
        AI_TOOLS = ["midjourney", "dall-e", "stable diffusion", "firefly",
                    "canva", "photoshop", "gimp", "affinity", "deepdream",
                    "runwayml", "bing image creator", "adobe"]
        if any(t in software.lower() for t in AI_TOOLS):
            result["flags"].append("ai_generated_hint")
            risk += 3.0
    if dt_orig:
        try:
            dt = None
            for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.datetime.strptime(dt_orig, fmt)
                    break
                except ValueError:
                    continue
            if dt and dt > datetime.datetime.utcnow():
                result["flags"].append("future_timestamp")
                risk += 4.0
        except Exception:
            pass
    if dt_orig and dt_mod and dt_orig != dt_mod:
        try:
            d1 = datetime.datetime.strptime(dt_orig, "%Y:%m:%d %H:%M:%S")
            d2 = datetime.datetime.strptime(dt_mod,  "%Y:%m:%d %H:%M:%S")
            if abs((d1 - d2).total_seconds()) > 86400:
                result["flags"].append("timestamp_mismatch")
                risk += 1.0
        except Exception:
            pass
    result["risk_contribution"] = round(min(risk, 8.0), 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# ML CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def _normalise_classifier_label(raw_label: str) -> str:
    label = str(raw_label).strip().upper()
    if label in ("LABEL_1", "1"):       return "PHISHING"
    if label in ("LABEL_0", "0"):       return "SAFE"
    if any(kw in label for kw in ("PHISH", "SPAM", "MALICIOUS", "FAKE", "FRAUD")):
        return "PHISHING"
    if any(kw in label for kw in ("SAFE", "LEGITIMATE", "LEGIT", "BENIGN", "REAL", "HAM")):
        return "SAFE"
    if "SUSPICIOUS" in label:           return "SUSPICIOUS"
    return "INSUFFICIENT_DATA"


def run_classifier(text: str) -> dict:
    if not text or len(text.strip()) < MIN_OCR_CHARS:
        return {"label": "INSUFFICIENT_DATA", "score": 0.0,
                "note": "Insufficient text extracted from image for classification"}
    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("email_classifier")
        if pipeline is None:
            return {"label": "INSUFFICIENT_DATA", "score": 0.0,
                    "note": "Classifier model not loaded"}
        output = pipeline(text[:512], truncation=True, max_length=512)
        if isinstance(output, list):
            output = output[0]
        raw_label  = output.get("label", "UNKNOWN")
        score      = float(output.get("score", 0.0))
        normalised = _normalise_classifier_label(raw_label)
        return {"label": normalised, "raw_label": raw_label, "score": round(score, 4)}
    except Exception as ex:
        logger.warning("Classifier failed: %s", ex)
        return {"label": "INSUFFICIENT_DATA", "score": 0.0,
                "note": f"Classifier error: {str(ex)[:80]}"}


def _derive_classifier_fallback(brands, keywords, qr_result) -> dict:
    has_malicious_qr  = len(qr_result.get("malicious_urls",  [])) > 0
    has_suspicious_qr = len(qr_result.get("suspicious_urls", [])) > 0
    n_brands   = len(brands)
    n_keywords = len(keywords)
    if has_malicious_qr:
        return {"label": "PHISHING",    "score": 0.85, "note": "Malicious QR code URL detected"}
    if (n_brands >= 2 and n_keywords >= 2) or (n_brands >= 1 and n_keywords >= 3):
        return {"label": "PHISHING",    "score": 0.70, "note": "Brand + phishing keyword combination"}
    if has_suspicious_qr or (n_brands >= 1 and n_keywords >= 1) or n_keywords >= 3:
        return {"label": "SUSPICIOUS",  "score": 0.50, "note": "Brand/keyword/QR signals present"}
    if n_brands >= 1:
        return {"label": "SUSPICIOUS",  "score": 0.35, "note": "Brand name detected in image"}
    return {"label": "NO_TEXT", "score": 0.0,
            "note": "Insufficient text extracted from image"}


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _compute_risk_score(
    classifier_result, brands, keywords, ocr_text,
    qr_result, stego_result, face_logo_result, exif_result,
    ela_result=None,
) -> float:
    score = 5.0
    clf_label = classifier_result.get("label", "UNKNOWN")
    clf_score = classifier_result.get("score", 0.0)
    if clf_label == "PHISHING":
        score += clf_score * 50.0
    elif clf_label == "SAFE":
        score += (1.0 - clf_score) * 5.0
    elif clf_label == "SUSPICIOUS":
        score += clf_score * 25.0
    score += min(len(brands)   * 12.0, 24.0)
    score += min(len(keywords) *  8.0, 32.0)
    url_hits = len(re.findall(r"https?://", ocr_text, re.IGNORECASE))
    score   += min(url_hits * 3.0, 12.0)
    score   += qr_result.get("risk_contribution",        0.0)
    score   += stego_result.get("risk_contribution",     0.0)
    score   += face_logo_result.get("risk_contribution", 0.0)
    score   += exif_result.get("risk_contribution",      0.0)
    # ELA manipulation adds up to 10 points
    if ela_result and ela_result.get("is_potentially_manipulated"):
        score += 10.0
    return min(round(score, 1), 100.0)


def _determine_verdict(score: float) -> str:
    if score >= 70: return "MALICIOUS"
    if score >= 30: return "SUSPICIOUS"
    return "CLEAN"


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED EXPLANATION BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def _build_explanation(
    verdict, score, brands, keywords, classifier_result,
    ocr_text, ocr_available, qr_result, stego_result,
    face_logo_result, exif_result,
    gemini_description=None, ela_result=None,
) -> dict:
    clf_label = classifier_result.get("label",     "INSUFFICIENT_DATA")
    clf_raw   = classifier_result.get("raw_label",  clf_label)
    clf_score = classifier_result.get("score",      0.0)
    clf_note  = classifier_result.get("note",       "")
    clf_pct   = int(clf_score * 100)

    verdict_words = {
        "CLEAN":      "no significant phishing indicators were detected",
        "SUSPICIOUS": "suspicious indicators were detected",
        "MALICIOUS":  "strong phishing indicators were found",
    }
    summary = (
        f"PhishGuard ran a {'partial (no OCR) ' if not ocr_available else ''}"
        f"multi-layer analysis on this image. "
        f"Risk score: {score}/100 — {verdict_words.get(verdict, 'analysis complete')}."
    )

    if clf_label == "PHISHING":
        clf_exp = (
            f"The phishing text classifier (DistilBERT) analysed the OCR-extracted "
            f"text and returned PHISHING with {clf_pct}% confidence. "
            f"Raw model label: '{clf_raw}'."
            + (f" {clf_note}" if clf_note else "")
        )
    elif clf_label == "SAFE":
        clf_exp = (
            f"Classifier found no phishing content ({clf_pct}% confidence safe). "
            f"Raw model label: '{clf_raw}'."
        )
    elif clf_label in ("INSUFFICIENT_DATA", "NO_TEXT"):
        clf_exp = (
            f"Too little text was extracted (under {MIN_OCR_CHARS} chars) for BERT. "
            f"Verdict derived from brand detection, keyword matching, and QR analysis."
            + (f" {clf_note}" if clf_note else "")
        )
    else:
        clf_exp = f"Classifier: '{clf_label}' (raw: '{clf_raw}', {clf_pct}% confidence). " + (clf_note or "")

    classifier_section = {
        "label":       clf_label, "raw_label": clf_raw,
        "score_pct":   clf_pct,
        "method":      "DistilBERT fine-tuned phishing text classifier",
        "explanation": clf_exp,
    }

    brand_section = {
        "brands_found": brands, "count": len(brands),
        "explanation": (
            f"{len(brands)} known brand name(s) detected: {', '.join(brands)}. "
            f"Brand impersonation is a primary phishing technique."
            if brands else
            "No known brand names detected in the image text."
        ),
    }

    keyword_section = {
        "keywords_found": keywords, "count": len(keywords),
        "explanation": (
            f"{len(keywords)} phishing keyword phrase(s) matched in image text."
            if keywords else
            f"No phishing phrases detected (checked against {len(PHISHING_KEYWORDS)} patterns)."
        ),
    }

    qr_section = None
    if qr_result.get("codes"):
        n   = len(qr_result["codes"])
        mal = qr_result.get("malicious_urls",  [])
        sus = qr_result.get("suspicious_urls", [])
        qr_section = {
            "code_count": n, "malicious_urls": mal, "suspicious_urls": sus,
            "explanation": (
                f"{n} QR/barcode(s) detected. "
                + (f"{len(mal)} malicious URL(s). " if mal else "")
                + (f"{len(sus)} suspicious URL(s). " if sus else "")
                + ("No malicious URLs in QR codes." if not mal and not sus else "")
            ),
        }

    stego_section = None
    if stego_result.get("available"):
        stego_section = {
            "suspicious": stego_result.get("suspicious", False),
            "confidence": stego_result.get("confidence", "low"),
            "flags":      stego_result.get("flags", []),
            "explanation": (
                "LSB steganography analysis scanned R/G/B channels for hidden data. "
                + (
                    f"Suspicious patterns detected ({stego_result.get('confidence','low')} confidence)."
                    if stego_result.get("suspicious") else
                    "No steganographic patterns detected."
                )
            ),
        }

    exif_section = None
    exif_flags = exif_result.get("flags", [])
    if exif_flags:
        flag_descriptions = {
            "future_timestamp":  "Image timestamp is set in the future — metadata may be forged",
            "ai_generated_hint": f"Software field indicates AI/editing: {exif_result.get('software','')}",
            "gps_present":       "GPS coordinates embedded in EXIF",
            "software_edited":   "Image was edited or generated by software",
            "timestamp_mismatch":"Creation and modification timestamps differ by > 24 hours",
            "no_device_info":    "No camera Make/Model — image was not taken by a real camera",
        }
        exif_section = {
            "flags":        exif_flags,
            "software":     exif_result.get("software", ""),
            "gps":          exif_result.get("gps"),
            "explanations": [flag_descriptions.get(f, f) for f in exif_flags],
            "explanation":  (
                f"EXIF metadata analysis found {len(exif_flags)} anomalous flag(s). "
                "EXIF manipulation can indicate forged phishing screenshots."
            ),
        }

    ocr_note = None
    if not ocr_available:
        ocr_note = (
            "OCR (Tesseract) is not installed. Text extraction, brand detection, "
            "and keyword analysis are disabled."
        )

    # ELA section
    ela_section = None
    if ela_result:
        ela_section = {
            "available":                  ela_result.get("available", False),
            "mean_ela":                   ela_result.get("mean_ela",  0.0),
            "max_ela":                    ela_result.get("max_ela",   0.0),
            "std_ela":                    ela_result.get("std_ela",   0.0),
            "is_potentially_manipulated": ela_result.get("is_potentially_manipulated", False),
            "ela_image_b64":              ela_result.get("ela_image_b64", ""),
            "explanation":                ela_result.get("explanation", ""),
        }

    return {
        "verdict":           verdict,
        "risk_score":        score,
        "summary":           summary,
        "classifier":        classifier_section,
        "brand_analysis":    brand_section,
        "keyword_analysis":  keyword_section,
        "qr_analysis":       qr_section,
        "stego_analysis":    stego_section,
        "exif_analysis":     exif_section,
        "ela_analysis":      ela_section,
        "gemini_description": gemini_description,
        "ocr_note":          ocr_note,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze_image(file_bytes: bytes, filename: str) -> dict:
    """
    Main entry point called by the FastAPI /scan/image endpoint.
    Phase 7 additions: gemini_description, ela_analysis.
    """
    result = {
        "filename":           filename,
        "file_size":          len(file_bytes),
        "image_width":        0,
        "image_height":       0,
        "image_format":       "",
        "ocr_text":           "",
        "ocr_word_count":     0,
        "detected_brands":    [],
        "phishing_keywords":  [],
        "classifier_result":  {"label": "INSUFFICIENT_DATA", "score": 0.0},
        "qr_codes":           {},
        "steganography":      {},
        "face_logo":          {},
        "exif":               {},
        "ela_analysis":       {},       # ← Phase 7 NEW
        "gemini_description": {},       # ← Phase 7 NEW
        "risk_score":         5.0,
        "verdict":            "CLEAN",
        "explanation":        "",
        "error":              None,
        "ocr_available":      TESS_AVAILABLE and PIL_AVAILABLE,
    }

    if len(file_bytes) > MAX_IMAGE_BYTES:
        result["error"] = "File too large (max 20 MB)."
        result["explanation"] = result["error"]
        return result

    if not PIL_AVAILABLE:
        result["error"] = "Pillow not installed."
        result["explanation"] = result["error"]
        return result

    img = load_image(file_bytes, filename)
    if img is None:
        result["error"] = "Could not open image — unsupported format or corrupt file."
        result["explanation"] = result["error"]
        return result

    meta = get_image_metadata(img)
    result["image_width"]  = meta["width"]
    result["image_height"] = meta["height"]
    result["image_format"] = meta["format"]

    ocr_text                   = run_ocr(img)
    result["ocr_text"]         = ocr_text
    result["ocr_word_count"]   = len(ocr_text.split()) if ocr_text else 0
    result["detected_brands"]  = detect_brands(ocr_text)
    result["phishing_keywords"]= detect_phishing_keywords(ocr_text)
    result["qr_codes"]         = detect_qr_codes(img)
    result["steganography"]    = detect_steganography(img)
    result["face_logo"]        = detect_faces_and_logos(img)
    result["exif"]             = extract_exif(img, file_bytes)

    # ── Phase 7: ELA analysis ─────────────────────────────────────────────────
    ela_result = _run_ela_analysis(img, file_bytes)
    result["ela_analysis"] = ela_result

    # ── Phase 7: Gemini vision description ────────────────────────────────────
    gemini_result = _describe_with_gemini(file_bytes, filename)
    result["gemini_description"] = gemini_result

    clf = run_classifier(ocr_text)
    if clf["label"] == "INSUFFICIENT_DATA":
        clf = _derive_classifier_fallback(
            result["detected_brands"],
            result["phishing_keywords"],
            result["qr_codes"],
        )
    result["classifier_result"] = clf

    result["risk_score"] = _compute_risk_score(
        clf,
        result["detected_brands"],
        result["phishing_keywords"],
        ocr_text,
        result["qr_codes"],
        result["steganography"],
        result["face_logo"],
        result["exif"],
        ela_result=ela_result,
    )
    result["verdict"] = _determine_verdict(result["risk_score"])

    result["explanation"] = _build_explanation(
        result["verdict"],
        result["risk_score"],
        result["detected_brands"],
        result["phishing_keywords"],
        clf,
        ocr_text,
        result["ocr_available"],
        result["qr_codes"],
        result["steganography"],
        result["face_logo"],
        result["exif"],
        gemini_description=gemini_result,
        ela_result=ela_result,
    )

    return result