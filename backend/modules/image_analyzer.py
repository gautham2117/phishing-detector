"""
backend/modules/image_analyzer.py
Phase 7 — Image Analysis Engine  (FIXED + EXTENDED)

FIXES IN THIS VERSION:
  1. "UNKNOWN" / "LABEL_1" classifier label — raw HuggingFace labels like
     LABEL_0 / LABEL_1 are now fully normalised before being stored or used.
     run_classifier() maps LABEL_1 → PHISHING, LABEL_0 → SAFE, etc.
     When OCR text is too short, verdict is derived from brand/keyword/QR
     signals instead of hard-returning UNKNOWN.
     UNKNOWN is only emitted when ALL signals are absent (truly unanalysable).
  2. Verdict threshold fixed — _determine_verdict() now uses >= 30 for
     SUSPICIOUS (was >= 35), matching the standard threshold used across
     all other PhishGuard modules.
  3. OCR preprocessing — grayscale + adaptive threshold applied before
     pytesseract, dramatically improving accuracy on screenshots.
  4. _compute_risk_score — now incorporates QR, steganography, face, and EXIF
     signal weights correctly.
  5. explanation — now returns a structured dict (not a plain string) with
     sections for each analysis module, enabling rich card-based rendering
     in the JS renderExplanation() function.

NEW IN THIS VERSION:
  6. QR Code detector  — pyzbar decodes all QR / barcodes in the image.
  7. Steganography detection — LSB entropy analysis + chi-square test.
  8. Face / logo brand detection — OpenCV Haar cascade + heuristic logo scan.
  9. EXIF metadata extractor — full EXIF dump with anomaly flagging.
"""

import io
import re
import os
import math
import logging
import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional deps — graceful fallback if not installed ────────────────────────
try:
    from PIL import Image, UnidentifiedImageError, ExifTags
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

MAX_IMAGE_BYTES  = 20 * 1024 * 1024
ALLOWED_FORMATS  = {"PNG", "JPEG", "JPG", "GIF", "BMP", "WEBP"}
MIN_OCR_CHARS    = 20

STEGO_ENTROPY_HIGH  = 0.98
STEGO_CHISQ_UNIFORM = 0.45

KNOWN_BRANDS = {
    "paypal":        "PayPal",
    "google":        "Google",
    "microsoft":     "Microsoft",
    "apple":         "Apple",
    "amazon":        "Amazon",
    "netflix":       "Netflix",
    "facebook":      "Facebook",
    "instagram":     "Instagram",
    "twitter":       "Twitter",
    "linkedin":      "LinkedIn",
    "dropbox":       "Dropbox",
    "onedrive":      "OneDrive",
    "icloud":        "iCloud",
    "chase":         "Chase Bank",
    "wellsfargo":    "Wells Fargo",
    "citibank":      "Citibank",
    "bankofamerica": "Bank of America",
    "gmail":         "Gmail",
    "outlook":       "Outlook",
    "yahoo":         "Yahoo",
    "adobe":         "Adobe",
    "docusign":      "DocuSign",
    "steam":         "Steam",
    "discord":       "Discord",
    "whatsapp":      "WhatsApp",
    "coinbase":      "Coinbase",
    "binance":       "Binance",
    "blockchain":    "Blockchain",
    "dhl":           "DHL",
    "fedex":         "FedEx",
    "ups":           "UPS",
    "usps":          "USPS",
    "irs":           "IRS",
}

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


# ══════════════════════════════════════════════════════════════════════════════
# IMAGE LOADING & METADATA
# ══════════════════════════════════════════════════════════════════════════════

def load_image(file_bytes: bytes, filename: str) -> Optional[object]:
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

def _preprocess_for_ocr(img):
    if CV2_AVAILABLE and NUMPY_AVAILABLE:
        try:
            arr   = np.array(img.convert("RGB"))
            gray  = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
            thresh = cv2.adaptiveThreshold(
                gray, 255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                blockSize=31,
                C=10,
            )
            return Image.fromarray(thresh)
        except Exception as ex:
            logger.debug("CV2 preprocessing failed, falling back: %s", ex)
    try:
        return img.convert("L")
    except Exception:
        return img


def run_ocr(img) -> str:
    if not TESS_AVAILABLE:
        logger.warning("pytesseract not installed — OCR skipped.")
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
    found = []
    for token, display in KNOWN_BRANDS.items():
        if re.search(r"\b" + re.escape(token) + r"\b", text_lower):
            if display not in found:
                found.append(display)
    return found


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
        "available":         PYZBAR_AVAILABLE,
        "codes":             [],
        "url_count":         0,
        "malicious_urls":    [],
        "suspicious_urls":   [],
        "risk_contribution": 0.0,
    }

    if not PYZBAR_AVAILABLE or not PIL_AVAILABLE:
        return result

    try:
        scan_img = img.convert("RGB") if img.mode != "RGB" else img
        symbols  = pyzbar.decode(scan_img)
    except Exception as ex:
        logger.warning("QR decode failed: %s", ex)
        result["error"] = str(ex)
        return result

    risk = 0.0

    for sym in symbols:
        try:
            raw_data = sym.data.decode("utf-8", errors="replace").strip()
        except Exception:
            raw_data = ""

        is_url     = bool(re.match(r"https?://", raw_data, re.IGNORECASE))
        code_entry = {
            "type":      sym.type,
            "data":      raw_data,
            "is_url":    is_url,
            "url_label": None,
            "url_score": None,
        }

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
                logger.warning("QR URL scoring failed for %s: %s", raw_data, ex)

        result["codes"].append(code_entry)

    result["risk_contribution"] = round(min(risk, 20.0), 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# STEGANOGRAPHY DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_steganography(img) -> dict:
    result = {
        "available":         NUMPY_AVAILABLE and PIL_AVAILABLE,
        "lsb_entropy":       {},
        "chi_scores":        {},
        "suspicious":        False,
        "confidence":        "low",
        "flags":             [],
        "risk_contribution": 0.0,
    }

    if not NUMPY_AVAILABLE or not PIL_AVAILABLE:
        return result

    try:
        arr = np.array(img.convert("RGB"), dtype=np.uint8)
    except Exception as ex:
        logger.warning("Stego: image convert failed: %s", ex)
        result["error"] = str(ex)
        return result

    channel_names       = ["R", "G", "B"]
    suspicious_channels = 0
    risk = 0.0

    for i, ch_name in enumerate(channel_names):
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
        "available":         CV2_AVAILABLE and NUMPY_AVAILABLE and PIL_AVAILABLE,
        "face_count":        0,
        "faces":             [],
        "logo_regions":      [],
        "risk_contribution": 0.0,
    }

    if not CV2_AVAILABLE or not NUMPY_AVAILABLE or not PIL_AVAILABLE:
        return result

    try:
        arr  = np.array(img.convert("RGB"))
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
    except Exception as ex:
        logger.warning("Face/logo: image convert failed: %s", ex)
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

    try:
        height, width = gray.shape
        edges = cv2.Canny(gray, threshold1=50, threshold2=150)
        hsv   = cv2.cvtColor(arr, cv2.COLOR_RGB2HSV)
        logo_candidates = []
        win_sizes = [(w, h) for w in [64, 96, 128] for h in [64, 96, 128]
                     if 0.5 <= w / h <= 2.0]
        for win_w, win_h in win_sizes:
            step_x = max(win_w // 4, 8)
            step_y = max(win_h // 4, 8)
            for y in range(0, height - win_h, step_y):
                for x in range(0, width - win_w, step_x):
                    edge_patch   = edges[y:y+win_h, x:x+win_w]
                    edge_density = edge_patch.sum() / (win_w * win_h * 255.0)
                    if edge_density < 0.08:
                        continue
                    sat_patch = hsv[y:y+win_h, x:x+win_w, 1]
                    if float(sat_patch.mean()) / 255.0 < 0.25:
                        continue
                    hue_patch    = hsv[y:y+win_h, x:x+win_w, 0]
                    dominant_hue = int(np.median(hue_patch))
                    logo_candidates.append({
                        "x": x, "y": y, "w": win_w, "h": win_h,
                        "edge_density": round(edge_density, 4),
                        "dominant_hue": dominant_hue,
                    })
        logo_candidates.sort(key=lambda c: c["edge_density"], reverse=True)
        kept = []
        for cand in logo_candidates:
            overlap = False
            for k in kept:
                ix = max(0, min(cand["x"]+cand["w"], k["x"]+k["w"]) - max(cand["x"], k["x"]))
                iy = max(0, min(cand["y"]+cand["h"], k["y"]+k["h"]) - max(cand["y"], k["y"]))
                if ix * iy > 0.5 * cand["w"] * cand["h"]:
                    overlap = True
                    break
            if not overlap:
                kept.append(cand)
            if len(kept) >= 5:
                break
        result["logo_regions"] = kept
    except Exception as ex:
        logger.debug("Logo detection failed: %s", ex)

    risk = 0.0
    if result["face_count"] > 0:
        risk += min(result["face_count"] * 3.0, 6.0)
    if len(result["logo_regions"]) > 0:
        risk += min(len(result["logo_regions"]) * 1.5, 4.0)
    result["risk_contribution"] = round(risk, 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# EXIF METADATA EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def extract_exif(img, file_bytes: bytes) -> dict:
    result = {
        "available":         PIL_AVAILABLE,
        "raw":               {},
        "flags":             [],
        "gps":               None,
        "software":          "",
        "make":              "",
        "model":             "",
        "datetime_original": "",
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
    except Exception as ex:
        logger.debug("EXIF extraction failed: %s", ex)
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
        AI_TOOLS = [
            "midjourney", "dall-e", "stable diffusion", "firefly",
            "canva", "photoshop", "gimp", "affinity",
            "deepdream", "runwayml", "bing image creator", "adobe"
        ]
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
# ML CLASSIFIER  ← FIX 1: full label normalisation including LABEL_0/LABEL_1
# ══════════════════════════════════════════════════════════════════════════════

def _normalise_classifier_label(raw_label: str) -> str:
    """
    Map any raw HuggingFace model label to one of:
        PHISHING | SAFE | SUSPICIOUS | INSUFFICIENT_DATA

    Handles:
      - cybersectony/phishing-email-detection-distilbert_v2.4.1:
            LABEL_1 = phishing, LABEL_0 = safe
      - ealvaradob/bert-finetuned-phishing:
            PHISHING, LEGITIMATE
      - Any generic model using SPAM / MALICIOUS / BENIGN / LEGIT
    """
    label = str(raw_label).strip().upper()

    # Numeric HuggingFace labels — most common source of the LABEL_1 bug
    if label in ("LABEL_1", "1"):
        return "PHISHING"
    if label in ("LABEL_0", "0"):
        return "SAFE"

    # Named phishing labels
    if any(kw in label for kw in ("PHISH", "SPAM", "MALICIOUS", "FAKE", "FRAUD")):
        return "PHISHING"

    # Named safe labels
    if any(kw in label for kw in ("SAFE", "LEGITIMATE", "LEGIT", "BENIGN", "REAL", "HAM")):
        return "SAFE"

    # Generic suspicious
    if "SUSPICIOUS" in label:
        return "SUSPICIOUS"

    # Anything else we cannot map — treat as insufficient
    return "INSUFFICIENT_DATA"


def run_classifier(text: str) -> dict:
    """
    Run the email phishing classifier (DistilBERT) on extracted OCR text.
    Returns INSUFFICIENT_DATA when text is too short or model unavailable.
    All raw model labels are normalised through _normalise_classifier_label().
    """
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

        return {
            "label":     normalised,
            "raw_label": raw_label,        # kept for debugging
            "score":     round(score, 4),
        }

    except Exception as ex:
        logger.warning("Classifier failed on OCR text: %s", ex)
        return {"label": "INSUFFICIENT_DATA", "score": 0.0,
                "note": f"Classifier error: {str(ex)[:80]}"}


def _derive_classifier_fallback(
    brands: list,
    keywords: list,
    qr_result: dict,
) -> dict:
    """
    Synthesise a classifier label from brand, keyword, and QR signals
    when BERT cannot run due to insufficient OCR text.
    """
    has_malicious_qr  = len(qr_result.get("malicious_urls",  [])) > 0
    has_suspicious_qr = len(qr_result.get("suspicious_urls", [])) > 0
    n_brands   = len(brands)
    n_keywords = len(keywords)

    if has_malicious_qr:
        return {"label": "PHISHING", "score": 0.85,
                "note": "Malicious QR code URL detected — OCR insufficient for BERT"}
    if (n_brands >= 2 and n_keywords >= 2) or (n_brands >= 1 and n_keywords >= 3):
        return {"label": "PHISHING", "score": 0.70,
                "note": "Brand + phishing keyword combination detected"}
    if has_suspicious_qr or (n_brands >= 1 and n_keywords >= 1) or n_keywords >= 3:
        return {"label": "SUSPICIOUS", "score": 0.50,
                "note": "Brand/keyword/QR signals present — OCR insufficient for BERT"}
    if n_brands >= 1:
        return {"label": "SUSPICIOUS", "score": 0.35,
                "note": "Brand name detected in image"}

    return {"label": "NO_TEXT", "score": 0.0,
            "note": "Insufficient text extracted from image for classification"}


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING  ← FIX 2: threshold fixed to >= 30 for SUSPICIOUS
# ══════════════════════════════════════════════════════════════════════════════

def _compute_risk_score(
    classifier_result: dict,
    brands: list,
    keywords: list,
    ocr_text: str,
    qr_result: dict,
    stego_result: dict,
    face_logo_result: dict,
    exif_result: dict,
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

    score += qr_result.get("risk_contribution",        0.0)
    score += stego_result.get("risk_contribution",     0.0)
    score += face_logo_result.get("risk_contribution", 0.0)
    score += exif_result.get("risk_contribution",      0.0)

    return min(round(score, 1), 100.0)


def _determine_verdict(score: float) -> str:
    """
    FIX 2: threshold corrected.
    Previously used >= 35 for SUSPICIOUS — this caused a 33.0 score
    (which clearly has phishing signals) to be labelled CLEAN.
    Now consistent with all other PhishGuard modules: >= 30 = SUSPICIOUS.
    """
    if score >= 70:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED EXPLANATION BUILDER  ← FIX 5: returns dict, not plain string
# ══════════════════════════════════════════════════════════════════════════════

def _build_explanation(
    verdict: str,
    score: float,
    brands: list,
    keywords: list,
    classifier_result: dict,
    ocr_text: str,
    ocr_available: bool,
    qr_result: dict,
    stego_result: dict,
    face_logo_result: dict,
    exif_result: dict,
) -> dict:
    """
    Build a structured explanation dict for the image analysis.
    The JS renderExplanation() reads each section and renders cards.

    Shape:
    {
      "verdict":          str,
      "risk_score":       float,
      "summary":          str,
      "classifier": {
        "label":          str,        normalised label
        "raw_label":      str,        original model output
        "score_pct":      int,        0-100
        "method":         str,
        "explanation":    str,
      },
      "brand_analysis": {
        "brands_found":   list[str],
        "count":          int,
        "explanation":    str,
      },
      "keyword_analysis": {
        "keywords_found": list[str],
        "count":          int,
        "explanation":    str,
      },
      "qr_analysis":      dict | None,
      "stego_analysis":   dict | None,
      "exif_analysis":    dict | None,
      "ocr_note":         str | None,
    }
    """

    clf_label   = classifier_result.get("label",     "INSUFFICIENT_DATA")
    clf_raw     = classifier_result.get("raw_label",  clf_label)
    clf_score   = classifier_result.get("score",      0.0)
    clf_note    = classifier_result.get("note",       "")
    clf_pct     = int(clf_score * 100)

    # ── Summary ───────────────────────────────────────────────────────────────
    verdict_words = {
        "CLEAN":      "no significant phishing indicators were detected",
        "SUSPICIOUS": "suspicious indicators were detected",
        "MALICIOUS":  "strong phishing indicators were found",
    }
    summary = (
        f"PhishGuard ran a {'' if ocr_available else 'partial (no OCR) '}multi-layer "
        f"analysis on this image. Risk score: {score}/100 — "
        f"{verdict_words.get(verdict, 'analysis complete')}."
    )

    # ── Classifier section ────────────────────────────────────────────────────
    if clf_label == "PHISHING":
        clf_exp = (
            f"The phishing text classifier (DistilBERT fine-tuned on email/phishing data) "
            f"analysed the OCR-extracted text and returned a PHISHING classification "
            f"with {clf_pct}% confidence. "
            f"The raw model output label was '{clf_raw}'."
            + (f" {clf_note}" if clf_note else "")
        )
    elif clf_label == "SAFE":
        clf_exp = (
            f"The classifier found no phishing content in the extracted text "
            f"({clf_pct}% confidence the text is safe). "
            f"Raw model label: '{clf_raw}'."
        )
    elif clf_label in ("INSUFFICIENT_DATA", "NO_TEXT"):
        clf_exp = (
            f"The OCR engine extracted too little text (under {MIN_OCR_CHARS} chars) "
            f"for the BERT classifier to produce a reliable result. "
            f"The verdict was derived from brand name detection, phishing keyword "
            f"matching, and QR code analysis instead."
            + (f" {clf_note}" if clf_note else "")
        )
    else:
        clf_exp = (
            f"Classifier returned '{clf_label}' (raw: '{clf_raw}', {clf_pct}% confidence). "
            + (clf_note or "")
        )

    classifier_section = {
        "label":       clf_label,
        "raw_label":   clf_raw,
        "score_pct":   clf_pct,
        "method":      "DistilBERT fine-tuned phishing text classifier (cybersectony/phishing-email-detection-distilbert_v2.4.1)",
        "explanation": clf_exp,
    }

    # ── Brand analysis ────────────────────────────────────────────────────────
    if brands:
        brand_exp = (
            f"{len(brands)} known brand name(s) were detected in the image text: "
            f"{', '.join(brands)}. "
            f"Phishing attacks commonly impersonate trusted brands to trick victims "
            f"into entering credentials. This is a strong phishing signal when combined "
            f"with urgency language or credential-harvesting forms."
        )
    else:
        brand_exp = (
            "No known brand names were detected in the image text. "
            "Brand impersonation is one of the most common phishing techniques — "
            "the absence of brand names reduces (but does not eliminate) risk."
        )

    brand_section = {
        "brands_found": brands,
        "count":        len(brands),
        "explanation":  brand_exp,
    }

    # ── Keyword analysis ──────────────────────────────────────────────────────
    if keywords:
        kw_exp = (
            f"{len(keywords)} phishing keyword phrase(s) were matched in the image text. "
            f"These phrases are statistically correlated with phishing content based on "
            f"analysis of known phishing campaigns. Common tactics include urgency "
            f"('act now', 'suspended'), fear ('account will be closed'), and "
            f"credential requests ('verify your account', 'enter your password')."
        )
    else:
        kw_exp = (
            "No phishing keyword phrases were detected. The image text was checked "
            f"against a library of {len(PHISHING_KEYWORDS)} known phishing phrases."
        )

    keyword_section = {
        "keywords_found": keywords,
        "count":          len(keywords),
        "explanation":    kw_exp,
    }

    # ── QR section ────────────────────────────────────────────────────────────
    qr_section = None
    if qr_result.get("codes"):
        n   = len(qr_result["codes"])
        mal = qr_result.get("malicious_urls",  [])
        sus = qr_result.get("suspicious_urls", [])
        qr_section = {
            "code_count":     n,
            "malicious_urls": mal,
            "suspicious_urls": sus,
            "explanation": (
                f"{n} QR/barcode(s) detected in the image. "
                + (f"{len(mal)} URL(s) were classified as malicious by the ML URL model. " if mal else "")
                + (f"{len(sus)} URL(s) were flagged as suspicious. " if sus else "")
                + ("No malicious URLs found in QR codes." if not mal and not sus else "")
            ),
        }

    # ── Steganography section ─────────────────────────────────────────────────
    stego_section = None
    if stego_result.get("available"):
        stego_section = {
            "suspicious":  stego_result.get("suspicious", False),
            "confidence":  stego_result.get("confidence", "low"),
            "flags":       stego_result.get("flags", []),
            "explanation": (
                f"LSB (Least Significant Bit) steganography analysis scanned all "
                f"three colour channels (R, G, B) for hidden data patterns using "
                f"entropy analysis and chi-square uniformity tests. "
                + (
                    f"Suspicious patterns were detected ({stego_result.get('confidence','low')} confidence) — "
                    f"this may indicate hidden data embedded in the image pixels."
                    if stego_result.get("suspicious") else
                    "No steganographic patterns detected — LSB distribution appears normal."
                )
            ),
        }

    # ── EXIF section ──────────────────────────────────────────────────────────
    exif_section = None
    exif_flags = exif_result.get("flags", [])
    if exif_flags:
        flag_descriptions = {
            "future_timestamp":  "Image timestamp is set in the future — metadata may be forged",
            "ai_generated_hint": f"Software field indicates AI generation or editing: {exif_result.get('software','')}",
            "gps_present":       f"GPS coordinates embedded in EXIF",
            "software_edited":   "Image was edited or generated by software",
            "timestamp_mismatch":"Creation and modification timestamps differ by > 24 hours",
            "no_device_info":    "No camera Make/Model — image was not taken by a real camera",
        }
        exif_section = {
            "flags":       exif_flags,
            "software":    exif_result.get("software", ""),
            "gps":         exif_result.get("gps"),
            "explanations": [flag_descriptions.get(f, f) for f in exif_flags],
            "explanation": (
                "EXIF metadata analysis extracted embedded image properties and "
                f"found {len(exif_flags)} anomalous flag(s). EXIF manipulation "
                "can indicate forged screenshots used in phishing attacks."
            ),
        }

    # ── OCR note ──────────────────────────────────────────────────────────────
    ocr_note = None
    if not ocr_available:
        ocr_note = (
            "OCR (Tesseract) is not installed on this server. Text extraction, "
            "brand detection, and keyword analysis are disabled. Install "
            "pytesseract and Tesseract for full image analysis capability."
        )

    return {
        "verdict":          verdict,
        "risk_score":       score,
        "summary":          summary,
        "classifier":       classifier_section,
        "brand_analysis":   brand_section,
        "keyword_analysis": keyword_section,
        "qr_analysis":      qr_section,
        "stego_analysis":   stego_section,
        "exif_analysis":    exif_section,
        "ocr_note":         ocr_note,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze_image(file_bytes: bytes, filename: str) -> dict:
    """
    Main entry point called by the FastAPI /scan/image endpoint.
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
        "classifier_result": {"label": "INSUFFICIENT_DATA", "score": 0.0},
        "qr_codes":          {},
        "steganography":     {},
        "face_logo":         {},
        "exif":              {},
        "risk_score":        5.0,
        "verdict":           "CLEAN",
        "explanation":       "",
        "error":             None,
        "ocr_available":     TESS_AVAILABLE and PIL_AVAILABLE,
    }

    if len(file_bytes) > MAX_IMAGE_BYTES:
        result["error"] = "File too large (max 20 MB)."
        result["explanation"] = result["error"]
        return result

    if not PIL_AVAILABLE:
        result["error"] = "Pillow not installed — cannot process image."
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

    ocr_text                  = run_ocr(img)
    result["ocr_text"]        = ocr_text
    result["ocr_word_count"]  = len(ocr_text.split()) if ocr_text else 0
    result["detected_brands"] = detect_brands(ocr_text)
    result["phishing_keywords"] = detect_phishing_keywords(ocr_text)
    result["qr_codes"]        = detect_qr_codes(img)
    result["steganography"]   = detect_steganography(img)
    result["face_logo"]       = detect_faces_and_logos(img)
    result["exif"]            = extract_exif(img, file_bytes)

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
    )
    result["verdict"] = _determine_verdict(result["risk_score"])

    # explanation is now a structured dict (not a plain string)
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
    )

    return result