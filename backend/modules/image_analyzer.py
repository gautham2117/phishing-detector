"""
backend/modules/image_analyzer.py
Phase 7 — Image Analysis Engine  (FIXED + EXTENDED)

FIXES IN THIS VERSION:
  1. "UNKNOWN" classifier label — when OCR text is too short, verdict is now
     derived from brand/keyword/QR signals instead of hard-returning UNKNOWN.
     UNKNOWN is only emitted when ALL signals are absent (truly unanalysable).
  2. OCR preprocessing — grayscale + adaptive threshold applied before
     pytesseract, dramatically improving accuracy on screenshots & low-contrast
     images.
  3. _compute_risk_score — now incorporates QR, steganography, face, and EXIF
     signal weights correctly. UNKNOWN classifier label no longer silently
     contributes 0 risk when other signals are present.
  4. _build_explanation — surfaces findings from all four new modules.

NEW IN THIS VERSION:
  5. QR Code detector  — pyzbar decodes all QR / barcodes in the image.
     Each decoded URL is scored via _classify_url_with_bert from
     url_intelligence.py. Suspicious/malicious QR URLs raise risk score.
  6. Steganography detection — LSB (least-significant-bit) entropy analysis
     + chi-square uniformity test on R/G/B channels. High LSB entropy or
     near-uniform LSB distribution indicates hidden payload.
  7. Face / logo brand detection — OpenCV Haar cascade frontal-face detector
     for faces (identity-theft lure detection). Logo region detection via
     edge-density + color-blob heuristics on isolated bright/saturated patches.
  8. EXIF metadata extractor — full EXIF dump via Pillow's _getexif().
     Flags: future timestamps, GPS coordinates present, software field set
     (indicates edited/generated image), mismatched creation vs modification.
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
    # OSError is raised on Windows when libzbar-64.dll or its dependency
    # libiconv.dll is missing — treat identically to pyzbar not being installed.
    PYZBAR_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

MAX_IMAGE_BYTES  = 20 * 1024 * 1024      # 20 MB
ALLOWED_FORMATS  = {"PNG", "JPEG", "JPG", "GIF", "BMP", "WEBP"}

# Minimum OCR text length worth sending to the BERT classifier
MIN_OCR_CHARS = 20

# Steganography thresholds
STEGO_ENTROPY_HIGH   = 0.98   # LSB channel entropy above this → suspicious
STEGO_CHISQ_UNIFORM  = 0.45   # chi-square uniformity score above this → suspicious

# Brand name → display name mapping
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
# OCR  (FIX 2: preprocessing added)
# ══════════════════════════════════════════════════════════════════════════════

def _preprocess_for_ocr(img):
    """
    Convert PIL image to a high-contrast version suited for Tesseract.
    Pipeline: RGB → grayscale → adaptive threshold (if cv2 available),
    otherwise simple grayscale convert.
    """
    if CV2_AVAILABLE and NUMPY_AVAILABLE:
        try:
            arr  = np.array(img.convert("RGB"))
            gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
            # Adaptive threshold handles varying lighting / screenshot gradients
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

    # Fallback: simple grayscale
    try:
        return img.convert("L")
    except Exception:
        return img


def run_ocr(img) -> str:
    """
    Extract text from a PIL Image using Tesseract.
    Applies preprocessing first for improved accuracy.
    Returns empty string if Tesseract is unavailable or fails.
    """
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
# BRAND DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_brands(text: str) -> list:
    """Search OCR text for known brand names. Returns list of display names."""
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
    """Scan OCR text for known phishing phrases. Returns list of matches."""
    if not text:
        return []
    text_lower = text.lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in text_lower]


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — QR CODE DETECTOR  (NEW)
# ══════════════════════════════════════════════════════════════════════════════

def detect_qr_codes(img) -> dict:
    """
    Decode all QR codes and barcodes present in the image using pyzbar.
    Each decoded URL is scored via the URL ML model from url_intelligence.py.

    Returns:
        {
          "available":        bool,
          "codes":            list[dict],
          "url_count":        int,
          "malicious_urls":   list[str],
          "suspicious_urls":  list[str],
          "risk_contribution": float   0-20
        }

    Each code dict:
        {
          "type":      str,         e.g. "QRCODE", "EAN13"
          "data":      str,         decoded string
          "is_url":    bool,
          "url_label": str | None,  "MALICIOUS" | "BENIGN" | None
          "url_score": float | None  0.0-1.0 phishing probability
        }
    """
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

        is_url = bool(re.match(r"https?://", raw_data, re.IGNORECASE))
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
                # Import here to avoid circular import at module load time
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
# MODULE 2 — STEGANOGRAPHY DETECTION  (NEW)
# ══════════════════════════════════════════════════════════════════════════════

def detect_steganography(img) -> dict:
    """
    Analyse the Least Significant Bits (LSBs) of each colour channel for
    hidden-data patterns using two independent tests:

    Test A — LSB entropy:
        Natural images have slightly non-uniform LSB distributions.
        Stego tools (LSB substitution, Steghide, OpenStego) produce LSB
        channels with entropy ≈ 1.0 (perfectly random).
        Threshold: > 0.98 per channel is suspicious.

    Test B — Chi-square uniformity:
        Pairs of adjacent pixel values (2k, 2k+1) should appear equally
        in stego-embedded data. Chi-score > 0.45 is suspicious.

    Returns:
        {
          "available":        bool,
          "lsb_entropy":      dict  {"R":float,"G":float,"B":float}
          "chi_scores":       dict  {"R":float,"G":float,"B":float}
          "suspicious":       bool,
          "confidence":       str   "low"|"medium"|"high"
          "flags":            list[str]
          "risk_contribution": float  0-15
        }
    """
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

    channel_names      = ["R", "G", "B"]
    suspicious_channels = 0
    risk = 0.0

    for i, ch_name in enumerate(channel_names):
        channel = arr[:, :, i].flatten()

        # ── Test A: LSB entropy ──────────────────────────────────────────────
        lsb_bits = channel & 1
        ones     = int(np.sum(lsb_bits))
        total    = len(lsb_bits)
        p1       = ones / total if total > 0 else 0.5
        p0       = 1.0 - p1
        entropy  = 0.0
        if p1 > 0:
            entropy -= p1 * math.log2(p1)
        if p0 > 0:
            entropy -= p0 * math.log2(p0)
        result["lsb_entropy"][ch_name] = round(entropy, 6)

        # ── Test B: Chi-square uniformity ────────────────────────────────────
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

        # ── Flag suspicious channels ─────────────────────────────────────────
        ch_sus = False
        if entropy > STEGO_ENTROPY_HIGH:
            result["flags"].append(
                f"High LSB entropy on {ch_name} ({entropy:.4f} > {STEGO_ENTROPY_HIGH})"
            )
            ch_sus = True
        if chi_score > STEGO_CHISQ_UNIFORM:
            result["flags"].append(
                f"Near-uniform LSB distribution on {ch_name} (chi={chi_score:.4f})"
            )
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
# MODULE 3 — FACE & LOGO DETECTION  (NEW)
# ══════════════════════════════════════════════════════════════════════════════

def detect_faces_and_logos(img) -> dict:
    """
    Detect human faces and candidate logo regions in the image.

    Face detection:
        Uses OpenCV Haar cascade (frontal face).
        Faces in phishing screenshots = identity-theft lure signal.

    Logo region detection (heuristic — no pretrained model required):
        Scans for compact, high-edge-density, saturated colour regions
        typical of corporate logos in phishing screenshots.

    Returns:
        {
          "available":        bool,
          "face_count":       int,
          "faces":            list[dict]  {"x","y","w","h"}
          "logo_regions":     list[dict]  {"x","y","w","h","edge_density","dominant_hue"}
          "risk_contribution": float  0-10
        }
    """
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

    # ── Face detection ───────────────────────────────────────────────────────
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

    # ── Logo region detection (heuristic) ────────────────────────────────────
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
                    hue_patch     = hsv[y:y+win_h, x:x+win_w, 0]
                    dominant_hue  = int(np.median(hue_patch))
                    logo_candidates.append({
                        "x": x, "y": y, "w": win_w, "h": win_h,
                        "edge_density": round(edge_density, 4),
                        "dominant_hue": dominant_hue,
                    })

        # Non-maximum suppression
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

    # ── Risk contribution ────────────────────────────────────────────────────
    risk = 0.0
    if result["face_count"] > 0:
        risk += min(result["face_count"] * 3.0, 6.0)
    if len(result["logo_regions"]) > 0:
        risk += min(len(result["logo_regions"]) * 1.5, 4.0)
    result["risk_contribution"] = round(risk, 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — EXIF METADATA EXTRACTOR  (NEW)
# ══════════════════════════════════════════════════════════════════════════════

def extract_exif(img, file_bytes: bytes) -> dict:
    """
    Extract EXIF metadata and flag anomalies relevant to phishing / forgery.

    Anomaly flags:
      future_timestamp    — DateTimeOriginal is in the future
      no_device_info      — No Make/Model (unusual for a real camera photo)
      software_edited     — Software field is set
      ai_generated_hint   — Software field contains AI generator names
      gps_present         — GPS coordinates embedded
      timestamp_mismatch  — DateTimeOriginal vs DateTime differ by > 24 h

    Returns:
        {
          "available":          bool,
          "raw":                dict,
          "flags":              list[str],
          "gps":                dict | None  {"lat":float,"lon":float}
          "software":           str,
          "make":               str,
          "model":              str,
          "datetime_original":  str,
          "risk_contribution":  float  0-8
        }
    """
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
    dt_mod   = str(human.get("DateTime",          "")).strip()

    result.update({"software": software, "make": make, "model": model,
                   "datetime_original": dt_orig})

    # ── GPS ──────────────────────────────────────────────────────────────────
    gps_info = exif_data.get(34853)
    if gps_info:
        try:
            def _deg(vals):
                return float(vals[0]) + float(vals[1]) / 60.0 + float(vals[2]) / 3600.0
            lat = _deg(gps_info.get(2, [0, 0, 0]))
            lon = _deg(gps_info.get(4, [0, 0, 0]))
            if gps_info.get(1, "N") == "S":
                lat = -lat
            if gps_info.get(3, "E") == "W":
                lon = -lon
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
            fmt = "%Y:%m:%d %H:%M:%S"
            d1  = datetime.datetime.strptime(dt_orig, fmt)
            d2  = datetime.datetime.strptime(dt_mod,  fmt)
            if abs((d1 - d2).total_seconds()) > 86400:
                result["flags"].append("timestamp_mismatch")
                risk += 1.0
        except Exception:
            pass

    result["risk_contribution"] = round(min(risk, 8.0), 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# ML CLASSIFIER  (FIX 1: returns INSUFFICIENT_DATA instead of UNKNOWN)
# ══════════════════════════════════════════════════════════════════════════════

def run_classifier(text: str) -> dict:
    """
    Run the email phishing classifier (DistilBERT) on extracted OCR text.
    Returns INSUFFICIENT_DATA (not UNKNOWN) when text is too short —
    the caller will synthesise a label from other signals via
    _derive_classifier_fallback().
    """
    if not text or len(text.strip()) < MIN_OCR_CHARS:
        return {"label": "INSUFFICIENT_DATA", "score": 0.0}

    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("email_classifier")
        if pipeline is None:
            return {"label": "INSUFFICIENT_DATA", "score": 0.0}

        output = pipeline(text[:512], truncation=True, max_length=512)
        if isinstance(output, list):
            output = output[0]

        label = output.get("label", "UNKNOWN").upper()
        score = float(output.get("score", 0.0))

        if any(kw in label for kw in ("PHISH", "SPAM", "MALICIOUS", "FAKE")):
            return {"label": "PHISHING", "score": score}
        elif any(kw in label for kw in ("SAFE", "LEGITIMATE", "BENIGN", "REAL")):
            return {"label": "SAFE", "score": score}
        else:
            return {"label": label, "score": score}

    except Exception as ex:
        logger.warning("Classifier failed on OCR text: %s", ex)
        return {"label": "INSUFFICIENT_DATA", "score": 0.0}


def _derive_classifier_fallback(
    brands: list,
    keywords: list,
    qr_result: dict,
) -> dict:
    """
    FIX 1 (core): Synthesise a classifier label from brand, keyword, and QR
    signals when BERT cannot run due to insufficient OCR text.

    Label hierarchy:
      PHISHING   — malicious QR URL present, OR (2+ brands AND 2+ keywords)
      SUSPICIOUS — suspicious QR URL, OR any brand + any keyword, OR 3+ keywords
      NO_TEXT    — no signals at all
    """
    has_malicious_qr  = len(qr_result.get("malicious_urls",  [])) > 0
    has_suspicious_qr = len(qr_result.get("suspicious_urls", [])) > 0
    n_brands   = len(brands)
    n_keywords = len(keywords)

    if has_malicious_qr:
        return {"label": "PHISHING",  "score": 0.85,
                "note": "Malicious QR code URL detected — OCR insufficient for BERT"}
    if (n_brands >= 2 and n_keywords >= 2) or (n_brands >= 1 and n_keywords >= 3):
        return {"label": "PHISHING",  "score": 0.70,
                "note": "Brand + phishing keyword combination — OCR insufficient for BERT"}
    if has_suspicious_qr or (n_brands >= 1 and n_keywords >= 1) or n_keywords >= 3:
        return {"label": "SUSPICIOUS", "score": 0.50,
                "note": "Brand/keyword/QR signals present — OCR insufficient for BERT"}
    if n_brands >= 1:
        return {"label": "SUSPICIOUS", "score": 0.35,
                "note": "Brand name detected in image — OCR insufficient for BERT"}

    return {"label": "NO_TEXT", "score": 0.0,
            "note": "Insufficient text extracted from image for classification"}


# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING  (FIX 3: all four new modules included)
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
    # NO_TEXT / INSUFFICIENT_DATA → 0 additional (other signals carry it)

    score += min(len(brands)   * 12.0, 24.0)
    score += min(len(keywords) * 8.0,  32.0)

    url_hits = len(re.findall(r"https?://", ocr_text, re.IGNORECASE))
    score += min(url_hits * 3.0, 12.0)

    score += qr_result.get("risk_contribution",      0.0)
    score += stego_result.get("risk_contribution",   0.0)
    score += face_logo_result.get("risk_contribution", 0.0)
    score += exif_result.get("risk_contribution",    0.0)

    return min(round(score, 1), 100.0)


def _determine_verdict(score: float) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "CLEAN"


# ══════════════════════════════════════════════════════════════════════════════
# EXPLANATION BUILDER  (FIX 4: covers all new modules)
# ══════════════════════════════════════════════════════════════════════════════

def _build_explanation(
    verdict: str,
    score: float,
    brands: list,
    keywords: list,
    classifier_result: dict,
    ocr_available: bool,
    qr_result: dict,
    stego_result: dict,
    face_logo_result: dict,
    exif_result: dict,
) -> str:
    parts = []

    if not ocr_available:
        parts.append(
            "OCR is not available — install pytesseract and Tesseract "
            "for full text extraction."
        )

    clf_label = classifier_result.get("label", "UNKNOWN")
    clf_pct   = int(classifier_result.get("score", 0.0) * 100)
    note      = classifier_result.get("note", "")

    if clf_label == "PHISHING":
        parts.append(
            (f"Phishing signals detected: {note}" if note else
             f"Phishing classifier flagged extracted text ({clf_pct}% confidence).")
        )
    elif clf_label == "SUSPICIOUS":
        parts.append(
            f"Suspicious signals detected. {note}" if note else
            f"Classifier returned suspicious ({clf_pct}% confidence)."
        )
    elif clf_label in ("INSUFFICIENT_DATA", "NO_TEXT") and note:
        parts.append(note)

    if brands:
        parts.append(
            f"Brand name(s) detected: {', '.join(brands)} — possible spoofing attempt."
        )

    if keywords:
        parts.append(f"{len(keywords)} phishing keyword(s) found in image text.")

    # QR codes
    if qr_result.get("codes"):
        n   = len(qr_result["codes"])
        mal = qr_result.get("malicious_urls",  [])
        sus = qr_result.get("suspicious_urls", [])
        parts.append(
            f"{n} QR/barcode(s) detected."
            + (f" {len(mal)} URL(s) classified as malicious." if mal else "")
            + (f" {len(sus)} URL(s) flagged as suspicious."   if sus else "")
        )

    # Steganography
    if stego_result.get("suspicious"):
        conf = stego_result.get("confidence", "low")
        parts.append(
            f"Steganography analysis flagged hidden-data patterns "
            f"({conf} confidence) — LSB entropy or chi-square anomaly detected."
        )

    # Faces
    if face_logo_result.get("face_count", 0) > 0:
        parts.append(
            f"{face_logo_result['face_count']} face(s) detected — "
            f"may indicate an identity-lure phishing screenshot."
        )

    # EXIF anomalies
    exif_flags = exif_result.get("flags", [])
    if "future_timestamp" in exif_flags:
        parts.append("EXIF timestamp is in the future — image metadata may be forged.")
    if "ai_generated_hint" in exif_flags:
        sw = exif_result.get("software", "")
        parts.append(
            f"Image EXIF suggests AI generation or heavy editing (Software: {sw})."
        )
    if "gps_present" in exif_flags:
        gps = exif_result.get("gps") or {}
        parts.append(
            f"GPS coordinates embedded in EXIF "
            f"({gps.get('lat','?')}, {gps.get('lon','?')})."
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
        "risk_score":         5.0,
        "verdict":            "CLEAN",
        "explanation":        "",
        "error":              None,
        "ocr_available":      TESS_AVAILABLE and PIL_AVAILABLE,
    }

    # ── Size guard ───────────────────────────────────────────────────────────
    if len(file_bytes) > MAX_IMAGE_BYTES:
        result["error"] = "File too large (max 20 MB)."
        result["explanation"] = result["error"]
        return result

    if not PIL_AVAILABLE:
        result["error"] = "Pillow not installed — cannot process image."
        result["explanation"] = result["error"]
        return result

    # ── Load image ───────────────────────────────────────────────────────────
    img = load_image(file_bytes, filename)
    if img is None:
        result["error"] = "Could not open image — unsupported format or corrupt file."
        result["explanation"] = result["error"]
        return result

    # ── Metadata ─────────────────────────────────────────────────────────────
    meta = get_image_metadata(img)
    result["image_width"]  = meta["width"]
    result["image_height"] = meta["height"]
    result["image_format"] = meta["format"]

    # ── OCR (with preprocessing) ─────────────────────────────────────────────
    ocr_text = run_ocr(img)
    result["ocr_text"]       = ocr_text
    result["ocr_word_count"] = len(ocr_text.split()) if ocr_text else 0

    # ── Brand detection ──────────────────────────────────────────────────────
    result["detected_brands"]   = detect_brands(ocr_text)

    # ── Phishing keyword scan ────────────────────────────────────────────────
    result["phishing_keywords"] = detect_phishing_keywords(ocr_text)

    # ── QR Code detection ────────────────────────────────────────────────────
    result["qr_codes"] = detect_qr_codes(img)

    # ── Steganography detection ──────────────────────────────────────────────
    result["steganography"] = detect_steganography(img)

    # ── Face & logo detection ─────────────────────────────────────────────────
    result["face_logo"] = detect_faces_and_logos(img)

    # ── EXIF metadata extraction ──────────────────────────────────────────────
    result["exif"] = extract_exif(img, file_bytes)

    # ── ML classifier ────────────────────────────────────────────────────────
    clf = run_classifier(ocr_text)

    # FIX 1: BERT couldn't run → derive label from other signals
    if clf["label"] == "INSUFFICIENT_DATA":
        clf = _derive_classifier_fallback(
            result["detected_brands"],
            result["phishing_keywords"],
            result["qr_codes"],
        )

    result["classifier_result"] = clf

    # ── Risk score + verdict ─────────────────────────────────────────────────
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

    # ── Explanation ──────────────────────────────────────────────────────────
    result["explanation"] = _build_explanation(
        result["verdict"],
        result["risk_score"],
        result["detected_brands"],
        result["phishing_keywords"],
        clf,
        result["ocr_available"],
        result["qr_codes"],
        result["steganography"],
        result["face_logo"],
        result["exif"],
    )

    return result