# image_detector.py
# Image-Based Phishing Detection Module — Phase 7.
#
# Pipeline:
#   1. Load image bytes → PIL Image + OpenCV array
#   2. Tesseract OCR   → extract all visible text
#   3. DistilBERT      → classify extracted text as phishing / safe
#   4. OpenCV          → detect form elements (input fields, buttons)
#   5. ViT classifier  → brand impersonation detection
#   6. Aggregate       → final verdict + risk score

import io
import re
import logging
import base64
import platform
import os
from typing import Optional

# ── Safe OpenCV import ────────────────────────────────────────────────────────
try:
    import cv2 # pyright: ignore[reportMissingImports]
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    cv2           = None
    np            = None
    CV2_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "cv2 not found — OpenCV form detection disabled. "
        "Fix: pip install opencv-python-headless==4.8.1.78"
    )

# ── Safe Pillow import ────────────────────────────────────────────────────────
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    Image         = None
    PIL_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "Pillow not found. Fix: pip install Pillow==10.3.0"
    )

# ── Safe Tesseract import ─────────────────────────────────────────────────────
try:
    import pytesseract

    # Windows — automatically find the Tesseract binary
    if platform.system() == "Windows":
        win_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            r"C:\Users\{}\AppData\Local\Programs\Tesseract-OCR\tesseract.exe".format(
                os.environ.get("USERNAME", "")
            ),
        ]
        for p in win_paths:
            if os.path.exists(p):
                pytesseract.pytesseract.tesseract_cmd = p
                break

    TESSERACT_AVAILABLE = True
except ImportError:
    pytesseract         = None
    TESSERACT_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "pytesseract not found. Fix: pip install pytesseract==0.3.10"
    )

from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

BRAND_KEYWORDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "github", "bank", "chase", "wellsfargo", "citibank", "barclays",
    "hsbc", "dhl", "fedex", "ups", "usps", "adobe", "office",
    "outlook", "gmail", "yahoo", "icloud", "whatsapp", "telegram"
]

PHISHING_TEXT_KEYWORDS = [
    "password", "username", "sign in", "log in", "login",
    "verify", "confirm", "update", "account", "security",
    "enter your", "please enter", "credit card", "social security",
    "bank account", "billing", "payment", "expired", "suspended",
    "unauthorized", "verify now", "action required", "click here"
]


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze_image(image_bytes: bytes, filename: str = "image.png") -> dict:
    """
    Run the full image phishing detection pipeline.

    Args:
        image_bytes: Raw image file bytes.
        filename:    Original filename for reference.

    Returns:
        Structured result dict with all sub-module findings,
        a 0-100 risk score, verdict, and explanation.
    """
    logger.info(f"Analyzing image: {filename} ({len(image_bytes)} bytes)")

    # Step 1: Load image
    pil_image, cv_image = _load_image(image_bytes)

    if pil_image is None:
        return _error_result(filename, "Could not load image — unsupported format")

    image_info = {
        "filename":  filename,
        "width":     pil_image.width,
        "height":    pil_image.height,
        "mode":      pil_image.mode,
        "file_size": len(image_bytes)
    }

    # Step 2: Tesseract OCR
    ocr_result = _run_ocr(pil_image)

    # Step 3: DistilBERT on extracted text
    distilbert_result = _classify_text_distilbert(ocr_result["text"])

    # Step 4: OpenCV form detection
    opencv_result = _detect_form_elements(cv_image, pil_image)

    # Step 5: ViT brand impersonation
    vit_result = _classify_image_vit(pil_image)

    # Step 6: Keyword check on OCR text
    keyword_result = _check_phishing_keywords(ocr_result["text"])

    # Step 7: Aggregate risk
    risk_score, flags, verdict = _aggregate_risk(
        distilbert_result=distilbert_result,
        opencv_result=opencv_result,
        vit_result=vit_result,
        keyword_result=keyword_result,
        ocr_text=ocr_result["text"]
    )

    explanation = _build_explanation(
        verdict, flags, distilbert_result, opencv_result, vit_result
    )

    return {
        "filename":          filename,
        "image_info":        image_info,
        "ocr_result":        ocr_result,
        "distilbert_result": distilbert_result,
        "opencv_result":     opencv_result,
        "vit_result":        vit_result,
        "keyword_result":    keyword_result,
        "risk_score":        risk_score,
        "verdict":           verdict,
        "flags":             flags,
        "explanation":       explanation
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Image loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_image(image_bytes: bytes):
    """
    Load image bytes into PIL Image and OpenCV numpy array.
    Returns (None, None) on failure — never raises.
    """
    if not PIL_AVAILABLE:
        logger.error("Pillow not available")
        return None, None

    try:
        pil_image = Image.open(io.BytesIO(image_bytes))

        # Normalize to RGB so all downstream steps work uniformly
        if pil_image.mode not in ("RGB", "L"):
            pil_image = pil_image.convert("RGB")

        # Build OpenCV image only if cv2 is available
        cv_image = None
        if CV2_AVAILABLE:
            cv_array = np.array(pil_image)
            if len(cv_array.shape) == 3:
                # PIL is RGB, OpenCV expects BGR
                cv_image = cv2.cvtColor(cv_array, cv2.COLOR_RGB2BGR)
            else:
                cv_image = cv_array

        return pil_image, cv_image

    except Exception as e:
        logger.error(f"Image load failed: {e}")
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Tesseract OCR
# ─────────────────────────────────────────────────────────────────────────────

def _run_ocr(pil_image) -> dict:
    """
    Extract all visible text from the image using Tesseract OCR.
    Returns an empty text dict if Tesseract is not installed.
    """
    result = {
        "text":       "",
        "word_count": 0,
        "confidence": 0.0,
        "error":      None
    }

    if not TESSERACT_AVAILABLE:
        result["error"] = (
            "Tesseract not installed. "
            "Windows: https://github.com/UB-Mannheim/tesseract/wiki "
            "Linux: sudo apt install tesseract-ocr"
        )
        return result

    if pil_image is None:
        result["error"] = "No image available for OCR"
        return result

    try:
        ocr_data = pytesseract.image_to_data(
            pil_image,
            config="--psm 3 --oem 3",
            output_type=pytesseract.Output.DICT
        )

        words       = []
        confidences = []

        for i, word in enumerate(ocr_data["text"]):
            conf = int(ocr_data["conf"][i])
            if conf > 30 and word.strip():
                words.append(word.strip())
                confidences.append(conf)

        result["text"]       = " ".join(words)
        result["word_count"] = len(words)
        result["confidence"] = (
            round(sum(confidences) / len(confidences), 1)
            if confidences else 0.0
        )

    except pytesseract.TesseractNotFoundError:
        result["error"] = (
            "Tesseract binary not found. "
            "Windows: install from https://github.com/UB-Mannheim/tesseract/wiki"
        )
        logger.error(result["error"])

    except Exception as e:
        result["error"] = f"OCR error: {str(e)[:100]}"
        logger.error(f"Tesseract OCR failed: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — DistilBERT text classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_text_distilbert(text: str) -> dict:
    """
    Classify OCR-extracted text using the DistilBERT phishing model.
    Reuses the email_classifier model from Phase 1.
    """
    fallback = {
        "label": "UNKNOWN",
        "score": 0.0,
        "model": "fallback_rule_based",
        "note":  "insufficient_text"
    }

    if not text or len(text.strip()) < 10:
        return fallback

    model = get_model("email_classifier")
    if model is None:
        logger.warning("email_classifier not loaded — OCR text unclassified")
        return fallback

    try:
        truncated = text.strip()[:1500]
        results   = model(truncated)
        top       = results[0]
        raw_label = top["label"].upper()

        if "PHISH" in raw_label or raw_label in ("LABEL_1", "1"):
            normalized = "PHISHING"
        elif "SAFE" in raw_label or "LEGIT" in raw_label or raw_label in ("LABEL_0", "0"):
            normalized = "SAFE"
        else:
            normalized = raw_label

        return {
            "label": normalized,
            "score": round(float(top["score"]), 4),
            "model": "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        }

    except Exception as e:
        logger.error(f"DistilBERT on OCR text failed: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — OpenCV form element detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_form_elements(cv_image, pil_image) -> dict:
    """
    Use OpenCV to detect input fields and buttons in the image.
    Phishing pages almost always contain credential harvesting forms.
    """
    # Safe fallback when OpenCV is not available
    if not CV2_AVAILABLE:
        return {
            "input_fields_detected": 0,
            "buttons_detected":      0,
            "total_rectangles":      0,
            "has_password_region":   False,
            "is_likely_login_page":  False,
            "regions":               [],
            "error": (
                "OpenCV not available. "
                "Fix: pip install opencv-python-headless==4.8.1.78"
            )
        }

    if cv_image is None:
        return {
            "input_fields_detected": 0,
            "buttons_detected":      0,
            "total_rectangles":      0,
            "has_password_region":   False,
            "is_likely_login_page":  False,
            "regions":               [],
            "error":                 "No OpenCV image available"
        }

    result = {
        "input_fields_detected": 0,
        "buttons_detected":      0,
        "total_rectangles":      0,
        "has_password_region":   False,
        "is_likely_login_page":  False,
        "regions":               [],
        "error":                 None
    }

    try:
        img_h, img_w = cv_image.shape[:2]

        # Convert to grayscale
        gray = (
            cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            if len(cv_image.shape) == 3
            else cv_image
        )

        # Blur and threshold
        blurred = cv2.GaussianBlur(gray, (3, 3), 0)
        thresh  = cv2.adaptiveThreshold(
            blurred, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV,
            11, 2
        )

        # Find contours
        contours, _ = cv2.findContours(
            thresh,
            cv2.RETR_EXTERNAL,
            cv2.CHAIN_APPROX_SIMPLE
        )

        input_fields = 0
        buttons      = 0
        regions      = []

        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)

            # Skip noise and full-page borders
            if w < 50 or h < 8:
                continue
            if w > img_w * 0.95 or h > img_h * 0.8:
                continue
            if (w * h) / (img_w * img_h) < 0.002:
                continue

            aspect_ratio = w / max(h, 1)
            region_type  = None

            # Input field: wide and short
            if 3.0 <= aspect_ratio <= 20.0 and 15 <= h <= 80:
                region_type   = "input_field"
                input_fields += 1

            # Button: moderate aspect ratio
            elif 1.5 <= aspect_ratio <= 8.0 and 25 <= h <= 70:
                region_type = "button"
                buttons    += 1

            if region_type:
                regions.append({
                    "type":         region_type,
                    "x":            int(x),
                    "y":            int(y),
                    "width":        int(w),
                    "height":       int(h),
                    "aspect_ratio": round(aspect_ratio, 2)
                })

        result["input_fields_detected"] = input_fields
        result["buttons_detected"]      = buttons
        result["total_rectangles"]      = len(regions)
        result["regions"]               = regions[:20]
        result["is_likely_login_page"]  = input_fields >= 1 and buttons >= 1
        result["has_password_region"]   = input_fields >= 2

    except Exception as e:
        result["error"] = f"OpenCV error: {str(e)[:100]}"
        logger.error(f"OpenCV form detection failed: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — ViT brand impersonation classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_image_vit(pil_image) -> dict:
    """
    Run the ViT image classifier to detect brand impersonation.
    Model: google/vit-base-patch16-224
    """
    result = {
        "top_predictions":  [],
        "brand_detected":   None,
        "brand_confidence": 0.0,
        "is_impersonation": False,
        "available":        False,
        "model":            "google/vit-base-patch16-224"
    }

    if pil_image is None:
        result["note"] = "No image available"
        return result

    model = get_model("image_classifier")
    if model is None:
        result["note"] = "ViT model not loaded"
        return result

    try:
        predictions = model(pil_image, top_k=5)

        top_preds = [
            {
                "label": p.get("label", ""),
                "score": round(float(p.get("score", 0.0)), 4)
            }
            for p in predictions
        ]

        result["top_predictions"] = top_preds
        result["available"]       = True

        # Check predictions for brand keywords
        for pred in top_preds:
            label_lower = pred["label"].lower()
            for brand in BRAND_KEYWORDS:
                if brand in label_lower:
                    result["brand_detected"]   = brand
                    result["brand_confidence"] = pred["score"]
                    result["is_impersonation"] = pred["score"] > 0.15
                    break
            if result["brand_detected"]:
                break

    except Exception as e:
        result["note"] = f"ViT inference error: {str(e)[:100]}"
        logger.error(f"ViT classification failed: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Phishing keyword check
# ─────────────────────────────────────────────────────────────────────────────

def _check_phishing_keywords(text: str) -> dict:
    """Check OCR text for brand and phishing indicator keywords."""
    if not text:
        return {
            "brand_keywords_found":    [],
            "phishing_keywords_found": [],
            "keyword_score":           0.0
        }

    text_lower     = text.lower()
    brand_found    = [b for b in BRAND_KEYWORDS        if b in text_lower]
    phishing_found = [p for p in PHISHING_TEXT_KEYWORDS if p in text_lower]

    score = min(len(brand_found) * 5 + len(phishing_found) * 3, 30)

    return {
        "brand_keywords_found":    brand_found[:10],
        "phishing_keywords_found": phishing_found[:10],
        "keyword_score":           float(score)
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Risk aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_risk(
    distilbert_result: dict,
    opencv_result:     dict,
    vit_result:        dict,
    keyword_result:    dict,
    ocr_text:          str
) -> tuple:
    """
    Combine all signals into a final risk score (0-100), flags, and verdict.

    Scoring:
      DistilBERT:  up to 40 pts
      OpenCV:      up to 25 pts
      ViT:         up to 20 pts
      Keywords:    up to 15 pts
    """
    score = 0.0
    flags = []

    # DistilBERT
    dist_label = distilbert_result.get("label", "UNKNOWN")
    dist_score = distilbert_result.get("score", 0.0)

    if dist_label == "PHISHING":
        score += dist_score * 40
        flags.append(
            f"DISTILBERT_PHISHING ({int(dist_score * 100)}% confidence)"
        )
    elif not ocr_text.strip():
        flags.append("NO_TEXT_EXTRACTED")

    # OpenCV
    if opencv_result.get("is_likely_login_page"):
        score += 20
        flags.append(
            f"LOGIN_FORM_DETECTED "
            f"({opencv_result.get('input_fields_detected', 0)} inputs, "
            f"{opencv_result.get('buttons_detected', 0)} buttons)"
        )

    if opencv_result.get("has_password_region"):
        score += 5
        flags.append("PASSWORD_FIELD_LIKELY")

    # ViT
    if vit_result.get("is_impersonation"):
        brand = vit_result.get("brand_detected", "unknown")
        conf  = vit_result.get("brand_confidence", 0.0)
        score += 20
        flags.append(
            f"BRAND_IMPERSONATION ({brand}, {int(conf * 100)}%)"
        )
    elif vit_result.get("brand_detected"):
        score += 8
        flags.append(f"BRAND_ELEMENT ({vit_result.get('brand_detected')})")

    # Keywords
    kw_score = keyword_result.get("keyword_score", 0.0)
    score   += min(kw_score, 15)

    if keyword_result.get("brand_keywords_found"):
        flags.append(
            "BRAND_KEYWORDS: " +
            ", ".join(keyword_result["brand_keywords_found"][:3])
        )
    if keyword_result.get("phishing_keywords_found"):
        flags.append(
            "PHISHING_KEYWORDS: " +
            ", ".join(keyword_result["phishing_keywords_found"][:3])
        )

    final_score = round(min(score, 100.0), 2)

    if final_score >= 70:
        verdict = "Malicious"
    elif final_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return final_score, flags, verdict


# ─────────────────────────────────────────────────────────────────────────────
# Explanation builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_explanation(
    verdict:           str,
    flags:             list,
    distilbert_result: dict,
    opencv_result:     dict,
    vit_result:        dict
) -> str:
    parts = [f"Image assessed as {verdict}."]

    if distilbert_result.get("label") == "PHISHING":
        conf = int(distilbert_result.get("score", 0) * 100)
        parts.append(
            f"OCR text classified as phishing by DistilBERT "
            f"({conf}% confidence)."
        )

    if opencv_result.get("is_likely_login_page"):
        parts.append(
            f"Login form detected: "
            f"{opencv_result.get('input_fields_detected', 0)} input field(s), "
            f"{opencv_result.get('buttons_detected', 0)} button(s)."
        )

    if vit_result.get("is_impersonation"):
        parts.append(
            f"ViT detected brand impersonation: "
            f"'{vit_result.get('brand_detected', 'unknown brand')}'."
        )

    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Error result
# ─────────────────────────────────────────────────────────────────────────────

def _error_result(filename: str, message: str) -> dict:
    """Return a safe error result when image loading fails."""
    return {
        "filename":          filename,
        "image_info":        {},
        "ocr_result":        {
            "text": "", "word_count": 0,
            "confidence": 0.0, "error": message
        },
        "distilbert_result": {
            "label": "UNKNOWN", "score": 0.0, "model": "none"
        },
        "opencv_result":     {
            "is_likely_login_page": False,
            "input_fields_detected": 0,
            "buttons_detected": 0,
            "regions": [], "error": message
        },
        "vit_result":        {
            "top_predictions": [], "brand_detected": None,
            "is_impersonation": False, "available": False
        },
        "keyword_result":    {
            "brand_keywords_found": [],
            "phishing_keywords_found": [],
            "keyword_score": 0.0
        },
        "risk_score":        0.0,
        "verdict":           "Unknown",
        "flags":             ["IMAGE_LOAD_ERROR"],
        "explanation":       f"Image analysis failed: {message}"
    }