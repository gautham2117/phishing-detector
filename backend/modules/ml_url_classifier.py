# ml_url_classifier.py
# ML-Based Phishing URL Classifier — soft-voting ensemble.
#
# Two classifiers are combined:
#
#   Classifier 1 — scikit-learn Random Forest
#     Input:  24-dimensional feature vector from feature_extractor.py
#     Output: probability score (0.0–1.0) for phishing
#     Speed:  ~0.5ms per URL (pure CPU, no GPU needed)
#
#   Classifier 2 — ealvaradob/bert-finetuned-phishing (HuggingFace)
#     Input:  raw URL string
#     Output: probability score (0.0–1.0) for phishing
#     Speed:  ~50–200ms per URL on CPU
#
#   Ensemble (soft voting):
#     final_score = (rf_weight * rf_prob) + (bert_weight * bert_prob)
#     Default weights: RF=0.45, BERT=0.55
#     BERT gets slightly more weight as it understands URL semantics.
#     If BERT is unavailable, falls back to RF alone with weight=1.0.

import os
import pickle
import logging
from typing import Optional

import numpy as np

from backend.ml.feature_extractor import extract_features
from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Model paths
# ─────────────────────────────────────────────────────────────────────────────

_this_dir  = os.path.dirname(os.path.abspath(__file__))
_ml_dir    = os.path.join(os.path.dirname(_this_dir), "ml")
RF_MODEL_PATH = os.path.join(_ml_dir, "models", "rf_url_classifier_v1.pkl")

# ─────────────────────────────────────────────────────────────────────────────
# Random Forest loader (loaded once, cached in module scope)
# ─────────────────────────────────────────────────────────────────────────────

_rf_model = None
_rf_loaded = False


def _load_rf_model():
    """
    Load the Random Forest model from disk.
    Called lazily on first use — the model is cached after first load.
    Returns the model or None if loading fails.
    """
    global _rf_model, _rf_loaded

    if _rf_loaded:
        return _rf_model

    _rf_loaded = True   # mark as attempted regardless of success

    if not os.path.exists(RF_MODEL_PATH):
        logger.warning(
            f"RF model not found at {RF_MODEL_PATH}. "
            f"Run: python -m backend.ml.train_url_classifier"
        )
        _rf_model = None
        return None

    try:
        with open(RF_MODEL_PATH, "rb") as f:
            _rf_model = pickle.load(f)
        logger.info(f"Random Forest model loaded from {RF_MODEL_PATH}")
        return _rf_model

    except Exception as e:
        logger.error(f"Failed to load RF model: {e}")
        _rf_model = None
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Main classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_url(url: str,
                 rf_weight: float = 0.45,
                 bert_weight: float = 0.55) -> dict:
    """
    Classify a URL using the soft-voting ensemble of RF + BERT.

    Args:
        url:         Raw URL string to classify.
        rf_weight:   Weight for the Random Forest score (0.0–1.0).
        bert_weight: Weight for the BERT score (0.0–1.0).
                     rf_weight + bert_weight should equal 1.0.

    Returns:
        {
          "url":            str,
          "rf_result":      {score, label, available},
          "bert_result":    {score, label, available},
          "ensemble_score": float,   # 0.0–1.0
          "ensemble_label": str,     # PHISHING / LEGITIMATE
          "ensemble_confidence": float,  # how far from 0.5 threshold
          "weights_used":   {rf, bert},
          "explanation":    str
        }
    """
    rf_result   = _classify_with_rf(url)
    bert_result = _classify_with_bert(url)

    # ── Soft voting ────────────────────────────────────────────────────────
    # If only one model is available, use it with full weight
    if rf_result["available"] and bert_result["available"]:
        ensemble_score = (
            rf_weight   * rf_result["score"] +
            bert_weight * bert_result["score"]
        )
        weights_used = {"rf": rf_weight, "bert": bert_weight}

    elif rf_result["available"]:
        ensemble_score = rf_result["score"]
        weights_used   = {"rf": 1.0, "bert": 0.0}
        logger.info("BERT unavailable — using RF only")

    elif bert_result["available"]:
        ensemble_score = bert_result["score"]
        weights_used   = {"rf": 0.0, "bert": 1.0}
        logger.info("RF unavailable — using BERT only")

    else:
        # Both models unavailable — return neutral result
        return _fallback_result(url, "Both classifiers unavailable")

    ensemble_score = round(float(ensemble_score), 4)

    # ── Final label ────────────────────────────────────────────────────────
    # Threshold 0.5: above = phishing, below = legitimate
    ensemble_label = "PHISHING" if ensemble_score >= 0.5 else "LEGITIMATE"

    # Confidence = distance from the 0.5 decision boundary
    ensemble_confidence = round(abs(ensemble_score - 0.5) * 2, 4)

    explanation = _build_explanation(
        url, rf_result, bert_result,
        ensemble_score, ensemble_label
    )

    return {
        "url":                url,
        "rf_result":          rf_result,
        "bert_result":        bert_result,
        "ensemble_score":     ensemble_score,
        "ensemble_label":     ensemble_label,
        "ensemble_confidence":ensemble_confidence,
        "weights_used":       weights_used,
        "explanation":        explanation
    }


def classify_url_batch(urls: list) -> list:
    """
    Classify a list of URLs.
    Returns a list of result dicts in the same order as the input.
    """
    return [classify_url(url) for url in urls]


# ─────────────────────────────────────────────────────────────────────────────
# Classifier 1 — Random Forest
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_rf(url: str) -> dict:
    """
    Run the scikit-learn Random Forest on the URL feature vector.

    Returns:
        {
          "score":     float,   # probability of phishing (0.0–1.0)
          "label":     str,     # PHISHING / LEGITIMATE
          "available": bool
        }
    """
    rf = _load_rf_model()

    if rf is None:
        return {"score": 0.5, "label": "UNKNOWN", "available": False,
                "note": "Model not trained yet"}

    try:
        features = extract_features(url).reshape(1, -1)
        # predict_proba returns [[prob_legitimate, prob_phishing]]
        proba    = rf.predict_proba(features)[0]

        # Class 1 = phishing (as defined during training)
        phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        label         = "PHISHING" if phishing_prob >= 0.5 else "LEGITIMATE"

        return {
            "score":     round(phishing_prob, 4),
            "label":     label,
            "available": True
        }

    except Exception as e:
        logger.error(f"RF inference error: {e}")
        return {"score": 0.5, "label": "UNKNOWN", "available": False,
                "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Classifier 2 — ealvaradob/bert-finetuned-phishing
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_bert(url: str) -> dict:
    """
    Run the fine-tuned BERT phishing classifier on the raw URL string.

    Model: ealvaradob/bert-finetuned-phishing
    Task:  text-classification (binary: phishing vs legitimate)
    Input: raw URL string (truncated to 512 tokens)

    Returns:
        {
          "score":     float,
          "label":     str,
          "available": bool
        }
    """
    model = get_model("url_phishing_bert")

    if model is None:
        return {"score": 0.5, "label": "UNKNOWN", "available": False,
                "note": "BERT model not loaded"}

    try:
        # Truncate to 400 chars — safe limit for BERT's 512 token budget
        truncated = url[:400]
        results   = model(truncated)
        top       = results[0]

        raw_label = top["label"].upper()

        # Normalize label strings — model may return various formats
        if any(x in raw_label for x in ("PHISH", "LABEL_1", "1", "BAD", "MALICIOUS")):
            normalized = "PHISHING"
            score      = float(top["score"])
        elif any(x in raw_label for x in ("LEGIT", "BENIGN", "LABEL_0", "0", "SAFE")):
            normalized = "LEGITIMATE"
            # For LEGITIMATE labels, score = 1 - confidence
            # so that score always represents phishing probability
            score      = 1.0 - float(top["score"])
        else:
            normalized = raw_label
            score      = float(top["score"])

        return {
            "score":     round(score, 4),
            "label":     normalized,
            "available": True,
            "raw_label": raw_label,
            "raw_score": round(float(top["score"]), 4)
        }

    except Exception as e:
        logger.error(f"BERT inference error: {e}")
        return {"score": 0.5, "label": "UNKNOWN", "available": False,
                "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Explanation builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_explanation(url, rf_result, bert_result,
                        ensemble_score, label) -> str:
    parts = []

    if label == "PHISHING":
        parts.append(
            f"Ensemble classified URL as phishing "
            f"({int(ensemble_score * 100)}% phishing probability)."
        )
    else:
        parts.append(
            f"Ensemble classified URL as legitimate "
            f"({int((1-ensemble_score)*100)}% legitimate probability)."
        )

    if rf_result.get("available"):
        parts.append(
            f"Random Forest: {rf_result['label']} "
            f"({int(rf_result['score']*100)}%)."
        )

    if bert_result.get("available"):
        parts.append(
            f"BERT: {bert_result['label']} "
            f"({int(bert_result['score']*100)}%)."
        )

    if rf_result.get("available") and bert_result.get("available"):
        if rf_result["label"] != bert_result["label"]:
            parts.append(
                "Note: the two classifiers disagreed — "
                "ensemble weight resolved the conflict."
            )

    return " ".join(parts)


def _fallback_result(url: str, reason: str) -> dict:
    return {
        "url":                url,
        "rf_result":          {"score": 0.5, "label": "UNKNOWN", "available": False},
        "bert_result":        {"score": 0.5, "label": "UNKNOWN", "available": False},
        "ensemble_score":     0.5,
        "ensemble_label":     "UNKNOWN",
        "ensemble_confidence":0.0,
        "weights_used":       {"rf": 0.0, "bert": 0.0},
        "explanation":        f"Classification unavailable: {reason}"
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public helper — reload the RF model (used by Model Management page)
# ─────────────────────────────────────────────────────────────────────────────

def reload_rf_model() -> bool:
    """
    Force-reload the Random Forest model from disk.
    Called by the Model Management page after retraining.
    Returns True if successful, False otherwise.
    """
    global _rf_model, _rf_loaded
    _rf_loaded = False   # reset the cache flag
    model      = _load_rf_model()
    return model is not None


def get_rf_model_path() -> str:
    return RF_MODEL_PATH