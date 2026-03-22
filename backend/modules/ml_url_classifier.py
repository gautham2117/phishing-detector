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
#
# PHASE 5 ADDITION:
#   _compute_feature_contributions() — simplified permutation-based
#   feature attribution for individual RF predictions.
#   For each of the 24 features, the feature value is replaced with the
#   feature's mean across a reference distribution (neutral value), and
#   the delta in predicted phishing probability is measured. This gives a
#   directional contribution per feature for the specific URL being scored.
#   Returns 24 dicts sorted by absolute contribution descending.
#   Added as "feature_contributions" key in classify_url() return dict.

import os
import pickle
import logging
from typing import Optional

import numpy as np # pyright: ignore[reportMissingImports]

from backend.ml.feature_extractor import extract_features, FEATURE_NAMES
from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Model paths
# ─────────────────────────────────────────────────────────────────────────────

_this_dir     = os.path.dirname(os.path.abspath(__file__))
_ml_dir       = os.path.join(os.path.dirname(_this_dir), "ml")
RF_MODEL_PATH = os.path.join(_ml_dir, "models", "rf_url_classifier_v1.pkl")

# ─────────────────────────────────────────────────────────────────────────────
# Reference distribution for feature contribution baseline
# ─────────────────────────────────────────────────────────────────────────────
# These are representative neutral values for each of the 24 features.
# Used as the "mean" replacement in permutation-based attribution:
# when a feature is masked out, it is replaced with this neutral value.
#
# Values are calibrated to a typical "benign" URL baseline:
# e.g. https://example.com/page  (length ~25, 1 dot, no suspicious chars)
#
# Index order matches FEATURE_NAMES exactly.

_FEATURE_REFERENCE: list = [
    30.0,   # [0]  url_length          — typical short URL
    12.0,   # [1]  domain_length       — e.g. "example.com"
    5.0,    # [2]  path_length         — short path
    2.0,    # [3]  num_dots            — domain dot + TLD dot
    0.0,    # [4]  num_hyphens
    0.0,    # [5]  num_underscores
    2.0,    # [6]  num_slashes         — https://example.com/
    0.0,    # [7]  num_at_symbols
    0.0,    # [8]  num_question_marks
    0.0,    # [9]  num_equals
    0.0,    # [10] num_ampersands
    0.0,    # [11] num_digits
    0.0,    # [12] digit_ratio
    0.05,   # [13] special_char_ratio  — slashes/colons
    0.0,    # [14] subdomain_depth
    0.0,    # [15] has_ip_address
    1.0,    # [16] has_https           — assume HTTPS
    0.0,    # [17] has_http
    0.0,    # [18] is_shortener
    0.0,    # [19] has_suspicious_tld
    0.0,    # [20] has_at_in_domain
    0.0,    # [21] has_double_slash
    2.5,    # [22] domain_entropy      — moderate entropy
    1.5,    # [23] path_entropy        — low path entropy
]


# ─────────────────────────────────────────────────────────────────────────────
# Random Forest loader (loaded once, cached in module scope)
# ─────────────────────────────────────────────────────────────────────────────

_rf_model  = None
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
# Phase 5 — Feature contribution (permutation-based attribution)
# ─────────────────────────────────────────────────────────────────────────────

def _compute_feature_contributions(url: str, rf_model) -> list:
    """
    Compute per-feature contributions to the RF phishing prediction for
    a specific URL using a simplified permutation-based attribution method.

    Algorithm:
      1. Extract the 24-feature vector for the URL.
      2. Get the baseline predicted phishing probability (predict_proba).
      3. For each of the 24 features:
           a. Replace that feature's value with its reference/neutral value
              (see _FEATURE_REFERENCE — calibrated to a typical benign URL).
           b. Re-run predict_proba on the modified vector.
           c. contribution = baseline_prob − masked_prob
              Positive contribution → feature INCREASES phishing risk.
              Negative contribution → feature DECREASES phishing risk.
      4. Restore the feature and move to the next one.
      5. Return all 24 results sorted by |contribution| descending,
         capped at 50 entries (all 24 returned here).

    This is NOT full SHAP — it is a single-feature masking approach.
    It gives directional feature importance for the specific prediction
    without requiring the shap library.

    Args:
        url:      Raw URL string.
        rf_model: Loaded scikit-learn RandomForest model.

    Returns:
        List of 24 dicts sorted by abs(contribution) descending:
        [
          {
            "feature":    str,    feature name from FEATURE_NAMES
            "value":      float,  actual value for this URL
            "reference":  float,  neutral baseline value used for masking
            "contribution": float, baseline_prob − masked_prob
            "direction":  str,   "increases_risk" | "decreases_risk"
            "abs_contribution": float
          },
          ...
        ]
        Returns [] if rf_model is None or feature extraction fails.
    """
    if rf_model is None:
        return []

    try:
        features = extract_features(url)          # shape: (24,)
        vec      = features.reshape(1, -1)        # shape: (1, 24)

        # Baseline prediction — phishing probability with all real features
        proba_full = rf_model.predict_proba(vec)[0]
        # Class index 1 = phishing
        baseline_prob = float(proba_full[1]) if len(proba_full) > 1 else float(proba_full[0])

        contributions = []

        for i, feat_name in enumerate(FEATURE_NAMES):
            # Build a modified vector with feature i replaced by reference value
            masked     = vec.copy()
            actual_val = float(masked[0, i])
            ref_val    = float(_FEATURE_REFERENCE[i])
            masked[0, i] = ref_val

            # Predict with masked feature
            proba_masked  = rf_model.predict_proba(masked)[0]
            masked_prob   = float(proba_masked[1]) if len(proba_masked) > 1 else float(proba_masked[0])

            # contribution > 0 means this feature pushes toward phishing
            # contribution < 0 means this feature pushes toward benign
            contribution = round(baseline_prob - masked_prob, 6)

            contributions.append({
                "feature":          feat_name,
                "value":            round(actual_val, 6),
                "reference":        round(ref_val,    6),
                "contribution":     contribution,
                "direction":        "increases_risk" if contribution >= 0 else "decreases_risk",
                "abs_contribution": round(abs(contribution), 6),
            })

        # Sort by absolute contribution descending — most impactful first
        contributions.sort(key=lambda x: x["abs_contribution"], reverse=True)
        return contributions

    except Exception as e:
        logger.error(f"Feature contribution computation failed for {url[:60]}: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Trusted domain allowlist for the ML classifier
# ─────────────────────────────────────────────────────────────────────────────
# Mirrors the list in scan_router.py _extract_url_risk().
# When classify_url() is called for a trusted domain, both the RF and BERT
# scores are overridden to 0.05 (LEGITIMATE) and ensemble_score = 0.05.
# This prevents known-good platforms from being labelled PHISHING by models
# with poor calibration on short, common URLs (e.g. linkedin.com/feed → 98%).

_ML_TRUSTED_DOMAINS: frozenset = frozenset({
    "linkedin.com", "twitter.com", "x.com", "facebook.com",
    "instagram.com", "reddit.com", "tiktok.com", "youtube.com",
    "pinterest.com", "snapchat.com", "discord.com", "slack.com",
    "whatsapp.com", "telegram.org", "signal.org",
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "gmail.com", "outlook.com", "office.com", "microsoft.com",
    "apple.com", "icloud.com", "amazon.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "npmjs.com", "pypi.org",
    "docker.com", "kubernetes.io", "digitalocean.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "wikipedia.org", "bbc.com", "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com",
})


def _is_ml_trusted(url: str) -> bool:
    """Return True when the URL's apex domain is in the trusted allowlist."""
    from urllib.parse import urlparse
    try:
        netloc = urlparse(url).netloc.lower().lstrip("www.").split(":")[0]
        if netloc in _ML_TRUSTED_DOMAINS:
            return True
        for apex in _ML_TRUSTED_DOMAINS:
            if netloc.endswith("." + apex):
                return True
    except Exception:
        pass
    return False


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
          "url":                   str,
          "rf_result":             {score, label, available,
                                    feature_contributions: list},
          "bert_result":           {score, label, available},
          "ensemble_score":        float,   # 0.0–1.0
          "ensemble_label":        str,     # PHISHING / LEGITIMATE
          "ensemble_confidence":   float,
          "weights_used":          {rf, bert},
          "explanation":           str
        }

    Phase 5 addition:
        rf_result["feature_contributions"] is populated when the RF model
        is loaded. Contains 24 dicts sorted by absolute contribution
        descending. Each dict has: feature, value, reference, contribution,
        direction ("increases_risk" | "decreases_risk"), abs_contribution.

    Trusted domain override:
        For well-known legitimate domains (linkedin.com, google.com, etc.)
        both model scores are overridden to 0.05 and ensemble_score = 0.05
        (LEGITIMATE) regardless of what the models return. The BERT model
        has known high false-positive rates on short, common URLs.
    """
    # ── Trusted domain early return ───────────────────────────────────────
    if _is_ml_trusted(url):
        rf_model = _load_rf_model()
        feature_contributions = _compute_feature_contributions(url, rf_model)
        trusted_rf = {
            "score":                0.05,
            "label":                "LEGITIMATE",
            "available":            rf_model is not None,
            "note":                 "Trusted domain — model score overridden",
            "feature_contributions": feature_contributions,
        }
        trusted_bert = {
            "score":     0.05,
            "label":     "LEGITIMATE",
            "available": True,
            "note":      "Trusted domain — model score overridden",
        }
        logger.info("classify_url: trusted domain override for %s", url[:80])
        return {
            "url":                 url,
            "rf_result":           trusted_rf,
            "bert_result":         trusted_bert,
            "ensemble_score":      0.05,
            "ensemble_label":      "LEGITIMATE",
            "ensemble_confidence": round(abs(0.05 - 0.5) * 2, 4),
            "weights_used":        {"rf": rf_weight, "bert": bert_weight},
            "explanation": (
                "This domain is on the trusted allowlist of well-known legitimate "
                "platforms. ML model scores have been overridden to prevent false "
                "positives from miscalibrated phishing classifiers."
            ),
        }

    rf_model    = _load_rf_model()
    rf_result   = _classify_with_rf(url, rf_model)
    bert_result = _classify_with_bert(url)

    # ── Phase 5: Feature contributions ────────────────────────────────────
    # Only computed when the RF model is loaded — returns [] otherwise.
    feature_contributions = _compute_feature_contributions(url, rf_model)
    rf_result["feature_contributions"] = feature_contributions

    # ── Soft voting ────────────────────────────────────────────────────────
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
        return _fallback_result(url, "Both classifiers unavailable")

    ensemble_score = round(float(ensemble_score), 4)

    ensemble_label      = "PHISHING" if ensemble_score >= 0.5 else "LEGITIMATE"
    ensemble_confidence = round(abs(ensemble_score - 0.5) * 2, 4)

    explanation = _build_explanation(
        url, rf_result, bert_result,
        ensemble_score, ensemble_label
    )

    return {
        "url":                 url,
        "rf_result":           rf_result,
        "bert_result":         bert_result,
        "ensemble_score":      ensemble_score,
        "ensemble_label":      ensemble_label,
        "ensemble_confidence": ensemble_confidence,
        "weights_used":        weights_used,
        "explanation":         explanation,
    }


def classify_url_batch(urls: list) -> list:
    """Classify a list of URLs. Returns results in the same order."""
    return [classify_url(url) for url in urls]


# ─────────────────────────────────────────────────────────────────────────────
# Classifier 1 — Random Forest
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_rf(url: str, rf_model=None) -> dict:
    """
    Run the scikit-learn Random Forest on the URL feature vector.

    Accepts an optional pre-loaded rf_model to avoid double-loading
    when classify_url() already loaded it for feature contributions.
    """
    rf = rf_model if rf_model is not None else _load_rf_model()

    if rf is None:
        return {
            "score": 0.5, "label": "UNKNOWN", "available": False,
            "note": "Model not trained yet",
            "feature_contributions": [],
        }

    try:
        features = extract_features(url).reshape(1, -1)
        proba    = rf.predict_proba(features)[0]

        phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        label         = "PHISHING" if phishing_prob >= 0.5 else "LEGITIMATE"

        return {
            "score":                round(phishing_prob, 4),
            "label":                label,
            "available":            True,
            "feature_contributions": [],   # populated by classify_url()
        }

    except Exception as e:
        logger.error(f"RF inference error: {e}")
        return {
            "score": 0.5, "label": "UNKNOWN", "available": False,
            "error": str(e),
            "feature_contributions": [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Classifier 2 — ealvaradob/bert-finetuned-phishing
# ─────────────────────────────────────────────────────────────────────────────

def _classify_with_bert(url: str) -> dict:
    """
    Run the fine-tuned BERT phishing classifier on the raw URL string.
    """
    model = get_model("url_phishing_bert")

    if model is None:
        return {"score": 0.5, "label": "UNKNOWN", "available": False,
                "note": "BERT model not loaded"}

    try:
        truncated = url[:400]
        results   = model(truncated)
        top       = results[0]

        raw_label = top["label"].upper()

        if any(x in raw_label for x in ("PHISH", "LABEL_1", "1", "BAD", "MALICIOUS")):
            normalized = "PHISHING"
            score      = float(top["score"])
        elif any(x in raw_label for x in ("LEGIT", "BENIGN", "LABEL_0", "0", "SAFE")):
            normalized = "LEGITIMATE"
            score      = 1.0 - float(top["score"])
        else:
            normalized = raw_label
            score      = float(top["score"])

        return {
            "score":     round(score, 4),
            "label":     normalized,
            "available": True,
            "raw_label": raw_label,
            "raw_score": round(float(top["score"]), 4),
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
            f"({int((1 - ensemble_score) * 100)}% legitimate probability)."
        )

    if rf_result.get("available"):
        parts.append(
            f"Random Forest: {rf_result['label']} "
            f"({int(rf_result['score'] * 100)}%)."
        )

        # Surface top contributing feature if available
        contribs = rf_result.get("feature_contributions", [])
        if contribs:
            top = contribs[0]
            direction = "increases" if top["direction"] == "increases_risk" else "decreases"
            parts.append(
                f"Top RF driver: {top['feature']} "
                f"({direction} risk by {top['abs_contribution']:.3f})."
            )

    if bert_result.get("available"):
        parts.append(
            f"BERT: {bert_result['label']} "
            f"({int(bert_result['score'] * 100)}%)."
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
        "url":                 url,
        "rf_result":           {
            "score": 0.5, "label": "UNKNOWN", "available": False,
            "feature_contributions": [],
        },
        "bert_result":         {"score": 0.5, "label": "UNKNOWN", "available": False},
        "ensemble_score":      0.5,
        "ensemble_label":      "UNKNOWN",
        "ensemble_confidence": 0.0,
        "weights_used":        {"rf": 0.0, "bert": 0.0},
        "explanation":         f"Classification unavailable: {reason}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public helpers
# ─────────────────────────────────────────────────────────────────────────────

def reload_rf_model() -> bool:
    """
    Force-reload the Random Forest model from disk.
    Called by the Model Management page after retraining.
    """
    global _rf_model, _rf_loaded
    _rf_loaded = False
    model      = _load_rf_model()
    return model is not None


def get_rf_model_path() -> str:
    return RF_MODEL_PATH