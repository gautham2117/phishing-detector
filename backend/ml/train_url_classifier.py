# train_url_classifier.py
# Training script for the scikit-learn Random Forest phishing URL classifier.
#
# HOW TO USE:
#   python -m backend.ml.train_url_classifier
#
# DATASETS (download these and place in backend/ml/datasets/):
#
#   Option A — PhiUSIIL Phishing URL Dataset (recommended):
#     https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
#     File: PhiUSIIL_Phishing_URL_Dataset.csv
#     Columns: URL, label  (label: 1=phishing, 0=legitimate)
#
#   Option B — ISCX-URL-2016:
#     https://www.unb.ca/cic/datasets/url-2016.html
#     Files: Benign_list_big_final.csv, phishing_dataset.csv
#
#   Option C — Built-in synthetic demo dataset (no download needed):
#     Run this script with no dataset — it generates a small synthetic
#     dataset for testing. NOT suitable for production accuracy.
#     Replace with a real dataset before the hackathon demo.
#
# OUTPUT:
#   Saves the trained model to backend/ml/models/rf_url_classifier_v1.pkl
#   Prints accuracy, precision, recall, F1 score.

import os
import sys
import json
import logging
import pickle
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score,
    recall_score, f1_score, classification_report
)

# Add project root to path
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))

from backend.ml.feature_extractor import extract_features_batch, get_feature_names

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

_this_dir    = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR  = os.path.join(_this_dir, "datasets")
MODEL_DIR    = os.path.join(_this_dir, "models")
MODEL_PATH   = os.path.join(MODEL_DIR, "rf_url_classifier_v1.pkl")
META_PATH    = os.path.join(MODEL_DIR, "rf_url_classifier_v1_meta.json")

os.makedirs(MODEL_DIR,  exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Dataset loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_phiusiil(path: str) -> tuple:
    """
    Load the PhiUSIIL dataset.
    Expected CSV columns: URL, label  (1=phishing, 0=legitimate)
    """
    logger.info(f"Loading PhiUSIIL dataset from {path}")
    df = pd.read_csv(path)

    # Normalize column names (dataset uses different cases)
    df.columns = [c.strip().lower() for c in df.columns]

    url_col   = next((c for c in df.columns if "url" in c), None)
    label_col = next((c for c in df.columns if "label" in c), None)

    if not url_col or not label_col:
        raise ValueError(
            f"Could not find URL and label columns. "
            f"Found columns: {list(df.columns)}"
        )

    urls   = df[url_col].astype(str).tolist()
    labels = df[label_col].astype(int).tolist()

    logger.info(
        f"Loaded {len(urls)} URLs "
        f"({sum(labels)} phishing, {len(labels)-sum(labels)} legitimate)"
    )
    return urls, labels


def load_synthetic_demo() -> tuple:
    """
    Generate a small synthetic dataset for testing the training pipeline.
    This produces low accuracy (~75%) — replace with a real dataset.
    """
    logger.warning(
        "Using SYNTHETIC demo dataset. "
        "Download a real dataset for production accuracy."
    )

    phishing_urls = [
        "http://paypa1-secure.login.xyz/verify?redirect=http://evil.com",
        "http://192.168.1.100/facebook-login/update",
        "http://secure-account-update.tk/banking/confirm",
        "http://g00gle-login.ml/signin?next=/mail",
        "http://amazon-account-verify.gq/update-payment",
        "http://microsoft-login.top/office365/update",
        "http://apple-id-suspended.xyz/verify-now",
        "http://netflix-billing.tk/payment/update",
        "http://bankofamerica-secure.gq/verify",
        "http://login-paypal.xyz/confirm-identity",
        "http://verify-your-account.online/banking",
        "http://secure.login.update.club/confirm",
        "http://account-suspended.tk/reactivate",
        "http://urgent-action-required.xyz/login",
        "http://192.0.2.1/login?redirect=http://malicious.com",
    ] * 20   # replicate to get enough samples

    legitimate_urls = [
        "https://github.com/trending",
        "https://stackoverflow.com/questions",
        "https://docs.python.org/3/library/",
        "https://www.google.com/search?q=python",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://www.amazon.com/products",
        "https://www.microsoft.com/en-us/windows",
        "https://support.apple.com/en-us",
        "https://www.youtube.com/watch?v=abc123",
        "https://www.linkedin.com/in/profile",
        "https://twitter.com/home",
        "https://www.facebook.com/marketplace",
        "https://www.bbc.co.uk/news",
        "https://www.nytimes.com/section/technology",
        "https://www.reddit.com/r/technology",
    ] * 20

    urls   = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)

    # Shuffle
    combined = list(zip(urls, labels))
    import random
    random.seed(42)
    random.shuffle(combined)
    urls, labels = zip(*combined)

    return list(urls), list(labels)


# ─────────────────────────────────────────────────────────────────────────────
# Training pipeline
# ─────────────────────────────────────────────────────────────────────────────

def train(urls: list, labels: list) -> dict:
    """
    Train a Random Forest classifier on the URL feature matrix.

    Steps:
      1. Extract 24-dimensional feature vectors for all URLs
      2. Split into 80% train / 20% test
      3. Train a RandomForestClassifier
      4. Evaluate on test set
      5. Save model + metadata to disk

    Args:
        urls:   List of URL strings
        labels: List of integer labels (1=phishing, 0=legitimate)

    Returns:
        metrics dict with accuracy, precision, recall, f1
    """
    logger.info(f"Extracting features for {len(urls)} URLs...")
    X = extract_features_batch(urls)
    y = np.array(labels, dtype=np.int32)

    logger.info(f"Feature matrix shape: {X.shape}")

    # ── Train / test split ─────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y    # preserve class ratio in both splits
    )
    logger.info(
        f"Train: {len(X_train)} samples | Test: {len(X_test)} samples"
    )

    # ── Random Forest configuration ────────────────────────────────────────
    # n_estimators=200: 200 trees — good balance of accuracy and speed
    # max_depth=None: let trees grow fully (regularization via min_samples_leaf)
    # min_samples_leaf=2: each leaf needs at least 2 samples (reduces overfitting)
    # class_weight="balanced": compensates for class imbalance in datasets
    # n_jobs=-1: use all CPU cores for faster training
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    logger.info("Training Random Forest (200 trees)...")
    rf.fit(X_train, y_train)
    logger.info("Training complete.")

    # ── Evaluation ─────────────────────────────────────────────────────────
    y_pred     = rf.predict(X_test)
    y_prob     = rf.predict_proba(X_test)[:, 1]  # probability of phishing

    accuracy   = accuracy_score(y_test, y_pred)
    precision  = precision_score(y_test, y_pred, zero_division=0)
    recall     = recall_score(y_test, y_pred, zero_division=0)
    f1         = f1_score(y_test, y_pred, zero_division=0)

    logger.info("\n" + classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"]
    ))
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")
    logger.info(f"F1 Score:  {f1:.4f}")

    # ── Cross-validation ───────────────────────────────────────────────────
    logger.info("Running 5-fold cross-validation...")
    cv_scores = cross_val_score(rf, X, y, cv=5, scoring="f1", n_jobs=-1)
    logger.info(
        f"CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})"
    )

    # ── Feature importance ─────────────────────────────────────────────────
    feature_names   = get_feature_names()
    importances     = rf.feature_importances_
    top_features    = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1], reverse=True
    )[:10]

    logger.info("\nTop 10 most important features:")
    for fname, importance in top_features:
        logger.info(f"  {fname:30s}: {importance:.4f}")

    # ── Save model ─────────────────────────────────────────────────────────
    logger.info(f"Saving model to {MODEL_PATH}")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(rf, f, protocol=pickle.HIGHEST_PROTOCOL)

    # Save metadata alongside the model for the Model Management page
    meta = {
        "version":        "v1.0",
        "model_type":     "RandomForestClassifier",
        "n_estimators":   200,
        "n_features":     X.shape[1],
        "feature_names":  feature_names,
        "train_samples":  len(X_train),
        "test_samples":   len(X_test),
        "accuracy":       round(accuracy,  4),
        "precision":      round(precision, 4),
        "recall":         round(recall,    4),
        "f1_score":       round(f1,        4),
        "cv_f1_mean":     round(float(cv_scores.mean()), 4),
        "cv_f1_std":      round(float(cv_scores.std()),  4),
        "top_features":   [{"name": n, "importance": round(float(i), 4)}
                           for n, i in top_features],
        "trained_at":     datetime.utcnow().isoformat() + "Z",
        "model_path":     MODEL_PATH
    }

    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Model metadata saved to {META_PATH}")

    return {
        "accuracy":  accuracy,
        "precision": precision,
        "recall":    recall,
        "f1_score":  f1,
        "model_path": MODEL_PATH
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Train the phishing URL Random Forest classifier"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help=(
            "Path to CSV dataset file. "
            "If not provided, uses built-in synthetic demo data."
        )
    )
    args = parser.parse_args()

    if args.dataset:
        if not os.path.exists(args.dataset):
            logger.error(f"Dataset file not found: {args.dataset}")
            sys.exit(1)
        urls, labels = load_phiusiil(args.dataset)
    else:
        urls, labels = load_synthetic_demo()

    metrics = train(urls, labels)

    print("\n" + "="*50)
    print("TRAINING COMPLETE")
    print("="*50)
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    print(f"Model saved: {metrics['model_path']}")