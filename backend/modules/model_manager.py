"""
backend/modules/model_manager.py
Phase 12 — Continuous Learning System
Handles feedback labeling, RF retraining, versioning,
hot-swap, and HuggingFace fine-tune pipeline concept.
"""

import os
import json
import time
import logging
import threading
import datetime
import pickle
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_MODULE_DIR)
MODELS_DIR   = os.path.join(_BACKEND_DIR, "ml", "models")
DATASETS_DIR = os.path.join(_BACKEND_DIR, "ml", "datasets")
os.makedirs(MODELS_DIR,   exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)

# ── Valid label types ──────────────────────────────────────────────────────────
VALID_LABEL_TYPES = {
    "FALSE_POSITIVE",
    "FALSE_NEGATIVE",
    "CONFIRMED_PHISHING",
    "CONFIRMED_SAFE",
}

# ── Training state (shared across threads) ────────────────────────────────────
_training_state = {
    "running":     False,
    "log":         [],
    "started_at":  None,
    "finished_at": None,
    "error":       None,
    "version":     None,
}
_state_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# TRAINING STATE ACCESSORS
# ══════════════════════════════════════════════════════════════════════════════

def get_training_state() -> dict:
    with _state_lock:
        return dict(_training_state)


def _log(msg: str) -> None:
    ts   = datetime.datetime.utcnow().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    logger.info(line)
    with _state_lock:
        _training_state["log"].append(line)


def _reset_state() -> None:
    with _state_lock:
        _training_state.update({
            "running":     True,
            "log":         [],
            "started_at":  datetime.datetime.utcnow().isoformat(),
            "finished_at": None,
            "error":       None,
            "version":     None,
        })


def _finish_state(version: Optional[int], error: Optional[str]) -> None:
    with _state_lock:
        _training_state.update({
            "running":     False,
            "finished_at": datetime.datetime.utcnow().isoformat(),
            "error":       error,
            "version":     version,
        })


# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK LABELING
# ══════════════════════════════════════════════════════════════════════════════

def add_feedback_label(
    url:            str,
    label_type:     str,
    feedback_label: str,
    original_label: str = "",
    url_scan_id:    Optional[int] = None,
    admin_note:     str = "",
) -> dict:
    """
    Store one admin-labeled feedback sample.
    Returns the saved record as a dict.
    """
    if label_type not in VALID_LABEL_TYPES:
        return {
            "error": (
                f"Invalid label_type '{label_type}'. "
                f"Must be one of: {sorted(VALID_LABEL_TYPES)}"
            )
        }

    try:
        from backend.app.database import db
        from backend.app.models   import FeedbackSample

        sample = FeedbackSample(
            url            = url[:2048],
            url_scan_id    = url_scan_id,
            original_label = original_label[:30],
            feedback_label = feedback_label[:30],
            label_type     = label_type[:30],
            admin_note     = admin_note[:500],
            created_at     = datetime.datetime.utcnow(),
        )
        db.session.add(sample)
        db.session.commit()

        return {
            "id":             sample.id,
            "url":            sample.url,
            "label_type":     sample.label_type,
            "feedback_label": sample.feedback_label,
            "created_at":     sample.created_at.isoformat() + "Z",
        }

    except Exception as ex:
        try:
            from backend.app.database import db
            db.session.rollback()
        except Exception:
            pass
        logger.error("add_feedback_label DB error: %s", ex)
        return {"error": str(ex)}


def get_feedback_queue(limit: int = 50) -> list:
    """Return recent feedback samples."""
    try:
        from backend.app.models import FeedbackSample
        rows = (
            FeedbackSample.query
            .order_by(FeedbackSample.created_at.desc())
            .limit(limit)
            .all()
        )
        return [_serialize_sample(r) for r in rows]
    except Exception as ex:
        logger.error("get_feedback_queue error: %s", ex)
        return []


def _serialize_sample(r) -> dict:
    return {
        "id":                 r.id,
        "url":                r.url,
        "url_scan_id":        r.url_scan_id,
        "original_label":     r.original_label,
        "feedback_label":     r.feedback_label,
        "label_type":         r.label_type,
        "admin_note":         r.admin_note,
        "used_in_training":   r.used_in_training,
        "created_at":         r.created_at.isoformat() + "Z" if r.created_at else "",
        "trained_in_version": r.trained_in_version,
    }


# ══════════════════════════════════════════════════════════════════════════════
# DATASET BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def _build_training_dataset() -> tuple:
    """
    Combine original URL scan records with feedback labels.
    Returns (X, y, n_original, n_feedback).
    """
    X, y         = [], []
    n_orig       = 0
    n_feed       = 0

    # ── Original URL scans ──────────────────────────────────────────────────
    try:
        from backend.ml.feature_extractor import extract_features
        from backend.app.models           import URLScan

        scans = URLScan.query.filter(
            URLScan.final_label.in_(["MALICIOUS", "SAFE", "BENIGN"])
        ).limit(5000).all()

        for scan in scans:
            try:
                url = scan.normalized_url or scan.raw_url or ""
                if not url:
                    continue
                feats = extract_features(url)
                label = 1 if scan.final_label == "MALICIOUS" else 0
                X.append(feats)
                y.append(label)
                n_orig += 1
            except Exception as inner_ex:
                logger.debug("Skipping URLScan row: %s", inner_ex)
                continue

    except Exception as ex:
        _log(f"Warning: Could not load URLScan records — {ex}")

    # ── Feedback samples ────────────────────────────────────────────────────
    try:
        from backend.app.models import FeedbackSample
        try:
            from backend.ml.feature_extractor import extract_features
        except Exception as import_ex:
            _log(f"Warning: feature_extractor import failed — {import_ex}")
            return np.array(X), np.array(y), n_orig, n_feed

        samples = FeedbackSample.query.all()

        for s in samples:
            try:
                url = s.url or ""
                if not url:
                    continue
                feats = extract_features(url)

                # Map feedback label → binary
                if s.feedback_label in (
                    "MALICIOUS", "PHISHING", "CONFIRMED_PHISHING"
                ):
                    label = 1
                elif s.feedback_label in (
                    "SAFE", "BENIGN", "CONFIRMED_SAFE"
                ):
                    label = 0
                else:
                    if s.label_type == "FALSE_POSITIVE":
                        label = 0
                    elif s.label_type == "FALSE_NEGATIVE":
                        label = 1
                    else:
                        continue

                X.append(feats)
                y.append(label)
                n_feed += 1

            except Exception as inner_ex:
                logger.debug("Skipping FeedbackSample row: %s", inner_ex)
                continue

    except Exception as ex:
        _log(f"Warning: Could not load FeedbackSample records — {ex}")

    return np.array(X), np.array(y), n_orig, n_feed


# ══════════════════════════════════════════════════════════════════════════════
# MODEL VERSIONING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_next_version_number() -> int:
    try:
        from backend.app.models import ModelVersion
        latest = (
            ModelVersion.query
            .filter_by(model_type="rf_url_classifier")
            .order_by(ModelVersion.version_number.desc())
            .first()
        )
        return (latest.version_number + 1) if latest else 1
    except Exception as ex:
        logger.warning("_get_next_version_number error: %s", ex)
        return 1


def get_model_versions() -> list:
    try:
        from backend.app.models import ModelVersion
        rows = (
            ModelVersion.query
            .order_by(ModelVersion.version_number.desc())
            .all()
        )
        return [_serialize_version(r) for r in rows]
    except Exception as ex:
        logger.error("get_model_versions error: %s", ex)
        return []


def _serialize_version(r) -> dict:
    try:
        cm = json.loads(r.confusion_matrix or "[]")
    except Exception:
        cm = []
    return {
        "id":               r.id,
        "version_number":   r.version_number,
        "model_type":       r.model_type,
        "pkl_filename":     r.pkl_filename,
        "training_samples": r.training_samples,
        "feedback_samples": r.feedback_samples,
        "accuracy":         r.accuracy,
        "precision":        r.precision,
        "recall":           r.recall,
        "f1_score":         r.f1_score,
        "confusion_matrix": cm,
        "is_active":        r.is_active,
        "created_at":       r.created_at.isoformat() + "Z" if r.created_at else "",
    }


# ══════════════════════════════════════════════════════════════════════════════
# HOT-SWAP
# ══════════════════════════════════════════════════════════════════════════════

def _hot_swap_model(new_model, version_number: int) -> None:
    """
    Replace the active RF model in model_loader's registry
    without restarting the server.
    """
    try:
        from backend.ml.model_loader import MODEL_REGISTRY
        MODEL_REGISTRY["rf_url_classifier"] = new_model
        _log(f"Hot-swap complete — v{version_number} is now active.")
    except Exception as ex:
        _log(f"Hot-swap warning: {ex} — model saved but not hot-swapped.")


# ══════════════════════════════════════════════════════════════════════════════
# RF RETRAINING (runs in background thread)
# ══════════════════════════════════════════════════════════════════════════════

def _retrain_worker(app_context) -> None:
    """Background thread worker — runs the full retraining pipeline."""
    try:
        if app_context is not None:
            ctx = app_context
        else:
            from backend.app import create_app
            ctx = create_app().app_context()

        with ctx:
            _run_retrain_pipeline()

    except Exception as ex:
        logger.error("Retrain worker outer error: %s", ex, exc_info=True)
        _log(f"FATAL ERROR (outer): {str(ex)[:200]}")
        _finish_state(None, str(ex))


def _run_retrain_pipeline() -> None:
    """Inner pipeline — called inside Flask app context."""
    try:
        from sklearn.ensemble        import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics         import (
            accuracy_score, precision_score,
            recall_score, f1_score, confusion_matrix
        )
        from backend.app.database import db
        from backend.app.models   import ModelVersion, FeedbackSample

        version_number = _get_next_version_number()
        _log(f"Starting RF retraining — target version v{version_number}")

        # ── Build dataset ──────────────────────────────────────────────────
        _log("Loading URL scan records and feedback samples…")
        try:
            X, y, n_orig, n_feed = _build_training_dataset()
        except Exception as ds_ex:
            _log(f"Dataset build error: {ds_ex}")
            _finish_state(None, str(ds_ex))
            return

        _log(
            f"Dataset: {len(X)} total samples "
            f"({n_orig} original + {n_feed} feedback)"
        )

        if len(X) < 10:
            msg = (
                "Not enough samples to retrain (need at least 10). "
                "Run more URL scans first, then retrain."
            )
            _log(f"ERROR: {msg}")
            _finish_state(None, msg)
            return

        # ── Train/test split ───────────────────────────────────────────────
        _log("Splitting dataset 80/20 train/test…")
        try:
            unique_classes = len(set(y.tolist()))
            stratify_y     = y if unique_classes > 1 else None
            X_train, X_test, y_train, y_test = train_test_split(
                X, y,
                test_size=0.2,
                random_state=42,
                stratify=stratify_y,
            )
        except Exception as split_ex:
            _log(f"Train/test split error: {split_ex}")
            _finish_state(None, str(split_ex))
            return

        _log(
            f"Train: {len(X_train)} samples | "
            f"Test:  {len(X_test)} samples"
        )

        # ── Train RF ───────────────────────────────────────────────────────
        _log("Training Random Forest (n_estimators=200, max_depth=20)…")
        try:
            t0  = time.time()
            clf = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=4,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
            clf.fit(X_train, y_train)
            elapsed = round(time.time() - t0, 2)
            _log(f"Training complete in {elapsed}s.")
        except Exception as train_ex:
            _log(f"RF training error: {train_ex}")
            _finish_state(None, str(train_ex))
            return

        # ── Evaluate ───────────────────────────────────────────────────────
        _log("Evaluating on held-out test set…")
        try:
            y_pred = clf.predict(X_test)
            acc    = round(accuracy_score(y_test, y_pred), 4)
            prec   = round(precision_score(
                y_test, y_pred, zero_division=0), 4)
            rec    = round(recall_score(
                y_test, y_pred, zero_division=0), 4)
            f1     = round(f1_score(
                y_test, y_pred, zero_division=0), 4)
            cm     = confusion_matrix(y_test, y_pred).tolist()

            _log(f"Accuracy:  {acc:.4f}")
            _log(f"Precision: {prec:.4f}")
            _log(f"Recall:    {rec:.4f}")
            _log(f"F1 Score:  {f1:.4f}")
            _log(f"Confusion Matrix: {cm}")
        except Exception as eval_ex:
            _log(f"Evaluation error: {eval_ex}")
            _finish_state(None, str(eval_ex))
            return

        # ── Save model .pkl ────────────────────────────────────────────────
        _log("Saving model to disk…")
        try:
            pkl_filename = f"rf_url_classifier_v{version_number}.pkl"
            pkl_path     = os.path.join(MODELS_DIR, pkl_filename)
            with open(pkl_path, "wb") as fh:
                pickle.dump(clf, fh)
            _log(f"Model saved → {pkl_filename}")
        except Exception as save_ex:
            _log(f"Model save error: {save_ex}")
            _finish_state(None, str(save_ex))
            return

        # ── Save ModelVersion to DB ────────────────────────────────────────
        _log("Writing ModelVersion record to database…")
        try:
            ModelVersion.query.filter_by(
                model_type="rf_url_classifier",
                is_active=True,
            ).update({"is_active": False})

            with _state_lock:
                log_snapshot = "\n".join(_training_state["log"])

            mv = ModelVersion(
                version_number   = version_number,
                model_type       = "rf_url_classifier",
                pkl_filename     = pkl_filename,
                training_samples = n_orig,
                feedback_samples = n_feed,
                accuracy         = acc,
                precision        = prec,
                recall           = rec,
                f1_score         = f1,
                confusion_matrix = json.dumps(cm),
                is_active        = True,
                training_log     = log_snapshot,
                created_at       = datetime.datetime.utcnow(),
            )
            db.session.add(mv)

            # Mark all pending feedback samples as used
            FeedbackSample.query.filter_by(
                used_in_training=False
            ).update({
                "used_in_training":    True,
                "trained_in_version":  version_number,
            })

            db.session.commit()
            _log(f"ModelVersion v{version_number} saved to DB.")

        except Exception as db_ex:
            _log(f"DB save error: {db_ex}")
            try:
                db.session.rollback()
            except Exception:
                pass
            _finish_state(None, str(db_ex))
            return

        # ── Hot-swap active model ──────────────────────────────────────────
        try:
            _hot_swap_model(clf, version_number)
        except Exception as swap_ex:
            _log(f"Hot-swap warning: {swap_ex}")
            # Non-fatal — model is saved, just not hot-swapped

        _log(f"Retraining pipeline complete — v{version_number} is active.")
        _finish_state(version_number, None)

    except Exception as ex:
        logger.error("_run_retrain_pipeline error: %s", ex, exc_info=True)
        _log(f"FATAL ERROR: {str(ex)[:200]}")
        _finish_state(None, str(ex))


def trigger_retrain(app_context) -> dict:
    """
    Start the retraining pipeline in a background thread.
    Returns immediately with status.
    """
    try:
        with _state_lock:
            if _training_state["running"]:
                return {
                    "status":  "error",
                    "message": "Retraining already in progress.",
                }
        _reset_state()
        t = threading.Thread(
            target=_retrain_worker,
            args=(app_context,),
            daemon=True,
            name="rf-retrain-thread",
        )
        t.start()
        return {
            "status":  "success",
            "message": "Retraining started in background.",
        }
    except Exception as ex:
        logger.error("trigger_retrain error: %s", ex)
        return {"status": "error", "message": str(ex)}


# ══════════════════════════════════════════════════════════════════════════════
# HUGGINGFACE FINE-TUNE PIPELINE CONCEPT
# ══════════════════════════════════════════════════════════════════════════════

def get_huggingface_finetune_plan() -> dict:
    """
    Returns a structured description of the HuggingFace fine-tuning
    pipeline. Fully designed concept — no GPU execution needed for demo.
    """
    try:
        return {
            "model_key":  "email_classifier",
            "base_model": "cybersectony/phishing-email-detection-distilbert_v2.4.1",
            "framework":  "HuggingFace Transformers + Trainer API",
            "steps": [
                {
                    "step": 1,
                    "name": "Prepare Dataset",
                    "description": (
                        "Load FeedbackSample rows where label_type in "
                        "(CONFIRMED_PHISHING, CONFIRMED_SAFE). "
                        "Tokenize url+admin_note text using AutoTokenizer. "
                        "Split 80/20 into train/eval datasets."
                    ),
                    "code_sketch": (
                        "tokenizer = AutoTokenizer.from_pretrained(base_model)\n"
                        "train_ds = Dataset.from_dict({'text': texts, 'label': labels})\n"
                        "train_ds = train_ds.map(\n"
                        "    lambda x: tokenizer(x['text'], truncation=True, max_length=128)\n"
                        ")"
                    ),
                },
                {
                    "step": 2,
                    "name": "Load Base Model",
                    "description": (
                        "Load base DistilBERT with AutoModelForSequenceClassification. "
                        "Freeze all layers except the final classification head "
                        "for lightweight fine-tuning (avoids catastrophic forgetting)."
                    ),
                    "code_sketch": (
                        "model = AutoModelForSequenceClassification.from_pretrained(\n"
                        "    base_model, num_labels=2, ignore_mismatched_sizes=True\n"
                        ")\n"
                        "for param in model.distilbert.parameters():\n"
                        "    param.requires_grad = False  # freeze base layers"
                    ),
                },
                {
                    "step": 3,
                    "name": "Configure Trainer",
                    "description": (
                        "Set TrainingArguments: 3 epochs, batch_size=16, "
                        "weight_decay=0.01, evaluation_strategy=epoch, "
                        "save_strategy=epoch, load_best_model_at_end=True."
                    ),
                    "code_sketch": (
                        "args = TrainingArguments(\n"
                        "    output_dir='ml/models/hf_finetuned_v{N}',\n"
                        "    num_train_epochs=3,\n"
                        "    per_device_train_batch_size=16,\n"
                        "    evaluation_strategy='epoch',\n"
                        "    load_best_model_at_end=True,\n"
                        ")"
                    ),
                },
                {
                    "step": 4,
                    "name": "Train and Evaluate",
                    "description": (
                        "Run trainer.train(). After training call "
                        "trainer.evaluate() to capture eval_accuracy and "
                        "eval_loss. Save model and tokenizer to versioned directory."
                    ),
                    "code_sketch": (
                        "trainer = Trainer(\n"
                        "    model=model, args=args,\n"
                        "    train_dataset=train_ds,\n"
                        "    eval_dataset=eval_ds,\n"
                        "    compute_metrics=compute_metrics,\n"
                        ")\n"
                        "trainer.train()\n"
                        "trainer.save_model('ml/models/hf_finetuned_v{N}')"
                    ),
                },
                {
                    "step": 5,
                    "name": "Hot-Swap Pipeline",
                    "description": (
                        "Load the saved model back as a pipeline and replace "
                        "MODEL_REGISTRY['email_classifier'] in model_loader.py. "
                        "All subsequent requests use the new model with zero downtime."
                    ),
                    "code_sketch": (
                        "new_pipe = pipeline(\n"
                        "    'text-classification',\n"
                        "    model='ml/models/hf_finetuned_v{N}'\n"
                        ")\n"
                        "MODEL_REGISTRY['email_classifier'] = new_pipe"
                    ),
                },
            ],
            "hardware_note": (
                "For hackathon/demo: fine-tuning runs on CPU with a small "
                "feedback dataset (50-200 samples) in approximately 5-15 minutes. "
                "For production: use a T4 GPU (Google Colab or AWS) for "
                "full dataset fine-tuning in under 30 minutes."
            ),
            "requirements": [
                "transformers>=4.30.0",
                "datasets>=2.14.0",
                "torch>=2.0.0",
                "scikit-learn (for compute_metrics)",
            ],
        }
    except Exception as ex:
        logger.error("get_huggingface_finetune_plan error: %s", ex)
        return {"error": str(ex)}