# model_loader.py
# Central model registry. ALL HuggingFace models used across the project
# are loaded here at server startup and stored in the MODEL_REGISTRY dict.
#
# Design principle:
#   - Each model is wrapped in try/except. If a model fails to load
#     (e.g. no internet, wrong model name), we log the error and store
#     None in the registry. Every module that uses a model must check
#     for None and fall back to rule-based results.
#   - Models are never reloaded per-request. This is critical for performance.
#   - The registry is a plain Python dict — no fancy singletons needed.

import logging
from typing import Optional

# transformers.pipeline is the high-level HuggingFace API.
# It handles tokenization, model inference, and output decoding.
from transformers import pipeline

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# The global model registry.
# Keys are human-readable names used throughout the codebase.
# Values are loaded pipeline objects (or None if load failed).
# ─────────────────────────────────────────────
MODEL_REGISTRY: dict = {}


def load_all_models() -> None:
    """
    Load every HuggingFace model used in the project.
    Call this ONCE from the FastAPI startup event handler.

    Each model is loaded with:
      - task: the HuggingFace pipeline task string
      - model: the model card name from huggingface.co/models
      - device: -1 means CPU (use 0 for GPU if available)

    Models are stored in MODEL_REGISTRY under a short key name.
    All code that needs a model does:
        model = MODEL_REGISTRY.get("email_classifier")
        if model is None:
            return fallback_rule_result()
    """

    # ── Module 1: Email phishing classification (DistilBERT) ──────────────
    # Model: cybersectony/phishing-email-detection-distilbert_v2.4.1
    # Fine-tuned DistilBERT on phishing email datasets.
    # Input: email body text (string)
    # Output: {"label": "PHISHING"/"SAFE", "score": 0.0–1.0}
    _load_model(
        key="email_classifier",
        task="text-classification",
        model_name="cybersectony/phishing-email-detection-distilbert_v2.4.1",
        description="Email phishing DistilBERT"
    )

    # ── Module 2: Malicious URL detection (BERT-based) ────────────────────
    # Model: elftsdmr/malware-url-detect
    # Input: raw URL string
    # Output: {"label": "MALICIOUS"/"BENIGN", "score": 0.0–1.0}
    _load_model(
        key="url_malware_detector",
        task="text-classification",
        model_name="elftsdmr/malware-url-detect",
        description="Malicious URL BERT"
    )

    # ── Module 5: Phishing URL + content classifier (BERT fine-tuned) ─────
    # Model: ealvaradob/bert-finetuned-phishing
    # Trained on combined phishing URL + content datasets.
    _load_model(
        key="url_phishing_bert",
        task="text-classification",
        model_name="ealvaradob/bert-finetuned-phishing",
        description="Phishing URL/content BERT"
    )

    # ── Module 8: AI-generated text detection (RoBERTa) ───────────────────
    # Model: Hello-SimpleAI/chatgpt-detector-roberta
    # Detects whether email body was written by ChatGPT/LLM.
    _load_model(
        key="ai_text_detector",
        task="text-classification",
        model_name="Hello-SimpleAI/chatgpt-detector-roberta",
        description="AI-generated text RoBERTa"
    )

    # ── Module 11: SMS/message phishing (BERT-tiny) ───────────────────────
    # Model: mrm8488/bert-tiny-finetuned-sms-spam-detection
    # Lightweight model, fast inference for real-time SMS.
    _load_model(
        key="sms_spam_detector",
        task="text-classification",
        model_name="mrm8488/bert-tiny-finetuned-sms-spam-detection",
        description="SMS spam BERT-tiny"
    )

    # ── Module 13: Threat summarization (BART) ───────────────────────────
    # Model: facebook/bart-large-cnn
    # Generates a 1–2 sentence human-readable threat summary.
    # Note: This is a large model (~1.6GB). Only load if you have >8GB RAM.
    _load_model(
        key="threat_summarizer",
        task="summarization",
        model_name="facebook/bart-large-cnn",
        description="Threat summarizer BART"
    )

    # Log a summary of what loaded successfully
    loaded = [k for k, v in MODEL_REGISTRY.items() if v is not None]
    failed = [k for k, v in MODEL_REGISTRY.items() if v is None]
    logger.info(f"Models loaded successfully: {loaded}")
    if failed:
        logger.warning(f"Models that FAILED to load (will use fallback): {failed}")


def _load_model(key: str, task: str, model_name: str, description: str) -> None:
    """
    Helper: attempt to load one model into MODEL_REGISTRY.
    On failure, stores None and logs the error — does NOT crash the server.

    Args:
        key:         Short identifier used to retrieve this model later.
        task:        HuggingFace pipeline task string.
        model_name:  HuggingFace model card path.
        description: Human-readable name for logging.
    """
    try:
        logger.info(f"Loading {description} ({model_name})...")

        # pipeline() downloads the model on first run, then caches it in
        # ~/.cache/huggingface/transformers/ for subsequent starts.
        # device=-1 forces CPU inference. Change to device=0 for CUDA GPU.
        model = pipeline(task=task, model=model_name, device=-1)

        MODEL_REGISTRY[key] = model
        logger.info(f"  ✓ {description} loaded")

    except Exception as e:
        # Catching broadly because load failures can be OSError (disk),
        # ConnectionError (no internet), RuntimeError (bad model), etc.
        logger.error(f"  ✗ Failed to load {description}: {e}")
        MODEL_REGISTRY[key] = None


def get_model(key: str):
    """
    Retrieve a model from the registry.
    Returns None if the model failed to load.
    Every caller must handle the None case.

    Usage:
        model = get_model("email_classifier")
        if model is None:
            return {"label": "UNKNOWN", "score": 0.0}
        result = model(text)[0]
    """
    return MODEL_REGISTRY.get(key)