"""
download_models.py
==================
PhishGuard — Team Model Installer
Run this script ONCE after cloning the repo to pre-download all
HuggingFace models to the local cache.

Usage:
    python download_models.py                  # download all models
    python download_models.py --skip-bart      # skip the 1.6 GB BART model
    python download_models.py --skip-translation  # skip MarianMT models
    python download_models.py --check          # only check what is cached

Requirements:
    pip install transformers torch sentencepiece
"""

import os
import sys
import time
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("model_installer")


# ─────────────────────────────────────────────────────────────────────────────
# Model registry
# ─────────────────────────────────────────────────────────────────────────────

CORE_MODELS = [
    {
        "key":         "email_classifier",
        "model":       "cybersectony/phishing-email-detection-distilbert_v2.4.1",
        "task":        "text-classification",
        "description": "Email phishing detector — DistilBERT (Phase 1)",
        "size_mb":     265,
        "required":    True,
    },
    {
        "key":         "url_malware_detector",
        "model":       "elftsdmr/malware-url-detect",
        "task":        "text-classification",
        "description": "Malicious URL BERT classifier (Phase 2)",
        "size_mb":     440,
        "required":    True,
    },
    {
        "key":         "url_phishing_bert",
        "model":       "ealvaradob/bert-finetuned-phishing",
        "task":        "text-classification",
        "description": "Phishing URL/content BERT (Phase 5)",
        "size_mb":     440,
        "required":    True,
    },
    {
        "key":         "ai_text_detector",
        "model":       "Hello-SimpleAI/chatgpt-detector-roberta",
        "task":        "text-classification",
        "description": "AI-generated content detector — RoBERTa (Phase 8)",
        "size_mb":     480,
        "required":    True,
    },
    {
        "key":         "sms_spam_detector",
        "model":       "mrm8488/bert-tiny-finetuned-sms-spam-detection",
        "task":        "text-classification",
        "description": "SMS spam detector — BERT-tiny (Phase 11)",
        "size_mb":     55,
        "required":    True,
    },
    {
        "key":         "threat_summarizer",
        "model":       "facebook/bart-large-cnn",
        "task":        "summarization",
        "description": "Threat summarizer — BART-large (Phase 13/16)  ⚠ 1.6 GB",
        "size_mb":     1630,
        "required":    False,   # large — can be skipped with --skip-bart
        "skip_flag":   "skip_bart",
    },
]

TRANSLATION_MODELS = [
    {
        "key":         "translation_fr",
        "model":       "Helsinki-NLP/opus-mt-en-fr",
        "task":        "translation",
        "description": "English → French (Phase 16)",
        "size_mb":     300,
    },
    {
        "key":         "translation_es",
        "model":       "Helsinki-NLP/opus-mt-en-es",
        "task":        "translation",
        "description": "English → Spanish (Phase 16)",
        "size_mb":     300,
    },
    {
        "key":         "translation_de",
        "model":       "Helsinki-NLP/opus-mt-en-de",
        "task":        "translation",
        "description": "English → German (Phase 16)",
        "size_mb":     300,
    },
    {
        "key":         "translation_zh",
        "model":       "Helsinki-NLP/opus-mt-en-zh",
        "task":        "translation",
        "description": "English → Chinese (Phase 16)",
        "size_mb":     300,
    },
    {
        "key":         "translation_ar",
        "model":       "Helsinki-NLP/opus-mt-en-ar",
        "task":        "translation",
        "description": "English → Arabic (Phase 16)",
        "size_mb":     300,
    },
    {
        "key":         "translation_ta",
        "model":       "Helsinki-NLP/opus-mt-en-mul",
        "task":        "translation",
        "description": "English → Tamil (multilingual) (Phase 16)",
        "size_mb":     300,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _separator(char="─", width=68):
    print(char * width)


def _check_transformers():
    """Verify transformers and torch are installed."""
    try:
        import transformers
        import torch
        logger.info("transformers %s  |  torch %s",
                    transformers.__version__, torch.__version__)
        return True
    except ImportError as e:
        logger.error("Missing dependency: %s", e)
        logger.error("Fix: pip install transformers torch sentencepiece")
        return False


def _is_cached(model_name: str) -> bool:
    """Return True if the model is already in the HuggingFace cache."""
    try:
        from huggingface_hub import try_to_load_from_cache
        # Check for config.json as a proxy for a full download
        result = try_to_load_from_cache(model_name, "config.json")
        return result is not None and result != "not in cache"
    except Exception:
        return False


def _download_model(entry: dict) -> bool:
    """
    Download one model using the transformers pipeline API.
    Returns True on success, False on failure.
    """
    from transformers import pipeline as hf_pipeline

    model_name  = entry["model"]
    task        = entry["task"]
    description = entry["description"]
    size_mb     = entry.get("size_mb", "?")

    logger.info("Downloading: %s  (~%s MB)", description, size_mb)
    logger.info("  Model ID : %s", model_name)

    t0 = time.time()
    try:
        pipe = hf_pipeline(task=task, model=model_name, device=-1)
        elapsed = round(time.time() - t0, 1)
        logger.info("  ✓ Done in %ss", elapsed)
        del pipe   # free memory immediately
        return True
    except Exception as exc:
        logger.error("  ✗ FAILED: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Main routines
# ─────────────────────────────────────────────────────────────────────────────

def check_cache(models: list):
    """Print cache status for every model without downloading."""
    _separator()
    print(f"{'KEY':<28} {'CACHED':>8}  MODEL")
    _separator()
    for entry in models:
        cached = "✓ YES" if _is_cached(entry["model"]) else "✗ NO"
        print(f"{entry['key']:<28} {cached:>8}  {entry['model']}")
    _separator()


def download_all(models: list) -> dict:
    """
    Download every model in the list.
    Returns a summary dict with lists of passed/failed keys.
    """
    results = {"ok": [], "failed": [], "skipped": []}

    total = len(models)
    for idx, entry in enumerate(models, start=1):
        _separator()
        print(f"[{idx}/{total}]", end="  ")

        # Check cache first
        if _is_cached(entry["model"]):
            logger.info("CACHED — skipping re-download: %s", entry["key"])
            results["skipped"].append(entry["key"])
            continue

        ok = _download_model(entry)
        if ok:
            results["ok"].append(entry["key"])
        else:
            results["failed"].append(entry["key"])

    return results


def print_summary(results: dict, models: list):
    _separator("═")
    print("  DOWNLOAD SUMMARY")
    _separator("═")
    print(f"  ✓ Downloaded  : {len(results['ok'])}")
    print(f"  ⏭ Already cached: {len(results['skipped'])}")
    print(f"  ✗ Failed      : {len(results['failed'])}")

    if results["failed"]:
        print("\n  Failed models (retry with a stable internet connection):")
        for key in results["failed"]:
            entry = next((m for m in models if m["key"] == key), {})
            print(f"    - {key}  ({entry.get('model', '')})")

    _separator("═")
    total_ok = len(results["ok"]) + len(results["skipped"])
    total    = len(models)
    if total_ok == total:
        print("  🎉 All models ready — PhishGuard can start fully.")
    else:
        missing = total - total_ok
        print(f"  ⚠  {missing} model(s) missing. "
              "Server will fall back to rule-based results for those modules.")
    _separator("═")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — pre-download all HuggingFace models"
    )
    parser.add_argument(
        "--skip-bart",
        action="store_true",
        help="Skip facebook/bart-large-cnn (~1.6 GB) — useful on slow connections",
    )
    parser.add_argument(
        "--skip-translation",
        action="store_true",
        help="Skip all 6 MarianMT translation models (~1.8 GB total)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only show cache status — do not download anything",
    )
    args = parser.parse_args()

    _separator("═")
    print("  PhishGuard — Model Installer")
    print("  Pre-downloads all HuggingFace models to local cache")
    _separator("═")

    # Verify dependencies
    if not _check_transformers():
        sys.exit(1)

    # Build the list of models to process
    models_to_process = []

    for entry in CORE_MODELS:
        if args.skip_bart and entry.get("skip_flag") == "skip_bart":
            logger.info("Skipping BART (--skip-bart flag set)")
            continue
        models_to_process.append(entry)

    if not args.skip_translation:
        models_to_process.extend(TRANSLATION_MODELS)
    else:
        logger.info("Skipping all translation models (--skip-translation flag set)")

    # Total size estimate
    total_mb = sum(m.get("size_mb", 0) for m in models_to_process)
    print(f"\n  Models to process : {len(models_to_process)}")
    print(f"  Estimated download: ~{total_mb:,} MB  "
          f"(already-cached files are skipped)\n")

    if args.check:
        check_cache(models_to_process)
        return

    # Confirm before downloading
    try:
        answer = input("  Proceed? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "y"

    if answer not in ("", "y", "yes"):
        print("  Aborted.")
        return

    print()
    results = download_all(models_to_process)
    print()
    print_summary(results, models_to_process)


if __name__ == "__main__":
    main()