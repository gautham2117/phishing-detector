"""
backend/modules/threat_explainer.py
Phase 16 — Multi-Language Threat Explanation & User Awareness Engine

Uses:
  - facebook/bart-large-cnn (already loaded as "threat_summarizer")
    for plain-language explanation generation
  - Helsinki-NLP MarianMT models for translation into 6 languages
    (lazy-loaded on first request per language)
"""

import re
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ── Supported languages ────────────────────────────────────────────────────────
SUPPORTED_LANGUAGES = {
    "fr": {
        "name":        "French",
        "native_name": "Français",
        "model":       "Helsinki-NLP/opus-mt-en-fr",
        "flag":        "🇫🇷",
    },
    "es": {
        "name":        "Spanish",
        "native_name": "Español",
        "model":       "Helsinki-NLP/opus-mt-en-es",
        "flag":        "🇪🇸",
    },
    "de": {
        "name":        "German",
        "native_name": "Deutsch",
        "model":       "Helsinki-NLP/opus-mt-en-de",
        "flag":        "🇩🇪",
    },
    "zh": {
        "name":        "Chinese",
        "native_name": "中文",
        "model":       "Helsinki-NLP/opus-mt-en-zh",
        "flag":        "🇨🇳",
    },
    "ar": {
        "name":        "Arabic",
        "native_name": "العربية",
        "model":       "Helsinki-NLP/opus-mt-en-ar",
        "flag":        "🇸🇦",
    },
    "ta": {
        "name":        "Tamil",
        "native_name": "தமிழ்",
        "model":       "Helsinki-NLP/opus-mt-en-mul",
        "flag":        "🇮🇳",
        "prefix":      ">>ta<< ",   # mul model needs language prefix
    },
}

# ── Lazy model cache ──────────────────────────────────────────────────────────
_translation_pipelines = {}
_pipeline_lock          = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# TRANSLATION MODEL LOADER (lazy)
# ══════════════════════════════════════════════════════════════════════════════

def _get_translation_pipeline(lang_code: str):
    """
    Return cached pipeline for lang_code.
    Downloads and caches the model on first call for that language.
    Thread-safe.
    """
    with _pipeline_lock:
        if lang_code in _translation_pipelines:
            return _translation_pipelines[lang_code]

    if lang_code not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language code: {lang_code}")

    lang_cfg   = SUPPORTED_LANGUAGES[lang_code]
    model_name = lang_cfg["model"]

    logger.info("Loading translation model: %s", model_name)
    try:
        from transformers import pipeline as hf_pipeline
        pipe = hf_pipeline(
            "translation",
            model=model_name,
        )
        with _pipeline_lock:
            _translation_pipelines[lang_code] = pipe
        logger.info("Translation model loaded: %s", model_name)
        return pipe

    except Exception as ex:
        logger.error("Failed to load translation model %s: %s", model_name, ex)
        raise


# ══════════════════════════════════════════════════════════════════════════════
# BART EXPLANATION GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_explanation(
    raw_text:  str,
    verdict:   str = "",
    module:    str = "",
    risk_score:float = 0.0,
) -> str:
    """
    Generate a plain-language 2–3 sentence explanation of a threat
    using BART (threat_summarizer, already loaded at startup).

    Falls back to a rule-based explanation if BART is unavailable.
    """
    if not raw_text or len(raw_text.strip()) < 10:
        return _rule_based_explanation(verdict, module, risk_score)

    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("threat_summarizer")

        if pipeline is None:
            raise RuntimeError("threat_summarizer not loaded")

        # Build a structured input for BART
        input_text = (
            f"Security scan result. "
            f"Module: {module or 'Unknown'}. "
            f"Verdict: {verdict or 'Unknown'}. "
            f"Risk score: {risk_score}/100. "
            f"Details: {raw_text.strip()}"
        )[:1024]

        output = pipeline(
            input_text,
            max_length=120,
            min_length=30,
            do_sample=False,
        )

        if isinstance(output, list) and output:
            text = output[0].get("summary_text", "").strip()
            if text:
                return text

    except Exception as ex:
        logger.warning("BART explanation failed: %s", ex)

    return _rule_based_explanation(verdict, module, risk_score)


def _rule_based_explanation(
    verdict: str,
    module:  str,
    score:   float,
) -> str:
    """Fallback plain-language explanation when BART is unavailable."""
    severity = "critical" if score >= 80 else \
               "high"     if score >= 60 else \
               "medium"   if score >= 35 else "low"

    verdict_upper = (verdict or "UNKNOWN").upper()

    if verdict_upper == "MALICIOUS":
        return (
            f"This {module or 'scan'} result indicates a malicious threat "
            f"with {severity} severity and a risk score of {score:.1f}/100. "
            f"Immediate action is recommended — do not interact with this "
            f"content and report it to your security team."
        )
    elif verdict_upper == "SUSPICIOUS":
        return (
            f"This {module or 'scan'} result shows suspicious activity "
            f"with a risk score of {score:.1f}/100. "
            f"Exercise caution before proceeding and verify the source "
            f"through trusted channels."
        )
    else:
        return (
            f"This {module or 'scan'} result appears safe with a risk "
            f"score of {score:.1f}/100. "
            f"No significant threats were detected, but always remain "
            f"vigilant about unexpected communications."
        )


# ══════════════════════════════════════════════════════════════════════════════
# TRANSLATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def translate_explanation(
    text:      str,
    lang_code: str,
) -> dict:
    """
    Translate the given English text into the target language.

    Returns:
        {
            "translated":    str,
            "language_code": str,
            "language_name": str,
            "model_used":    str,
            "error":         str | None,
        }
    """
    lang_cfg = SUPPORTED_LANGUAGES.get(lang_code)
    if not lang_cfg:
        return {
            "translated":    text,
            "language_code": lang_code,
            "language_name": "Unknown",
            "model_used":    "",
            "error":         f"Unsupported language: {lang_code}",
        }

    result = {
        "translated":    "",
        "language_code": lang_code,
        "language_name": lang_cfg["name"],
        "native_name":   lang_cfg["native_name"],
        "flag":          lang_cfg["flag"],
        "model_used":    lang_cfg["model"],
        "error":         None,
    }

    # Prepend language prefix for multi-language models
    prefix       = lang_cfg.get("prefix", "")
    input_text   = prefix + text.strip()

    # Split into sentences for better translation quality
    sentences = _split_sentences(input_text)

    try:
        pipe = _get_translation_pipeline(lang_code)

        translated_parts = []
        for sentence in sentences:
            if not sentence.strip():
                continue
            output = pipe(
                sentence,
                max_length=512,
            )
            if isinstance(output, list) and output:
                part = output[0].get("translation_text", "").strip()
                if part:
                    translated_parts.append(part)

        result["translated"] = " ".join(translated_parts)

        if not result["translated"]:
            result["translated"] = text
            result["error"]      = "Translation returned empty result."

    except Exception as ex:
        logger.error("Translation error for %s: %s", lang_code, ex)
        result["translated"] = text   # fallback to original English
        result["error"]      = (
            f"Translation unavailable for {lang_cfg['name']}. "
            f"Showing original English. Error: {str(ex)[:80]}"
        )

    return result


def _split_sentences(text: str) -> list:
    """Split text into sentences for chunked translation."""
    raw = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in raw if s.strip()]


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY AWARENESS TIPS
# ══════════════════════════════════════════════════════════════════════════════

# Tips are keyed by threat category — matched against verdict/module/keywords
SECURITY_TIPS = {
    "phishing_email": {
        "category": "Phishing Email",
        "icon":     "✉",
        "color":    "red",
        "tips": [
            "Never click links in unexpected emails — type the URL directly into your browser.",
            "Check the sender's actual email address, not just the display name.",
            "Legitimate organisations never ask for passwords via email.",
            "Look for urgency or threats in the subject line — these are phishing tactics.",
            "Enable multi-factor authentication (MFA) on all important accounts.",
            "Report phishing emails to your IT team or use Gmail/Outlook's 'Report Phishing' button.",
        ],
    },
    "malicious_url": {
        "category": "Malicious URL",
        "icon":     "🔗",
        "color":    "red",
        "tips": [
            "Check the full URL before clicking — hover over links to see the real destination.",
            "Look for HTTPS and a padlock, but note that phishing sites can also have HTTPS.",
            "Be suspicious of domains with extra words, typos, or hyphens (e.g. paypa1-login.com).",
            "Use a URL scanner (like VirusTotal) when unsure about a link.",
            "Avoid clicking shortened URLs (bit.ly, tinyurl) from unknown sources.",
            "Keep your browser updated to benefit from built-in phishing protection.",
        ],
    },
    "malware_attachment": {
        "category": "Malware Attachment",
        "icon":     "📎",
        "color":    "red",
        "tips": [
            "Never open unexpected attachments, even from known senders.",
            "Be especially cautious with .exe, .zip, .docm, .xlsm, and .ps1 files.",
            "Disable macros in Office documents by default — enable only from trusted sources.",
            "Scan all downloaded files with antivirus before opening.",
            "PDF files can contain embedded scripts — open with a sandboxed viewer.",
            "When in doubt, open attachments in a cloud viewer (Google Drive, OneDrive) first.",
        ],
    },
    "ai_generated": {
        "category": "AI-Generated Content",
        "icon":     "🤖",
        "color":    "amber",
        "tips": [
            "AI-generated phishing emails are more convincing — read carefully before acting.",
            "Check for overly formal or perfectly structured language in unexpected emails.",
            "Verify requests through a separate communication channel (phone call, in-person).",
            "Be sceptical of unsolicited messages that seem unusually polished.",
            "AI can mimic writing styles — verify identity even with familiar-sounding messages.",
            "Report suspected AI-generated phishing to help train better detection models.",
        ],
    },
    "image_phishing": {
        "category": "Image-Based Phishing",
        "icon":     "🖼",
        "color":    "amber",
        "tips": [
            "Phishing pages often use screenshots or images to bypass text-based filters.",
            "Be suspicious of login pages that look slightly different from the official site.",
            "Check the browser address bar carefully — fake sites mimic real ones visually.",
            "Never enter credentials on a page reached via an unexpected link.",
            "Use a password manager — it won't autofill on fake domains.",
            "Enable browser warnings for suspected phishing pages.",
        ],
    },
    "network_threat": {
        "category": "Network Threat",
        "icon":     "🌐",
        "color":    "amber",
        "tips": [
            "Avoid using public Wi-Fi for sensitive transactions without a VPN.",
            "Keep your router firmware updated and use WPA3 encryption.",
            "Disable unused open ports on servers and use a firewall.",
            "Use network monitoring tools to detect unusual traffic patterns.",
            "Segment your network — isolate IoT devices from sensitive systems.",
            "Enable intrusion detection alerts on your network equipment.",
        ],
    },
    "general_threat": {
        "category": "General Security",
        "icon":     "🛡",
        "color":    "blue",
        "tips": [
            "Keep all software and operating systems updated with the latest patches.",
            "Use unique, strong passwords for every account — use a password manager.",
            "Enable multi-factor authentication wherever possible.",
            "Regularly back up important data to an offline or separate location.",
            "Be cautious about what personal information you share online.",
            "Educate yourself and colleagues about social engineering tactics.",
        ],
    },
}


def get_security_tips(
    verdict:   str = "",
    module:    str = "",
    raw_text:  str = "",
) -> dict:
    """
    Return the most relevant security tips based on verdict, module, and text.
    """
    verdict_upper = (verdict or "").upper()
    module_lower  = (module  or "").lower()
    text_lower    = (raw_text or "").lower()

    # Category matching logic
    category_key = "general_threat"

    if "email" in module_lower or "email" in text_lower:
        category_key = "phishing_email"

    elif "attachment" in module_lower or "file" in module_lower:
        if any(kw in text_lower for kw in ["macro", "vba", "malware", "yara"]):
            category_key = "malware_attachment"
        else:
            category_key = "malware_attachment"

    elif "url" in module_lower or "url" in text_lower:
        category_key = "malicious_url"

    elif "ai" in module_lower or "ai_generated" in verdict_upper:
        category_key = "ai_generated"

    elif "image" in module_lower:
        category_key = "image_phishing"

    elif "network" in module_lower:
        category_key = "network_threat"

    elif verdict_upper in ("MALICIOUS", "PHISHING"):
        category_key = "phishing_email"

    tips = SECURITY_TIPS.get(category_key, SECURITY_TIPS["general_threat"])
    return {
        "category_key": category_key,
        "category":     tips["category"],
        "icon":         tips["icon"],
        "color":        tips["color"],
        "tips":         tips["tips"],
    }


# ══════════════════════════════════════════════════════════════════════════════
# SUPPORTED LANGUAGES METADATA (for frontend dropdown)
# ══════════════════════════════════════════════════════════════════════════════

def get_supported_languages() -> list:
    """Return language metadata for the frontend language selector."""
    return [
        {
            "code":        code,
            "name":        cfg["name"],
            "native_name": cfg["native_name"],
            "flag":        cfg["flag"],
            "model":       cfg["model"],
        }
        for code, cfg in SUPPORTED_LANGUAGES.items()
    ]