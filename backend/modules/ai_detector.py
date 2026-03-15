"""
backend/modules/ai_content_detector.py
Phase 8 — AI-Generated Content Detection Engine
Uses Hello-SimpleAI/chatgpt-detector-roberta (loaded as "ai_text_detector")
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_CHARS            = 8000      # truncate very long inputs before scoring
MIN_CHARS            = 40        # minimum text length worth analysing
SENTENCE_MAX_TOKENS  = 512       # model hard limit — sentences longer than this are chunked
AI_THRESHOLD_HIGH    = 0.75      # above this → AI_GENERATED
AI_THRESHOLD_MED     = 0.45      # above this → MIXED


# ══════════════════════════════════════════════════════════════════════════════
# TEXT EXTRACTION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def extract_text_from_url(url: str, timeout: int = 8) -> str:
    """Fetch a URL and strip HTML tags to get plain text."""
    try:
        import requests
        from html.parser import HTMLParser

        class _Stripper(HTMLParser):
            def __init__(self):
                super().__init__()
                self._parts = []
                self._skip  = False

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style", "noscript"):
                    self._skip = True

            def handle_endtag(self, tag):
                if tag in ("script", "style", "noscript"):
                    self._skip = False

            def handle_data(self, data):
                if not self._skip:
                    stripped = data.strip()
                    if stripped:
                        self._parts.append(stripped)

            def get_text(self):
                return " ".join(self._parts)

        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "PhishGuard/1.0"})
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "")
        if "html" in ct:
            parser = _Stripper()
            parser.feed(resp.text)
            return parser.get_text()
        return resp.text

    except Exception as ex:
        logger.warning("URL fetch failed for %s: %s", url, ex)
        return ""


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """Extract plain text from uploaded file bytes."""
    fn = filename.lower()

    # Plain text variants
    if fn.endswith((".txt", ".csv", ".log", ".md")):
        return file_bytes.decode("utf-8", errors="ignore")

    # HTML / EML
    if fn.endswith((".html", ".htm", ".eml")):
        from html.parser import HTMLParser

        class _Strip(HTMLParser):
            def __init__(self):
                super().__init__()
                self._parts = []
                self._skip  = False

            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style"):
                    self._skip = True

            def handle_endtag(self, tag):
                if tag in ("script", "style"):
                    self._skip = False

            def handle_data(self, data):
                if not self._skip and data.strip():
                    self._parts.append(data.strip())

            def get_text(self):
                return " ".join(self._parts)

        p = _Strip()
        p.feed(file_bytes.decode("utf-8", errors="ignore"))
        return p.get_text()

    # PDF
    if fn.endswith(".pdf"):
        try:
            import io
            from pdfminer.high_level import extract_text
            return extract_text(io.BytesIO(file_bytes))
        except Exception:
            return ""

    # DOCX
    if fn.endswith(".docx"):
        try:
            import io, zipfile
            from xml.etree import ElementTree as ET
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                xml_content = z.read("word/document.xml")
            root  = ET.fromstring(xml_content)
            ns    = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            texts = [t.text for t in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
                     if t.text]
            return " ".join(texts)
        except Exception:
            return ""

    # Fallback — try raw decode
    return file_bytes.decode("utf-8", errors="ignore")


# ══════════════════════════════════════════════════════════════════════════════
# SENTENCE SPLITTING
# ══════════════════════════════════════════════════════════════════════════════

def split_sentences(text: str) -> list:
    """
    Split text into sentences using a simple regex.
    Keeps sentences that are at least 15 characters long.
    """
    raw = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in raw if len(s.strip()) >= 15]


# ══════════════════════════════════════════════════════════════════════════════
# MODEL SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _score_text_chunk(pipeline, text: str) -> float:
    """
    Run one text chunk through the pipeline.
    Returns probability that the text is AI-generated (0.0–1.0).
    Label mapping:
      "ChatGPT" / "Fake" / "machine" → AI probability = score
      "Human"  / "Real" / "human"    → AI probability = 1 - score
    """
    try:
        outputs = pipeline(
            text[:SENTENCE_MAX_TOKENS],
            truncation=True,
            max_length=512,
        )
        # outputs is a list of dicts: [{"label": "...", "score": float}]
        if isinstance(outputs, list):
            outputs = outputs[0]

        label = outputs.get("label", "").lower()
        score = float(outputs.get("score", 0.5))

        ai_labels = ("chatgpt", "fake", "machine", "ai", "generated")
        if any(kw in label for kw in ai_labels):
            return round(score, 4)
        else:
            return round(1.0 - score, 4)

    except Exception as ex:
        logger.warning("Scoring chunk failed: %s", ex)
        return 0.5   # neutral fallback


def score_sentences(pipeline, sentences: list) -> list:
    """Score each sentence individually. Returns list of dicts."""
    results = []
    for sent in sentences:
        ai_prob = _score_text_chunk(pipeline, sent)
        results.append({
            "sentence":    sent[:300],   # cap for JSON safety
            "ai_prob":     ai_prob,
            "label":       _prob_to_label(ai_prob),
        })
    return results


# ══════════════════════════════════════════════════════════════════════════════
# VERDICT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _prob_to_label(prob: float) -> str:
    if prob >= AI_THRESHOLD_HIGH:
        return "AI_GENERATED"
    if prob >= AI_THRESHOLD_MED:
        return "MIXED"
    return "HUMAN"


def _compute_overall_prob(sentence_scores: list) -> float:
    """Weighted average — longer sentences count more."""
    if not sentence_scores:
        return 0.0
    total_weight = sum(len(s["sentence"]) for s in sentence_scores)
    if total_weight == 0:
        return 0.0
    weighted = sum(
        s["ai_prob"] * len(s["sentence"]) for s in sentence_scores
    )
    return round(weighted / total_weight, 4)


def _build_explanation(verdict: str, ai_prob: float,
                        sentence_scores: list, source_ref: str) -> str:
    pct = int(ai_prob * 100)
    ai_count   = sum(1 for s in sentence_scores if s["label"] == "AI_GENERATED")
    mixed_count= sum(1 for s in sentence_scores if s["label"] == "MIXED")
    total      = len(sentence_scores)

    if verdict == "AI_GENERATED":
        base = (
            f"Content is very likely AI-generated ({pct}% probability). "
            f"{ai_count} of {total} sentence(s) scored above the AI threshold."
        )
    elif verdict == "MIXED":
        base = (
            f"Content shows mixed signals ({pct}% AI probability). "
            f"{ai_count} AI-flagged and {mixed_count} borderline sentence(s) detected."
        )
    else:
        base = (
            f"Content appears to be human-written ({pct}% AI probability). "
            f"No strong AI-generation signals detected."
        )

    if source_ref:
        base += f" Source: {source_ref[:80]}."

    return base


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def detect_ai_content(
    text:       str,
    source_ref: str = "",
    input_type: str = "text",
) -> dict:
    """
    Main entry point called by the FastAPI endpoint.
    Returns a flat dict compatible with the standard module_results schema.

    Args:
        text:       Plain text to analyse.
        source_ref: URL or filename the text came from (for display only).
        input_type: "text" | "url" | "file"
    """
    result = {
        "input_type":     input_type,
        "source_ref":     source_ref,
        "input_preview":  "",
        "char_count":     0,
        "sentence_count": 0,
        "ai_probability": 0.0,
        "verdict":        "HUMAN",
        "risk_score":     0.0,
        "sentence_scores": [],
        "explanation":    "",
        "error":          None,
    }

    # ── Guard: too short ──
    text = text.strip()
    if len(text) < MIN_CHARS:
        result["error"]       = "Text too short for reliable detection (min 40 chars)."
        result["explanation"] = result["error"]
        return result

    # ── Truncate very long inputs ──
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS]

    result["input_preview"] = text[:500]
    result["char_count"]    = len(text)

    # ── Load model ──
    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("ai_text_detector")
        if pipeline is None:
            raise RuntimeError("ai_text_detector model not loaded")
    except Exception as ex:
        result["error"]       = f"Model unavailable: {str(ex)[:100]}"
        result["explanation"] = result["error"]
        return result

    # ── Score full text first (overall signal) ──
    overall_raw = _score_text_chunk(pipeline, text[:SENTENCE_MAX_TOKENS])

    # ── Score per sentence ──
    sentences = split_sentences(text)
    # Cap at 40 sentences to keep latency reasonable
    sentences = sentences[:40]
    result["sentence_count"]  = len(sentences)

    if sentences:
        result["sentence_scores"] = score_sentences(pipeline, sentences)
        result["ai_probability"]  = _compute_overall_prob(result["sentence_scores"])
    else:
        # Fallback if splitter returned nothing — use whole-text score
        result["sentence_scores"] = [{
            "sentence": text[:300],
            "ai_prob":  overall_raw,
            "label":    _prob_to_label(overall_raw),
        }]
        result["ai_probability"] = overall_raw
        result["sentence_count"] = 1

    # ── Verdict & risk score ──
    result["verdict"]    = _prob_to_label(result["ai_probability"])
    result["risk_score"] = round(result["ai_probability"] * 100, 2)

    # ── Explanation ──
    result["explanation"] = _build_explanation(
        result["verdict"],
        result["ai_probability"],
        result["sentence_scores"],
        source_ref,
    )

    return result