# feature_extractor.py
# URL Feature Engineering for the scikit-learn Random Forest classifier.
#
# Feature vector layout (24 features total):
#   [0]  url_length
#   [1]  domain_length
#   [2]  path_length
#   [3]  num_dots
#   [4]  num_hyphens
#   [5]  num_underscores
#   [6]  num_slashes
#   [7]  num_at_symbols
#   [8]  num_question_marks
#   [9]  num_equals
#   [10] num_ampersands
#   [11] num_digits
#   [12] digit_ratio
#   [13] special_char_ratio
#   [14] subdomain_depth
#   [15] has_ip_address
#   [16] has_https
#   [17] has_http
#   [18] is_shortener
#   [19] has_suspicious_tld
#   [20] has_at_in_domain
#   [21] has_double_slash
#   [22] domain_entropy
#   [23] path_entropy

import re
import math
import logging
from urllib.parse import urlparse

import numpy as np

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_at_symbols",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_digits",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_depth",
    "has_ip_address",
    "has_https",
    "has_http",
    "is_shortener",
    "has_suspicious_tld",
    "has_at_in_domain",
    "has_double_slash",
    "domain_entropy",
    "path_entropy",
]

# Total number of features — must match len(FEATURE_NAMES)
N_FEATURES = len(FEATURE_NAMES)   # 24

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clck.ru",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "s.id"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga", ".cf",
    ".pw", ".work", ".loan", ".click", ".link", ".buzz", ".fun",
    ".online", ".site", ".space", ".tech", ".icu", ".vip",
    ".zip", ".mov", ".phd", ".foo"
}

IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_feature_names() -> list:
    """
    Return the ordered list of feature names matching the vector layout.
    Used by the training script to label feature importances.
    """
    return list(FEATURE_NAMES)


def get_n_features() -> int:
    """Return the total number of features in the vector."""
    return N_FEATURES


def extract_features(url: str) -> np.ndarray:
    """
    Convert a single URL string into a 24-dimensional numeric feature vector.

    Args:
        url: Raw URL string (http:// or https://)

    Returns:
        numpy array of shape (24,) with dtype float32.
        Returns a zero vector if extraction fails — never raises.
    """
    try:
        return np.array(_compute_features(url), dtype=np.float32)
    except Exception as e:
        logger.warning(f"Feature extraction failed for '{url[:60]}': {e}")
        return np.zeros(N_FEATURES, dtype=np.float32)


def extract_features_batch(urls: list) -> np.ndarray:
    """
    Convert a list of URLs into a 2D feature matrix.

    Args:
        urls: List of URL strings.

    Returns:
        numpy array of shape (len(urls), 24) with dtype float32.
    """
    if not urls:
        return np.zeros((0, N_FEATURES), dtype=np.float32)

    rows = [extract_features(url) for url in urls]
    return np.vstack(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Feature computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_features(url: str) -> list:
    """
    Compute all 24 features for a URL.
    Returns a plain Python list of floats in FEATURE_NAMES order.
    """
    url    = url.strip()
    parsed = urlparse(url)

    domain  = parsed.netloc.lower()
    path    = parsed.path.lower()

    # Strip port number from domain (e.g. example.com:8080 → example.com)
    domain_no_port = domain.split(":")[0]

    # Subdomain depth = number of labels beyond registered domain + TLD
    domain_parts    = domain_no_port.split(".")
    subdomain_depth = max(0, len(domain_parts) - 2)

    # URL body without scheme — used for character ratio calculations
    url_body     = url.replace("https://", "").replace("http://", "")
    url_body_len = max(len(url_body), 1)   # guard against division by zero

    # ── Length features ────────────────────────────────────────────────────
    url_length    = float(len(url))
    domain_length = float(len(domain_no_port))
    path_length   = float(len(path))

    # ── Character count features ───────────────────────────────────────────
    num_dots           = float(url.count("."))
    num_hyphens        = float(url.count("-"))
    num_underscores    = float(url.count("_"))
    num_slashes        = float(url.count("/"))
    num_at_symbols     = float(url.count("@"))
    num_question_marks = float(url.count("?"))
    num_equals         = float(url.count("="))
    num_ampersands     = float(url.count("&"))
    num_digits         = float(sum(c.isdigit() for c in url_body))

    # ── Ratio features ─────────────────────────────────────────────────────
    digit_ratio = num_digits / url_body_len

    special_chars = sum(
        1 for c in url_body
        if not c.isalnum() and c not in (".", "-", "_", "/", ":")
    )
    special_char_ratio = special_chars / url_body_len

    # ── Boolean features (stored as 0.0 or 1.0) ───────────────────────────
    has_ip_address = float(
        bool(IP_PATTERN.match(domain_no_port))
    )
    has_https = float(url.lower().startswith("https://"))
    has_http  = float(url.lower().startswith("http://"))

    clean_domain = domain_no_port.lstrip("www.")
    is_shortener = float(clean_domain in SHORTENER_DOMAINS)

    tld = ("." + domain_no_port.split(".")[-1]) if "." in domain_no_port else ""
    has_suspicious_tld = float(tld in SUSPICIOUS_TLDS)

    has_at_in_domain = float("@" in domain)
    has_double_slash = float("//" in path)

    # ── Entropy features ───────────────────────────────────────────────────
    domain_entropy = _shannon_entropy(domain_no_port)
    path_entropy   = _shannon_entropy(path)

    return [
        url_length,          # [0]
        domain_length,       # [1]
        path_length,         # [2]
        num_dots,            # [3]
        num_hyphens,         # [4]
        num_underscores,     # [5]
        num_slashes,         # [6]
        num_at_symbols,      # [7]
        num_question_marks,  # [8]
        num_equals,          # [9]
        num_ampersands,      # [10]
        num_digits,          # [11]
        digit_ratio,         # [12]
        special_char_ratio,  # [13]
        float(subdomain_depth),  # [14]
        has_ip_address,      # [15]
        has_https,           # [16]
        has_http,            # [17]
        is_shortener,        # [18]
        has_suspicious_tld,  # [19]
        has_at_in_domain,    # [20]
        has_double_slash,    # [21]
        domain_entropy,      # [22]
        path_entropy,        # [23]
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.
    Higher value = more random character distribution.
    Used to detect DGA-generated domain names.
    """
    if not s:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    length  = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)