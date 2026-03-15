# rule_engine.py
# Rule-Based Phishing Detection Engine.
#
# This module applies deterministic heuristic rules to URLs and
# email content. No ML model is needed — these are hand-crafted
# pattern checks based on known phishing techniques.
#
# Every rule:
#   - Has a unique rule_id and human-readable name
#   - Carries a severity weight (points contributed to risk score)
#   - Returns a RuleHit dict when triggered
#   - Is completely independent — rules never call each other
#
# The engine runs all rules and returns:
#   - A list of RuleHit dicts (triggered rules only)
#   - A total rule_score (0–100, capped)
#   - A severity summary (how many LOW / MEDIUM / HIGH / CRITICAL hits)

import re
import math
import base64
import logging
import unicodedata
from typing import Optional
from urllib.parse import urlparse, unquote, parse_qs

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Rule registry — every rule is defined here as a dict.
# Fields:
#   rule_id:     unique string identifier
#   name:        short human-readable name shown on dashboard
#   description: what the rule checks and why it matters
#   severity:    LOW / MEDIUM / HIGH / CRITICAL
#   weight:      points added to the rule score when triggered
# ─────────────────────────────────────────────────────────────────────────────

RULE_REGISTRY = [
    {
        "rule_id":     "URL_TOO_LONG",
        "name":        "URL length > 75 characters",
        "description": (
            "Phishing URLs are often excessively long to obscure the real "
            "domain or embed Base64-encoded payloads. Legitimate URLs are "
            "typically under 75 characters."
        ),
        "severity": "MEDIUM",
        "weight":   8
    },
    {
        "rule_id":     "IP_IN_URL",
        "name":        "IP address used instead of domain",
        "description": (
            "Using a raw IP address (e.g. http://192.168.1.1/login) instead "
            "of a domain name is a strong phishing signal — legitimate services "
            "never ask users to visit bare IP addresses."
        ),
        "severity": "HIGH",
        "weight":   15
    },
    {
        "rule_id":     "EXCESSIVE_SUBDOMAINS",
        "name":        "Excessive subdomain depth (> 3 levels)",
        "description": (
            "Phishers add fake brand subdomains to make URLs look legitimate: "
            "e.g. paypal.com.accounts.login.evil.xyz — the real domain is evil.xyz. "
            "More than 3 subdomain levels is suspicious."
        ),
        "severity": "HIGH",
        "weight":   12
    },
    {
        "rule_id":     "SUSPICIOUS_TLD",
        "name":        "Suspicious top-level domain",
        "description": (
            "Certain TLDs (.xyz, .tk, .top, .club, .gq, .ml, .ga, .cf, .pw) "
            "are disproportionately used for phishing because they are free or "
            "very cheap to register."
        ),
        "severity": "MEDIUM",
        "weight":   10
    },
    {
        "rule_id":     "SPECIAL_CHARS_IN_DOMAIN",
        "name":        "Special characters in domain",
        "description": (
            "Characters like @, %, and // in the domain portion of a URL "
            "can confuse parsers and trick users. For example, "
            "http://trusted.com@evil.com — the browser navigates to evil.com."
        ),
        "severity": "HIGH",
        "weight":   14
    },
    {
        "rule_id":     "BRAND_KEYWORD_SPOOFING",
        "name":        "Brand keyword in non-brand domain",
        "description": (
            "The URL contains a well-known brand name (paypal, google, amazon, "
            "apple, microsoft, netflix...) but the registered domain is not "
            "that brand's official domain. Classic typosquatting technique."
        ),
        "severity": "HIGH",
        "weight":   15
    },
    {
        "rule_id":     "PUNYCODE_DOMAIN",
        "name":        "Punycode / IDN domain detected",
        "description": (
            "Internationalized Domain Names (IDN) use punycode encoding "
            "(xn-- prefix) to represent non-ASCII characters. Attackers use "
            "this to register visually identical domains: аpple.com (Cyrillic а) "
            "vs apple.com (Latin a)."
        ),
        "severity": "HIGH",
        "weight":   15
    },
    {
        "rule_id":     "HOMOGLYPH_ATTACK",
        "name":        "Homoglyph / lookalike character detected",
        "description": (
            "The domain contains characters that look identical to others: "
            "rn → m, 0 → o, 1 → l, vv → w. Attackers register these to "
            "impersonate brands at a glance."
        ),
        "severity": "CRITICAL",
        "weight":   20
    },
    {
        "rule_id":     "ENCODED_URL",
        "name":        "URL encoding / obfuscation detected",
        "description": (
            "The URL contains percent-encoding (%XX), hex encoding, or "
            "Base64-encoded segments used to hide the real destination "
            "from URL scanners and email filters."
        ),
        "severity": "HIGH",
        "weight":   12
    },
    {
        "rule_id":     "OPEN_REDIRECT",
        "name":        "Open redirect parameter detected",
        "description": (
            "The URL contains query parameters commonly used for open redirects: "
            "?url=, ?redirect=, ?next=, ?goto=, ?return= etc. Attackers chain "
            "trusted domains with open redirects to bypass filters."
        ),
        "severity": "HIGH",
        "weight":   13
    },
    {
        "rule_id":     "DOUBLE_SLASH_IN_PATH",
        "name":        "Double slash in URL path",
        "description": (
            "A // in the URL path (after the domain) can confuse parsers "
            "and is often used to obfuscate redirect destinations."
        ),
        "severity": "MEDIUM",
        "weight":   6
    },
    {
        "rule_id":     "HTTPS_IN_SUBDOMAIN",
        "name":        "HTTPS keyword used as subdomain",
        "description": (
            "URLs like https://https.evil.com trick users into thinking "
            "they are on a secure connection. The word 'https' is used "
            "as a subdomain label."
        ),
        "severity": "HIGH",
        "weight":   14
    },
    {
        "rule_id":     "HIGH_DIGIT_RATIO",
        "name":        "High ratio of digits in domain",
        "description": (
            "Legitimate domains rarely contain more than 2–3 digits. "
            "A domain like 192-168-secure-login.com is suspicious. "
            "Digit ratio > 35% of total domain characters is flagged."
        ),
        "severity": "MEDIUM",
        "weight":   7
    },
    {
        "rule_id":     "HIGH_ENTROPY",
        "name":        "High entropy domain name (random-looking)",
        "description": (
            "Domain names generated by domain generation algorithms (DGAs) "
            "used in phishing C2 infrastructure have high Shannon entropy "
            "because they look random (e.g. xkqzfjmp.com). "
            "Entropy > 3.8 bits/char is flagged."
        ),
        "severity": "MEDIUM",
        "weight":   8
    },
    {
        "rule_id":     "URGENT_EMAIL_SUBJECT",
        "name":        "Urgent / fear language in email subject",
        "description": (
            "Phishing emails use urgency and fear to bypass rational thinking: "
            "'Account suspended', 'Verify now', 'Unusual activity detected'. "
            "Multiple urgency keywords in the subject is a strong signal."
        ),
        "severity": "MEDIUM",
        "weight":   8
    },
    {
        "rule_id":     "CREDENTIAL_FORM_KEYWORDS",
        "name":        "Credential harvesting keywords in email body",
        "description": (
            "The email body contains combinations of keywords associated with "
            "credential phishing: password, username, login, verify, "
            "confirm, update payment, bank details, etc."
        ),
        "severity": "HIGH",
        "weight":   12
    },
    {
        "rule_id":     "MISMATCHED_LINK_TEXT",
        "name":        "Link text domain differs from href domain",
        "description": (
            "An email contains a hyperlink where the visible text shows one "
            "domain (e.g. 'www.paypal.com') but the actual href points to a "
            "completely different domain. Classic phishing deception technique."
        ),
        "severity": "CRITICAL",
        "weight":   20
    },
    {
        "rule_id":     "MULTIPLE_AT_IN_URL",
        "name":        "Multiple @ symbols in URL",
        "description": (
            "A URL with multiple @ signs is always suspicious. Browsers use "
            "the last @ to determine the host, so everything before it "
            "is treated as credentials — used to spoof the visible domain."
        ),
        "severity": "CRITICAL",
        "weight":   18
    },
]

# Build a lookup dict for fast access by rule_id
RULE_LOOKUP = {r["rule_id"]: r for r in RULE_REGISTRY}


# ─────────────────────────────────────────────────────────────────────────────
# Known brand domains — used by BRAND_KEYWORD_SPOOFING rule
# Format: keyword → set of legitimate domains that ARE allowed to use it
# ─────────────────────────────────────────────────────────────────────────────

BRAND_DOMAINS = {
    "paypal":    {"paypal.com", "paypal.co.uk", "paypal.com.au"},
    "google":    {"google.com", "google.co.uk", "googleapis.com", "googleusercontent.com", "goog.le"},
    "apple":     {"apple.com", "icloud.com", "me.com", "apple.co"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "hotmail.com", "msn.com", "office.com", "office365.com"},
    "amazon":    {"amazon.com", "amazon.co.uk", "aws.amazon.com", "amazonaws.com"},
    "netflix":   {"netflix.com", "nflxso.net"},
    "facebook":  {"facebook.com", "fb.com", "fbcdn.net", "messenger.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "twitter":   {"twitter.com", "t.co", "twimg.com"},
    "linkedin":  {"linkedin.com", "licdn.com"},
    "github":    {"github.com", "githubusercontent.com", "github.io"},
    "dropbox":   {"dropbox.com", "dropboxstatic.com"},
    "bank":      set(),    # any domain with 'bank' that isn't a known bank
    "secure":    set(),
    "verify":    set(),
    "account":   set(),
    "login":     set(),
    "signin":    set(),
    "update":    set(),
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga", ".cf",
    ".pw", ".work", ".loan", ".click", ".link", ".buzz", ".fun",
    ".online", ".site", ".space", ".tech", ".icu", ".vip"
}

# Open redirect parameter names
OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirecturl",
    "return", "return_url", "returnurl", "returnto",
    "next", "goto", "dest", "destination", "target",
    "link", "out", "checkout", "continue", "redir",
    "r", "u", "forward"
}

# Urgency keywords for email subject analysis
URGENCY_KEYWORDS = [
    "urgent", "verify now", "verify your", "account suspended",
    "action required", "immediate", "expire", "expires soon",
    "unusual activity", "unauthorized", "click here", "confirm identity",
    "update payment", "update your", "limited time", "act now",
    "security alert", "your account has been", "suspicious login",
    "we detected", "important notice", "final notice", "last chance"
]

# Credential harvesting keywords (email body)
CREDENTIAL_KEYWORDS = [
    "password", "username", "login", "sign in", "signin",
    "verify your identity", "confirm your", "bank details",
    "credit card", "social security", "date of birth",
    "update your payment", "billing information", "account information",
    "enter your", "provide your", "submit your credentials"
]

# Homoglyph character substitution patterns
HOMOGLYPH_PATTERNS = [
    # (suspicious_pattern, what_it_spoofs, description)
    (r'rn',         'm',      'rn → m confusion'),
    (r'vv',         'w',      'vv → w confusion'),
    (r'cl',         'd',      'cl → d confusion'),
    (r'[0o]',       'o/0',    '0 ↔ o confusion'),
    (r'[1il]',      'l/i/1',  '1 ↔ l ↔ i confusion'),
    (r'paypa[l1]',  'paypal', 'PayPal homoglyph'),
    (r'g[o0]{2}gle','google', 'Google homoglyph'),
    (r'arnazon',    'amazon', 'Amazon homoglyph'),
    (r'micros[o0]ft','microsoft','Microsoft homoglyph'),
    (r'app1e',      'apple',  'Apple homoglyph'),
]


# ─────────────────────────────────────────────────────────────────────────────
# Main entry points
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url_rules(url: str) -> dict:
    """
    Run all URL-applicable heuristic rules against a single URL.

    Args:
        url: Raw URL string.

    Returns:
        {
          "url":            str,
          "hits":           list[RuleHit],
          "rule_score":     float (0–100),
          "severity_counts":{"LOW": N, "MEDIUM": N, "HIGH": N, "CRITICAL": N},
          "triggered_ids":  list[str]
        }
    """
    url     = url.strip()
    hits    = []

    # Run every URL rule
    _run_url_rule(hits, _check_url_length,          url)
    _run_url_rule(hits, _check_ip_in_url,           url)
    _run_url_rule(hits, _check_excessive_subdomains,url)
    _run_url_rule(hits, _check_suspicious_tld,      url)
    _run_url_rule(hits, _check_special_chars,       url)
    _run_url_rule(hits, _check_brand_spoofing,      url)
    _run_url_rule(hits, _check_punycode,            url)
    _run_url_rule(hits, _check_homoglyphs,          url)
    _run_url_rule(hits, _check_url_encoding,        url)
    _run_url_rule(hits, _check_open_redirect,       url)
    _run_url_rule(hits, _check_double_slash,        url)
    _run_url_rule(hits, _check_https_in_subdomain,  url)
    _run_url_rule(hits, _check_digit_ratio,         url)
    _run_url_rule(hits, _check_entropy,             url)
    _run_url_rule(hits, _check_multiple_at,         url)

    return _build_result(url=url, input_type="url", hits=hits)


def analyze_email_rules(
    subject:   str = "",
    body_text: str = "",
    body_html: str = "",
    urls:      Optional[list] = None
) -> dict:
    """
    Run all email-applicable heuristic rules against email content.

    Args:
        subject:   Email subject line.
        body_text: Plain text body.
        body_html: HTML body (used for mismatched link detection).
        urls:      List of URL dicts from email_parser (optional).
                   Each dict has at minimum a "raw" key.

    Returns:
        Same structure as analyze_url_rules() but input_type="email".
        Also includes per-URL rule results for all embedded URLs.
    """
    hits     = []
    urls     = urls or []
    url_strs = [u.get("raw", "") for u in urls if u.get("raw")]

    # Email-specific rules
    _run_email_rule(hits, _check_urgent_subject,       subject)
    _run_email_rule(hits, _check_credential_keywords,  body_text)
    _run_email_rule(hits, _check_mismatched_links,     body_html)

    # Also run URL rules on every embedded URL
    url_results = []
    for url in url_strs[:20]:   # cap at 20 to prevent slow scans
        url_result = analyze_url_rules(url)
        url_results.append(url_result)
        # Roll URL rule hits into the email hit list with source annotation
        for hit in url_result["hits"]:
            # Annotate so the dashboard can show which URL triggered the rule
            annotated = dict(hit)
            annotated["triggered_on"] = url[:80]
            annotated["source"]       = "embedded_url"
            hits.append(annotated)

    result = _build_result(
        url=f"email ({len(url_strs)} URLs)",
        input_type="email",
        hits=hits
    )
    result["url_results"] = url_results
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Individual rule check functions
# Each returns None (rule not triggered) or a RuleHit dict.
# ─────────────────────────────────────────────────────────────────────────────

def _check_url_length(url: str) -> Optional[dict]:
    if len(url) > 75:
        return _hit(
            "URL_TOO_LONG",
            detail=f"URL is {len(url)} characters long (threshold: 75)",
            evidence=url[:80] + "..." if len(url) > 80 else url
        )


def _check_ip_in_url(url: str) -> Optional[dict]:
    # Matches http://192.168.1.1/... or http://10.0.0.1/...
    ip_pattern = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}', re.IGNORECASE)
    if ip_pattern.match(url):
        ip = re.search(r'(\d{1,3}\.){3}\d{1,3}', url)
        return _hit(
            "IP_IN_URL",
            detail=f"IP address found in URL: {ip.group() if ip else 'detected'}",
            evidence=url[:100]
        )


def _check_excessive_subdomains(url: str) -> Optional[dict]:
    try:
        domain = urlparse(url).netloc.lower()
        domain = domain.split(":")[0]   # strip port
        # Remove www prefix before counting
        if domain.startswith("www."):
            domain = domain[4:]
        parts = domain.split(".")
        # parts[-2] and parts[-1] = registered domain + TLD
        # anything before that = subdomains
        subdomain_count = len(parts) - 2
        if subdomain_count > 3:
            return _hit(
                "EXCESSIVE_SUBDOMAINS",
                detail=f"{subdomain_count} subdomain levels detected in '{domain}'",
                evidence=domain
            )
    except Exception:
        pass


def _check_suspicious_tld(url: str) -> Optional[dict]:
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        tld    = "." + domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            return _hit(
                "SUSPICIOUS_TLD",
                detail=f"TLD '{tld}' is associated with high phishing rates",
                evidence=domain
            )
    except Exception:
        pass


def _check_special_chars(url: str) -> Optional[dict]:
    """
    Detect @ and // (outside the scheme) in the URL domain or path.
    @ in the URL means everything before it is treated as credentials.
    """
    try:
        parsed = urlparse(url)
        # Check netloc for @ (user:pass@host style — unusual in legit URLs)
        if "@" in parsed.netloc:
            return _hit(
                "SPECIAL_CHARS_IN_DOMAIN",
                detail="'@' found in URL domain — credential injection attempt",
                evidence=parsed.netloc
            )
        # Check for // in path (not the scheme //)
        path = parsed.path
        if "//" in path:
            return _hit(
                "DOUBLE_SLASH_IN_PATH",
                detail="Double slash (//) found in URL path",
                evidence=path[:80]
            )
        # Check for % sequences outside of normal query string
        if "%" in parsed.netloc:
            return _hit(
                "SPECIAL_CHARS_IN_DOMAIN",
                detail="Percent-encoding found in domain portion of URL",
                evidence=parsed.netloc
            )
    except Exception:
        pass


def _check_brand_spoofing(url: str) -> Optional[dict]:
    """
    Detect brand keywords in the domain that aren't on the official domain.
    e.g. paypal-secure-login.xyz — contains 'paypal' but domain is .xyz
    """
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        # Strip www
        if domain.startswith("www."):
            domain = domain[4:]

        for brand, official_domains in BRAND_DOMAINS.items():
            if brand not in domain:
                continue

            # Check if this IS an official domain
            is_official = any(
                domain == od or domain.endswith("." + od)
                for od in official_domains
            )
            if not is_official and official_domains:
                return _hit(
                    "BRAND_KEYWORD_SPOOFING",
                    detail=(
                        f"Brand keyword '{brand}' found in non-official domain '{domain}'. "
                        f"Official domains: {', '.join(list(official_domains)[:3])}"
                    ),
                    evidence=domain
                )
            elif not is_official and not official_domains:
                # Generic sensitive keywords (secure, login, verify, etc.)
                if brand in ("secure", "verify", "login", "signin", "account", "update"):
                    return _hit(
                        "BRAND_KEYWORD_SPOOFING",
                        detail=f"Sensitive keyword '{brand}' found in domain '{domain}'",
                        evidence=domain
                    )
    except Exception:
        pass


def _check_punycode(url: str) -> Optional[dict]:
    """
    Detect xn-- punycode prefix in the domain, which indicates an
    internationalized domain name that may visually spoof a real domain.
    """
    try:
        domain = urlparse(url).netloc.lower()
        if "xn--" in domain:
            # Try to decode the punycode to show what it looks like
            try:
                decoded = domain.encode("ascii").decode("idna")
            except Exception:
                decoded = domain
            return _hit(
                "PUNYCODE_DOMAIN",
                detail=f"Punycode IDN detected: '{domain}' renders as '{decoded}'",
                evidence=domain
            )
    except Exception:
        pass


def _check_homoglyphs(url: str) -> Optional[dict]:
    """
    Scan the domain for character combinations that visually resemble
    other characters (homoglyph / lookalike attacks).
    """
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        for pattern, spoofs, description in HOMOGLYPH_PATTERNS:
            if re.search(pattern, domain):
                return _hit(
                    "HOMOGLYPH_ATTACK",
                    detail=(
                        f"Homoglyph pattern detected in '{domain}': "
                        f"{description} (spoofs '{spoofs}')"
                    ),
                    evidence=domain
                )
    except Exception:
        pass


def _check_url_encoding(url: str) -> Optional[dict]:
    """
    Detect excessive percent-encoding or Base64 segments in the URL
    that are used to hide the real content from URL scanners.
    """
    # Count percent-encoded characters
    pct_matches = re.findall(r'%[0-9a-fA-F]{2}', url)
    if len(pct_matches) > 5:
        return _hit(
            "ENCODED_URL",
            detail=f"{len(pct_matches)} percent-encoded characters detected in URL",
            evidence=url[:100]
        )

    # Check for Base64-like segments in query parameters
    try:
        qs = urlparse(url).query
        for val in parse_qs(qs).values():
            for v in val:
                if len(v) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', v):
                    try:
                        decoded = base64.b64decode(v + "==").decode("utf-8", errors="ignore")
                        if "http" in decoded or "://" in decoded:
                            return _hit(
                                "ENCODED_URL",
                                detail=(
                                    f"Base64-encoded URL found in query parameter. "
                                    f"Decoded: {decoded[:60]}..."
                                ),
                                evidence=v[:60]
                            )
                    except Exception:
                        pass
    except Exception:
        pass


def _check_open_redirect(url: str) -> Optional[dict]:
    """
    Detect query parameters commonly used for open redirects.
    These let attackers send users through trusted domains to evil destinations.
    """
    try:
        qs     = parse_qs(urlparse(url).query)
        params = {k.lower() for k in qs.keys()}
        matched = params & OPEN_REDIRECT_PARAMS

        if matched:
            # Check if the redirect value points to a different domain
            for param in matched:
                values = qs.get(param, [])
                for val in values:
                    if val.startswith(("http://", "https://")):
                        return _hit(
                            "OPEN_REDIRECT",
                            detail=(
                                f"Open redirect parameter '?{param}=' found. "
                                f"Redirect target: {val[:60]}"
                            ),
                            evidence=url[:100]
                        )
                # Param exists but value isn't a URL — still flag it
                return _hit(
                    "OPEN_REDIRECT",
                    detail=f"Potential open redirect parameter '?{param}=' detected",
                    evidence=url[:100]
                )
    except Exception:
        pass


def _check_double_slash(url: str) -> Optional[dict]:
    """Detect // in the URL path (after the domain)."""
    try:
        path = urlparse(url).path
        if "//" in path:
            return _hit(
                "DOUBLE_SLASH_IN_PATH",
                detail="Double slash (//) found in URL path — parser confusion technique",
                evidence=path[:80]
            )
    except Exception:
        pass


def _check_https_in_subdomain(url: str) -> Optional[dict]:
    """Detect 'https' used as a subdomain label to fool users."""
    try:
        domain = urlparse(url).netloc.lower()
        parts  = domain.split(".")
        # Any label other than the TLD and registered domain
        subdomains = parts[:-2] if len(parts) > 2 else []
        if "https" in subdomains or "http" in subdomains:
            return _hit(
                "HTTPS_IN_SUBDOMAIN",
                detail=(
                    f"'https' used as subdomain label in '{domain}' — "
                    "tricks users into thinking the connection is secure"
                ),
                evidence=domain
            )
    except Exception:
        pass


def _check_digit_ratio(url: str) -> Optional[dict]:
    """
    Flag domains where more than 35% of characters are digits.
    e.g. 192-168-1-secure.com or 12345bank.com
    """
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        if not domain:
            return None
        digits = sum(1 for c in domain if c.isdigit())
        ratio  = digits / len(domain)
        if ratio > 0.35 and digits > 3:
            return _hit(
                "HIGH_DIGIT_RATIO",
                detail=(
                    f"Domain '{domain}' has {int(ratio*100)}% digit characters "
                    f"({digits}/{len(domain)}) — typical of phishing infrastructure"
                ),
                evidence=domain
            )
    except Exception:
        pass


def _check_entropy(url: str) -> Optional[dict]:
    """
    Calculate Shannon entropy of the domain name.
    High entropy (> 3.8) suggests a DGA or randomly generated domain.
    """
    try:
        domain = urlparse(url).netloc.lower().split(":")[0]
        # Use only the second-level domain (not TLD or subdomains)
        parts  = domain.split(".")
        sld    = parts[-2] if len(parts) >= 2 else domain

        if len(sld) < 6:
            return None   # too short to compute meaningful entropy

        entropy = _shannon_entropy(sld)
        if entropy > 3.8:
            return _hit(
                "HIGH_ENTROPY",
                detail=(
                    f"Domain '{sld}' has Shannon entropy of {entropy:.2f} bits/char "
                    f"(threshold: 3.8) — suggests DGA or randomly generated domain"
                ),
                evidence=sld
            )
    except Exception:
        pass


def _check_multiple_at(url: str) -> Optional[dict]:
    """Detect multiple @ signs in the URL — always malicious."""
    at_count = url.count("@")
    if at_count >= 2:
        return _hit(
            "MULTIPLE_AT_IN_URL",
            detail=(
                f"URL contains {at_count} '@' characters. "
                "Browser uses the last @ as credential separator — "
                "everything before it is ignored as username:password."
            ),
            evidence=url[:100]
        )


# ─────────────────────────────────────────────────────────────────────────────
# Email-specific rules
# ─────────────────────────────────────────────────────────────────────────────

def _check_urgent_subject(subject: str) -> Optional[dict]:
    """Flag urgency/fear keywords in the email subject line."""
    if not subject:
        return None

    subject_lower = subject.lower()
    matched = [kw for kw in URGENCY_KEYWORDS if kw in subject_lower]

    if len(matched) >= 1:
        return _hit(
            "URGENT_EMAIL_SUBJECT",
            detail=(
                f"Subject contains urgency keywords: {matched[:3]}. "
                "Phishers use fear and urgency to bypass rational thinking."
            ),
            evidence=subject[:100]
        )


def _check_credential_keywords(body_text: str) -> Optional[dict]:
    """Detect credential harvesting language in the email body."""
    if not body_text:
        return None

    body_lower = body_text.lower()
    matched = [kw for kw in CREDENTIAL_KEYWORDS if kw in body_lower]

    if len(matched) >= 2:
        return _hit(
            "CREDENTIAL_FORM_KEYWORDS",
            detail=(
                f"Email body contains {len(matched)} credential-harvesting keywords: "
                f"{matched[:4]}"
            ),
            evidence=f"{len(matched)} keywords found in body"
        )


def _check_mismatched_links(body_html: str) -> Optional[dict]:
    """
    Parse HTML body to detect links where the visible text shows a
    different domain than the actual href attribute.

    e.g. <a href="http://evil.com">www.paypal.com</a>
    """
    if not body_html:
        return None

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body_html, "lxml")

        for tag in soup.find_all("a", href=True):
            href     = tag.get("href", "").strip()
            text     = tag.get_text(strip=True)

            if not href.startswith(("http://", "https://")):
                continue

            href_domain = urlparse(href).netloc.lower().lstrip("www.")

            # Check if the visible link text looks like a URL
            text_lower = text.lower().strip()
            if not ("." in text_lower and len(text_lower) > 4):
                continue

            # Try to extract a domain from the link text
            text_match = re.search(
                r'(?:https?://)?([a-z0-9\-\.]+\.[a-z]{2,})',
                text_lower
            )
            if not text_match:
                continue

            text_domain = text_match.group(1).lstrip("www.")

            # If the domains differ significantly — flag it
            if (text_domain and href_domain and
                    text_domain != href_domain and
                    not href_domain.endswith(text_domain) and
                    not text_domain.endswith(href_domain)):
                return _hit(
                    "MISMATCHED_LINK_TEXT",
                    detail=(
                        f"Link text shows '{text_domain}' "
                        f"but href points to '{href_domain}'"
                    ),
                    evidence=f"Text: {text[:40]} | href: {href[:60]}"
                )
    except Exception as e:
        logger.warning(f"Mismatched link check error: {e}")

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_url_rule(hits: list, fn, url: str) -> None:
    """Safely call a URL rule function and append hit if triggered."""
    try:
        result = fn(url)
        if result:
            hits.append(result)
    except Exception as e:
        logger.warning(f"Rule {fn.__name__} raised an exception: {e}")


def _run_email_rule(hits: list, fn, *args) -> None:
    """Safely call an email rule function and append hit if triggered."""
    try:
        result = fn(*args)
        if result:
            hits.append(result)
    except Exception as e:
        logger.warning(f"Rule {fn.__name__} raised an exception: {e}")


def _hit(rule_id: str, detail: str, evidence: str = "") -> dict:
    """
    Build a RuleHit dict from a triggered rule.

    Args:
        rule_id:  Must match a key in RULE_LOOKUP.
        detail:   Specific explanation for this particular trigger.
        evidence: The exact string that caused the trigger.
    """
    rule = RULE_LOOKUP.get(rule_id, {})
    return {
        "rule_id":     rule_id,
        "name":        rule.get("name",        rule_id),
        "description": rule.get("description", ""),
        "severity":    rule.get("severity",    "MEDIUM"),
        "weight":      rule.get("weight",      5),
        "detail":      detail,
        "evidence":    evidence,
        "source":      "direct_url"   # overridden to "embedded_url" for email scans
    }


def _build_result(url: str, input_type: str, hits: list) -> dict:
    """
    Aggregate rule hits into a final result dict.

    Score calculation:
      Sum of all hit weights, capped at 100.
      Each rule's weight is defined in RULE_REGISTRY.
    """
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    total_score     = 0.0

    for hit in hits:
        sev = hit.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_score += hit.get("weight", 5)

    rule_score     = round(min(total_score, 100.0), 2)
    triggered_ids  = list({h["rule_id"] for h in hits})

    return {
        "input":           url,
        "input_type":      input_type,
        "hits":            hits,
        "rule_score":      rule_score,
        "severity_counts": severity_counts,
        "triggered_ids":   triggered_ids,
        "total_rules_checked": len(RULE_REGISTRY),
        "total_rules_hit":     len(hits)
    }


def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.
    Higher value = more random / unpredictable character distribution.
    """
    if not s:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    length  = len(s)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def get_all_rules() -> list:
    """Return the full rule registry — used by the dashboard to display all rules."""
    return RULE_REGISTRY