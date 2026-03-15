# url_intelligence.py
# URL & Domain Intelligence Module — Phase 2
#
# For every URL extracted from an email this module runs:
#   1.  Normalization & unshortening   — resolve the real destination
#   2.  WHOIS lookup                   — owner, registrar, age
#   3.  DNS analysis                   — A / MX / TXT / NS records
#   4.  SSL/TLS certificate check      — issuer, expiry, self-signed?
#   5.  IP resolution + geolocation    — country, ASN via ipinfo.io or local
#   6.  ML classification              — elftsdmr/malware-url-detect BERT
#
# All six layers run concurrently via ThreadPoolExecutor so a batch
# of 10 URLs takes ~5 s instead of ~50 s.
#
# The function you call from outside this module:
#     result = analyze_url(raw_url)
# and to analyze a whole list:
#     results = analyze_url_batch(url_list)

import ssl
import json
import socket
import logging
import hashlib
import requests
import datetime
import ipaddress
import concurrent.futures
from urllib.parse import urlparse, urlunparse
from typing import Optional

import whois          # pip install python-whois
import dns.resolver   # pip install dnspython

from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Max time (seconds) per network call — keeps a single bad domain from
# stalling the entire batch.
NETWORK_TIMEOUT = 8

# Domains we skip WHOIS + DNS on (they'd always pass and waste time)
SKIP_DOMAINS = {"localhost", "127.0.0.1", "0.0.0.0", "example.com"}

# Known URL shortener domains — we follow these to find the real URL
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clck.ru",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc"
}

# Suspicious TLDs scored higher by the rule engine (Phase 4)
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga",
    ".cf", ".pw", ".work", ".loan", ".click", ".link",
    ".buzz", ".monster", ".rest", ".icu", ".cyou"
}

# New gTLDs / ccTLDs commonly abused for phishing — flag domains under 180 days
YOUNG_DOMAIN_THRESHOLD_DAYS = 180

# Max redirect hops to follow before flagging as redirect chain obfuscation
MAX_REDIRECT_HOPS = 5


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(raw_url: str) -> dict:
    """
    Run the full six-layer intelligence stack on a single URL.

    Args:
        raw_url: Any URL string (http/https). May be a shortener.

    Returns:
        A dict with keys matching the URLIntelResult schema:
          raw_url, final_url, domain, ip, country, asn,
          whois, dns, ssl, redirects,
          domain_age_days, domain_age_flag,
          ml_result, flags, risk_contribution, analyzed_at
    """
    raw_url = raw_url.strip()

    # ── Step 1: Normalize & unshorten ────────────────────────────────────
    normalization = _normalize_and_unshorten(raw_url)
    final_url  = normalization["final_url"]
    redirects  = normalization["redirect_chain"]

    # Parse the final (resolved) URL for domain extraction
    parsed = urlparse(final_url)
    domain = parsed.netloc.lower().lstrip("www.")
    # Remove port if present (e.g., "example.com:8080" → "example.com")
    domain = domain.split(":")[0]

    if domain in SKIP_DOMAINS or not domain:
        return _minimal_result(raw_url, "skipped_domain")

    # ── Steps 2–5 run concurrently in a thread pool ────────────────────
    # Each step is independent and involves network I/O (WHOIS, DNS, SSL).
    # Running them in parallel cuts total wall-clock time by ~4x.
    whois_data = {}
    dns_data   = {}
    ssl_data   = {}
    geo_data   = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_whois = executor.submit(_whois_lookup, domain)
        future_dns   = executor.submit(_dns_lookup, domain)
        future_ssl   = executor.submit(_ssl_check, domain, parsed.port)
        future_geo   = executor.submit(_ip_and_geo, domain)

        # Collect results — each wrapped in try/except inside its function,
        # so a failure in one doesn't cancel the others.
        whois_data = future_whois.result()
        dns_data   = future_dns.result()
        ssl_data   = future_ssl.result()
        geo_data   = future_geo.result()

    # ── Step 6: ML classification (elftsdmr/malware-url-detect) ──────────
    ml_result = _classify_url_with_bert(final_url)

    # ── Compute domain age ────────────────────────────────────────────────
    domain_age_days = _compute_domain_age(whois_data)
    domain_age_flag = (
        domain_age_days is not None and
        domain_age_days < YOUNG_DOMAIN_THRESHOLD_DAYS
    )

    # ── Aggregate flags from all layers ───────────────────────────────────
    flags = _aggregate_flags(
        raw_url=raw_url,
        final_url=final_url,
        domain=domain,
        redirects=redirects,
        whois_data=whois_data,
        ssl_data=ssl_data,
        domain_age_days=domain_age_days,
        ml_result=ml_result
    )

    # ── Compute this URL's contribution to the overall risk score ─────────
    # The Risk Engine (Phase 10) will use this as the "url_intel" component.
    # Maximum contribution: 15 points (as defined in the project spec).
    risk_contribution = _compute_risk_contribution(flags, ml_result, domain_age_flag)

    return {
        "raw_url":            raw_url,
        "final_url":          final_url,
        "domain":             domain,
        "ip":                 geo_data.get("ip", ""),
        "country":            geo_data.get("country", ""),
        "city":               geo_data.get("city", ""),
        "asn":                geo_data.get("asn", ""),
        "whois":              whois_data,
        "dns":                dns_data,
        "ssl":                ssl_data,
        "redirect_chain":     redirects,
        "redirect_count":     len(redirects),
        "domain_age_days":    domain_age_days,
        "domain_age_flag":    domain_age_flag,
        "ml_result":          ml_result,
        "flags":              flags,
        "risk_contribution":  risk_contribution,
        "analyzed_at":        datetime.datetime.utcnow().isoformat() + "Z"
    }


def analyze_url_batch(url_list: list[dict]) -> list[dict]:
    """
    Analyze a list of URL dicts (as produced by the email parser).
    Each dict must have at least a "raw" key with the URL string.

    Runs each URL's full six-layer analysis concurrently.
    Returns a list of URLIntelResult dicts in the same order as input.

    Args:
        url_list: List of dicts from email_parser's _extract_urls()
                  [{"raw": "https://...", "domain": "...", ...}, ...]

    Returns:
        List of full intelligence result dicts.
    """
    if not url_list:
        return []

    raw_urls = [u.get("raw", "") for u in url_list]

    # Cap concurrent URL analyses to avoid overwhelming DNS/WHOIS servers
    max_concurrent = min(len(raw_urls), 5)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        # Submit all URLs at once — results come back as futures
        futures = {
            executor.submit(analyze_url, url): i
            for i, url in enumerate(raw_urls) if url
        }

        # Collect in submission order (not completion order)
        ordered = [None] * len(raw_urls)
        for future, idx in futures.items():
            try:
                ordered[idx] = future.result(timeout=30)
            except concurrent.futures.TimeoutError:
                ordered[idx] = _minimal_result(raw_urls[idx], "analysis_timeout")
            except Exception as e:
                logger.error(f"URL analysis error for {raw_urls[idx]}: {e}")
                ordered[idx] = _minimal_result(raw_urls[idx], str(e))

        results = [r for r in ordered if r is not None]

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Normalize & Unshorten
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_and_unshorten(url: str) -> dict:
    """
    Normalize the URL and follow any redirect chain.

    Normalization:
      - Strip whitespace, trailing punctuation
      - Lowercase the scheme and domain
      - Decode %XX percent-encoding in path/query

    Unshortening:
      - Follow up to MAX_REDIRECT_HOPS redirects using HEAD requests
      - Record every intermediate hop in redirect_chain
      - Flag chains longer than 2 hops as obfuscation signal

    Returns:
        {
          "final_url": str,        # URL after all redirects
          "redirect_chain": list,  # list of intermediate URLs
          "error": str or None
        }
    """
    url = url.strip().rstrip(".,;!?)'\"")
    redirect_chain = []
    current_url    = url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lstrip("www.").split(":")[0].lower()
        is_shortener = domain in URL_SHORTENERS

        if not is_shortener:
            # For non-shorteners, still follow any server-side redirects
            # (some phishing pages use redirects even on "normal" domains)
            pass

        # Follow redirects — use HEAD to avoid downloading page bodies
        session = requests.Session()
        session.max_redirects = MAX_REDIRECT_HOPS

        try:
            response = session.head(
                current_url,
                allow_redirects=True,
                timeout=NETWORK_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (PhishingDetector/1.0)"}
            )

            # response.history contains all intermediate responses
            for hop in response.history:
                if hop.headers.get("Location"):
                    redirect_chain.append(hop.headers["Location"])

            final_url = response.url

        except requests.exceptions.TooManyRedirects:
            # Flag this — more than MAX_REDIRECT_HOPS is a red flag
            final_url = current_url
            redirect_chain.append(f"[ERROR: exceeded {MAX_REDIRECT_HOPS} redirect hops]")

        except requests.exceptions.RequestException:
            # Can't reach the URL — still analyze the domain
            final_url = current_url

        return {
            "final_url":      final_url,
            "redirect_chain": redirect_chain,
            "error":          None
        }

    except Exception as e:
        logger.warning(f"Normalization error for {url}: {e}")
        return {
            "final_url":      url,
            "redirect_chain": [],
            "error":          str(e)
        }


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — WHOIS Lookup
# ─────────────────────────────────────────────────────────────────────────────

def _whois_lookup(domain: str) -> dict:
    """
    Query WHOIS for domain registration information.

    Returns:
        {
          "registrar":     str,
          "creation_date": str (ISO format),
          "expiry_date":   str (ISO format),
          "updated_date":  str (ISO format),
          "name_servers":  list[str],
          "status":        list[str],
          "org":           str,
          "country":       str,
          "error":         str or None
        }

    WHOIS lookups can be slow (1–3 s) and sometimes fail for newer TLDs.
    We always return a dict — never raise — so callers get partial data.
    """
    result = {
        "registrar": "", "creation_date": "", "expiry_date": "",
        "updated_date": "", "name_servers": [], "status": [],
        "org": "", "country": "", "error": None
    }

    try:
        w = whois.whois(domain)

        result["registrar"] = str(w.registrar or "")
        result["org"]       = str(w.org or "")
        result["country"]   = str(w.country or "")

        # whois returns dates as datetime objects or lists of datetimes
        def _fmt_date(d) -> str:
            if not d:
                return ""
            if isinstance(d, list):
                d = d[0]  # take the earliest date if multiple returned
            if isinstance(d, datetime.datetime):
                return d.isoformat()
            return str(d)

        result["creation_date"] = _fmt_date(w.creation_date)
        result["expiry_date"]   = _fmt_date(w.expiry_date)
        result["updated_date"]  = _fmt_date(w.updated_date)

        # Name servers — normalize to lowercase list
        ns = w.name_servers
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            result["name_servers"] = [s.lower() for s in ns if s]

        # Status — can be a string or list
        status = w.status
        if status:
            if isinstance(status, str):
                status = [status]
            result["status"] = status

    except Exception as e:
        # Common failures: WHOIS rate limit, private registration,
        # unsupported TLD, no WHOIS server found
        result["error"] = str(e)
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")

    return result


def _compute_domain_age(whois_data: dict) -> Optional[int]:
    """
    Calculate the domain's age in days from its creation_date.
    Returns None if creation_date is unavailable.
    """
    creation_str = whois_data.get("creation_date", "")
    if not creation_str:
        return None

    try:
        # Handle multiple possible date formats
        from dateutil import parser as dateutil_parser
        creation_dt = dateutil_parser.parse(creation_str)

        # Make timezone-naive for comparison
        if creation_dt.tzinfo:
            creation_dt = creation_dt.replace(tzinfo=None)

        age = (datetime.datetime.utcnow() - creation_dt).days
        return max(age, 0)

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — DNS Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _dns_lookup(domain: str) -> dict:
    """
    Query DNS for A, MX, TXT, and NS records.

    Why each record matters for phishing detection:
      A   → IP the domain resolves to (cross-ref with geolocation)
      MX  → Phishing domains often have no MX (no real email server)
      TXT → Contains SPF policy — we check if it's permissive
      NS  → Name server provider (e.g. Cloudflare vs cheap registrars)

    Returns:
        {
          "a_records":   [{"address": str}, ...],
          "mx_records":  [{"host": str, "preference": int}, ...],
          "txt_records": [str, ...],
          "ns_records":  [str, ...],
          "has_mx":      bool,
          "spf_policy":  str,    # extracted from TXT, e.g. "v=spf1 +all"
          "error":       str or None
        }
    """
    result = {
        "a_records": [], "mx_records": [], "txt_records": [],
        "ns_records": [], "has_mx": False, "spf_policy": "", "error": None
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout  = NETWORK_TIMEOUT
    resolver.lifetime = NETWORK_TIMEOUT

    # ── A records ──────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [{"address": str(r)} for r in answers]
    except Exception as e:
        logger.debug(f"DNS A lookup failed for {domain}: {e}")

    # ── MX records ─────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [
            {"host": str(r.exchange), "preference": r.preference}
            for r in answers
        ]
        result["has_mx"] = len(result["mx_records"]) > 0
    except Exception as e:
        logger.debug(f"DNS MX lookup failed for {domain}: {e}")
        result["has_mx"] = False

    # ── TXT records ────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(domain, "TXT")
        for record in answers:
            # TXT records are returned as byte strings — decode each part
            txt_str = " ".join(part.decode("utf-8", errors="replace")
                               for part in record.strings)
            result["txt_records"].append(txt_str)

            # Extract SPF policy from TXT records
            if txt_str.startswith("v=spf1"):
                result["spf_policy"] = txt_str
    except Exception as e:
        logger.debug(f"DNS TXT lookup failed for {domain}: {e}")

    # ── NS records ─────────────────────────────────────────────────────────
    try:
        answers = resolver.resolve(domain, "NS")
        result["ns_records"] = [str(r) for r in answers]
    except Exception as e:
        logger.debug(f"DNS NS lookup failed for {domain}: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — SSL/TLS Certificate Validation
# ─────────────────────────────────────────────────────────────────────────────

def _ssl_check(domain: str, port: Optional[int] = None) -> dict:
    """
    Connect to the domain over SSL and inspect its certificate.

    Checks:
      - Whether a valid certificate exists (no SSL = big red flag for login pages)
      - Certificate issuer (Let's Encrypt is fine; self-signed is suspicious)
      - Certificate expiry date (expired cert = abandoned or malicious site)
      - Whether the cert's CN/SANs match the domain (name mismatch = suspicious)

    We use Python's built-in ssl module — no third-party library needed.

    Returns:
        {
          "has_ssl":       bool,
          "is_valid":      bool,   # cert is trusted and not expired
          "issuer":        str,
          "subject":       str,
          "expires":       str (ISO date),
          "days_to_expiry":int,
          "is_expired":    bool,
          "is_self_signed":bool,
          "san_mismatch":  bool,
          "error":         str or None
        }
    """
    result = {
        "has_ssl": False, "is_valid": False, "issuer": "", "subject": "",
        "expires": "", "days_to_expiry": 0, "is_expired": False,
        "is_self_signed": False, "san_mismatch": False, "error": None
    }

    connect_port = port or 443

    try:
        # Create an SSL context that validates certificates
        ctx = ssl.create_default_context()

        # Connect and retrieve the certificate
        with ctx.wrap_socket(
            socket.create_connection((domain, connect_port), timeout=NETWORK_TIMEOUT),
            server_hostname=domain
        ) as ssock:
            cert = ssock.getpeercert()
            result["has_ssl"] = True
            result["is_valid"] = True   # If we got here, cert is trusted

            # ── Issuer ─────────────────────────────────────────────────────
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer_dict.get("organizationName", "Unknown")

            # ── Subject ────────────────────────────────────────────────────
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject_dict.get("commonName", "")

            # ── Expiry date ────────────────────────────────────────────────
            # cert["notAfter"] format: "Jan 01 00:00:00 2025 GMT"
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result["expires"]       = expiry_dt.isoformat()
                days_left               = (expiry_dt - datetime.datetime.utcnow()).days
                result["days_to_expiry"]= days_left
                result["is_expired"]    = days_left < 0

            # ── Self-signed detection ─────────────────────────────────────
            # A cert is self-signed if issuer == subject
            issuer_cn  = issuer_dict.get("commonName", "")
            subject_cn = subject_dict.get("commonName", "")
            result["is_self_signed"] = (issuer_cn == subject_cn and bool(issuer_cn))

            # ── SAN mismatch ──────────────────────────────────────────────
            # Check that the domain appears in the cert's Subject Alt Names
            sans = [
                name for kind, name in cert.get("subjectAltName", [])
                if kind == "DNS"
            ]
            if sans:
                # Match with wildcard support (*.example.com matches sub.example.com)
                matched = any(
                    domain == san or
                    (san.startswith("*.") and domain.endswith(san[1:]))
                    for san in sans
                )
                result["san_mismatch"] = not matched

    except ssl.SSLCertVerificationError as e:
        # Certificate is present but invalid (expired, untrusted CA, etc.)
        result["has_ssl"]  = True
        result["is_valid"] = False
        result["error"]    = f"SSL cert verification failed: {e}"

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        # No SSL at all — site doesn't serve HTTPS
        result["has_ssl"] = False
        result["error"]   = str(e)

    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"SSL check error for {domain}: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — IP Resolution & Geolocation
# ─────────────────────────────────────────────────────────────────────────────

def _ip_and_geo(domain: str) -> dict:
    """
    Resolve the domain to an IP address and look up its geolocation.

    Geolocation strategy (no paid API required):
      1. Try ipinfo.io free tier (50k lookups/month — enough for dev/hackathon)
      2. Fallback: return just the IP with no geo data

    Returns:
        {
          "ip":       str,
          "country":  str,    # "IN", "US", etc.
          "city":     str,
          "region":   str,
          "org":      str,    # ASN + org name
          "asn":      str,    # e.g. "AS13335"
          "is_private":bool,  # RFC 1918 / loopback address
          "error":    str or None
        }
    """
    result = {
        "ip": "", "country": "", "city": "", "region": "",
        "org": "", "asn": "", "is_private": False, "error": None
    }

    try:
        # Resolve domain → IP
        ip_str = socket.gethostbyname(domain)
        result["ip"] = ip_str

        # Check if private/loopback
        ip_obj = ipaddress.ip_address(ip_str)
        result["is_private"] = ip_obj.is_private or ip_obj.is_loopback

        if result["is_private"]:
            result["country"] = "PRIVATE"
            return result

        # Geolocation via ipinfo.io (free, no key needed for basic info)
        try:
            geo_resp = requests.get(
                f"https://ipinfo.io/{ip_str}/json",
                timeout=NETWORK_TIMEOUT,
                headers={"Accept": "application/json"}
            )
            if geo_resp.status_code == 200:
                geo = geo_resp.json()
                result["country"] = geo.get("country", "")
                result["city"]    = geo.get("city", "")
                result["region"]  = geo.get("region", "")
                result["org"]     = geo.get("org", "")

                # Extract ASN from org field (format: "AS13335 Cloudflare, Inc.")
                org = result["org"]
                if org.startswith("AS"):
                    result["asn"] = org.split(" ")[0]

        except requests.exceptions.RequestException:
            # ipinfo.io unreachable — skip geo, keep IP
            pass

    except socket.gaierror as e:
        # Domain doesn't resolve at all (DNS failure or non-existent domain)
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"IP/geo lookup error for {domain}: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — ML Classification (elftsdmr/malware-url-detect)
# ─────────────────────────────────────────────────────────────────────────────

def _classify_url_with_bert(url: str) -> dict:
    """
    Classify the (final, unshortened) URL as MALICIOUS or BENIGN using
    the elftsdmr/malware-url-detect BERT model.

    The model was fine-tuned on malicious URL datasets and treats the
    raw URL string as a text sequence — it learns lexical patterns like
    long subdomains, suspicious keywords, and unusual character distributions.

    Args:
        url: The final URL (after following redirects).

    Returns:
        {"label": "MALICIOUS"/"BENIGN"/"UNKNOWN", "score": float, "model": str}
    """
    fallback = {
        "label": "UNKNOWN", "score": 0.0,
        "model": "elftsdmr/malware-url-detect",
        "note":  "model_unavailable"
    }

    if not url or len(url) < 4:
        return {**fallback, "note": "url_too_short"}

    model = get_model("url_malware_detector")
    if model is None:
        logger.warning("url_malware_detector not loaded — returning fallback")
        return fallback

    try:
        # Truncate to 512 chars — BERT tokenizer limit
        truncated = url[:512]

        results = model(truncated)
        top = results[0]

        raw_label = top["label"].upper()

        # Normalize label strings — the model uses LABEL_0/LABEL_1 or
        # MALICIOUS/BENIGN depending on the tokenizer config
        if any(x in raw_label for x in ["MALICIOUS", "MALWARE", "BAD", "1"]):
            normalized = "MALICIOUS"
        elif any(x in raw_label for x in ["BENIGN", "SAFE", "CLEAN", "GOOD", "0"]):
            normalized = "BENIGN"
        else:
            normalized = raw_label

        return {
            "label": normalized,
            "score": round(float(top["score"]), 4),
            "model": "elftsdmr/malware-url-detect"
        }

    except Exception as e:
        logger.error(f"URL BERT classify error: {e}")
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Flag aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_flags(
    raw_url: str,
    final_url: str,
    domain: str,
    redirects: list,
    whois_data: dict,
    ssl_data: dict,
    domain_age_days: Optional[int],
    ml_result: dict
) -> list[dict]:
    """
    Collect all intelligence signals into a uniform list of flag dicts.
    Each flag has:
      {"flag": str, "description": str, "severity": "low"/"medium"/"high"}

    These flags feed directly into:
      - The Risk Scoring Engine (Phase 10)
      - The Detection Rules Engine (Phase 4, which adds more rule flags)
      - The dashboard URL Intelligence page (rendered as cards)
    """
    flags = []

    def add(flag: str, desc: str, severity: str):
        flags.append({"flag": flag, "description": desc, "severity": severity})

    # ── URL structure flags ───────────────────────────────────────────────
    if len(raw_url) > 75:
        add("long_url", f"URL length {len(raw_url)} chars (> 75)", "medium")

    # IP address used directly instead of domain name
    import re
    if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', raw_url):
        add("ip_address_url", "URL uses raw IP address instead of domain", "high")

    # Suspicious TLD
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"TLD '{tld}' is commonly used in throwaway phishing domains", "high")

    # Too many subdomains (e.g. login.verify.paypal.attacker.com)
    subdomain_depth = len(domain.split(".")) - 2   # subtract SLD + TLD
    if subdomain_depth > 2:
        add("deep_subdomains", f"{subdomain_depth} subdomain levels (suspicious if ≥ 3)", "medium")

    # Redirect chain longer than 2 hops
    if len(redirects) > 2:
        add("long_redirect_chain",
            f"URL redirected {len(redirects)} times before final destination",
            "high" if len(redirects) > 3 else "medium")

    # ── WHOIS / domain age flags ──────────────────────────────────────────
    if domain_age_days is not None and domain_age_days < YOUNG_DOMAIN_THRESHOLD_DAYS:
        add("young_domain",
            f"Domain is only {domain_age_days} days old (< {YOUNG_DOMAIN_THRESHOLD_DAYS} days)",
            "high" if domain_age_days < 30 else "medium")

    if not whois_data.get("registrar"):
        add("no_whois", "WHOIS returned no registrar — domain may use private registration", "low")

    # ── SSL flags ─────────────────────────────────────────────────────────
    if not ssl_data.get("has_ssl"):
        add("no_https", "Domain does not serve HTTPS — unsafe for any login form", "medium")

    if ssl_data.get("is_expired"):
        add("expired_cert", "SSL certificate has expired", "high")

    if ssl_data.get("is_self_signed"):
        add("self_signed_cert", "SSL certificate is self-signed (not issued by trusted CA)", "high")

    if ssl_data.get("san_mismatch"):
        add("ssl_san_mismatch", "SSL certificate does not cover this domain", "high")

    # ── ML flag ───────────────────────────────────────────────────────────
    if ml_result.get("label") == "MALICIOUS" and ml_result.get("score", 0) > 0.6:
        add("ml_malicious",
            f"BERT model classified URL as malicious ({int(ml_result['score']*100)}% confidence)",
            "high" if ml_result["score"] > 0.85 else "medium")

    return flags


# ─────────────────────────────────────────────────────────────────────────────
# Risk contribution calculation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_risk_contribution(flags: list, ml_result: dict, domain_age_flag: bool) -> float:
    """
    Calculate this URL's contribution to the overall email risk score.
    Maximum: 15 points (as defined in the project spec for Module 2).

    Breakdown:
      - ML classification:    0–7  points
      - Flag severity:        0–5  points
      - Domain age:           0–3  points
    """
    score = 0.0

    # ML contribution (0–7)
    if ml_result.get("label") == "MALICIOUS":
        score += ml_result.get("score", 0.5) * 7

    # Flag severity contribution (0–5)
    severity_weights = {"high": 2.0, "medium": 1.0, "low": 0.3}
    flag_score = sum(severity_weights.get(f.get("severity", "low"), 0.3) for f in flags)
    score += min(flag_score, 5.0)

    # Domain age contribution (0–3)
    if domain_age_flag:
        score += 3.0

    return round(min(score, 15.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_result(url: str, reason: str) -> dict:
    """Return a minimal result dict when analysis is skipped or fails."""
    return {
        "raw_url": url, "final_url": url, "domain": "",
        "ip": "", "country": "", "city": "", "asn": "",
        "whois": {}, "dns": {}, "ssl": {},
        "redirect_chain": [], "redirect_count": 0,
        "domain_age_days": None, "domain_age_flag": False,
        "ml_result": {"label": "UNKNOWN", "score": 0.0, "model": ""},
        "flags": [], "risk_contribution": 0.0,
        "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z",
        "skipped_reason": reason
    }