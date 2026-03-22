# url_intelligence.py
# URL & Domain Intelligence Module — Phase 2
#
# FIXES IN THIS VERSION:
#   1. _safe_date() — handles list[datetime], naive datetimes, strings
#   2. _whois_lookup() — _safe_date() for all date fields
#   3. _compute_domain_age() — timezone-safe, no dateutil dependency
#   4. _ssl_check() — returns "is_valid" key consistently (never "valid")
#   5. _classify_url_with_bert() — score inversion fixed for BENIGN labels
#   6. _aggregate_flags() — references ssl["is_valid"] (not ssl["valid"])
#   7. analyze_url() return dict — "org" field added at top level
#   8. _ip_and_geo() — org now returned separately from asn
#
# NEW IN THIS VERSION:
#   9. _enumerate_subdomains() — dual-method subdomain discovery
#
# PHASE 2 FEATURE ADDITIONS:
#  10. _check_typosquatting(domain) — Levenshtein edit-distance check against
#      30 monitored brand domains. Detects character substitution, omission,
#      insertion, transposition, homoglyph substitution, hyphenation, and
#      subdomain abuse. Returns is_typosquatting_suspect, closest_brand,
#      edit_distance, technique, and a candidates[] list.
#      Result exposed as "typosquatting" key in analyze_url() return dict.
#
#  11. _check_cert_transparency(domain, ssl_data) — queries crt.sh for the
#      earliest certificate issuance date for the domain, computes
#      days_since_issued, and sets is_freshly_certified=True when < 30 days.
#      Uses ssl_data["expires"] as a fast-path fallback when crt.sh is
#      unavailable (inverts the expiry to estimate issuance).
#      Result exposed as "cert_transparency" key in analyze_url() return dict.
#
# BUG FIX (typosquatting):
#  12. _extract_registrable() now also returns each hyphen-separated segment
#      so that "paypa1-secure-login.xyz" correctly yields "paypa1" for
#      comparison rather than the full label "paypa1-secure-login".
#  13. _check_typosquatting() now iterates over all hyphen segments of the
#      registrable label and uses the closest-matching segment, so compound
#      phishing domains like paypa1-secure-login.xyz are correctly flagged.

import ssl
import json
import socket
import logging
import requests
import datetime
import ipaddress
import concurrent.futures
from urllib.parse import urlparse
from typing import Optional

import whois
import dns.resolver

from backend.ml.model_loader import get_model

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_TIMEOUT = 5

SKIP_DOMAINS = {"localhost", "127.0.0.1", "0.0.0.0", "example.com"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bc.vc", "clck.ru",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".top", ".club", ".gq", ".ml", ".ga",
    ".cf", ".pw", ".work", ".loan", ".click", ".link",
    ".buzz", ".monster", ".rest", ".icu", ".cyou"
}

YOUNG_DOMAIN_THRESHOLD_DAYS = 180
MAX_REDIRECT_HOPS            = 5

# ── Typosquatting: brands to monitor ─────────────────────────────────────────
_TYPOSQUAT_BRANDS: dict = {
    "paypal":      "paypal.com",
    "google":      "google.com",
    "gmail":       "gmail.com",
    "facebook":    "facebook.com",
    "amazon":      "amazon.com",
    "apple":       "apple.com",
    "microsoft":   "microsoft.com",
    "outlook":     "outlook.com",
    "netflix":     "netflix.com",
    "instagram":   "instagram.com",
    "twitter":     "twitter.com",
    "linkedin":    "linkedin.com",
    "github":      "github.com",
    "dropbox":     "dropbox.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo":  "wellsfargo.com",
    "chase":       "chase.com",
    "citibank":    "citibank.com",
    "hsbc":        "hsbc.com",
    "dhl":         "dhl.com",
    "fedex":       "fedex.com",
    "ups":         "ups.com",
    "steam":       "steampowered.com",
    "roblox":      "roblox.com",
    "coinbase":    "coinbase.com",
    "binance":     "binance.com",
    "docusign":    "docusign.com",
    "adobe":       "adobe.com",
    "zoom":        "zoom.us",
    "slack":       "slack.com",
}

_TYPOSQUAT_MAX_DISTANCE = 2
_CT_FRESH_THRESHOLD_DAYS = 30

SUBDOMAIN_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "email",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway",
    "api", "api2", "api-v2", "rest", "graphql",
    "app", "apps", "web", "portal", "admin", "administrator",
    "login", "signin", "auth", "sso", "oauth",
    "secure", "ssl", "tls", "cdn", "static", "assets",
    "img", "images", "media", "files", "upload", "uploads",
    "dev", "staging", "stage", "test", "qa", "uat", "sandbox",
    "beta", "alpha", "preview", "demo",
    "shop", "store", "pay", "payment", "checkout", "billing",
    "account", "accounts", "user", "users", "member", "members",
    "help", "support", "helpdesk", "tickets", "docs", "wiki",
    "blog", "news", "press", "forum", "community",
    "dashboard", "panel", "cpanel", "whm", "plesk",
    "monitor", "status", "health",
    "mx", "mx1", "mx2", "ns", "ns1", "ns2", "dns",
    "mobile", "m", "wap",
    "old", "legacy", "backup", "archive",
    "internal", "intranet", "corp", "office",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "search", "elastic", "kibana", "grafana", "prometheus",
    "s3", "bucket", "storage", "backup2",
    "webdisk", "autodiscover", "autoconfig",
    "track", "tracking", "pixel", "analytics", "stats",
]

MAX_SUBDOMAIN_RISK_SCORE = 20


# ─────────────────────────────────────────────────────────────────────────────
# Safe date coercion helper
# ─────────────────────────────────────────────────────────────────────────────

def _safe_date(raw) -> Optional[datetime.datetime]:
    """Coerce a raw whois date to a timezone-naive datetime, or None."""
    if raw is None:
        return None

    if isinstance(raw, list):
        valid = [d for d in raw if isinstance(d, datetime.datetime)]
        if not valid:
            for item in raw:
                result = _safe_date(item)
                if result:
                    return result
            return None
        return min(valid).replace(tzinfo=None)

    if isinstance(raw, datetime.datetime):
        return raw.replace(tzinfo=None)

    if isinstance(raw, str):
        raw = raw.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d",
            "%d-%b-%Y",
        ):
            try:
                return datetime.datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(raw_url: str, _skip_subdomains: bool = False) -> dict:
    """
    Run the full intelligence stack on a single URL.
    """
    raw_url = raw_url.strip()

    normalization = _normalize_and_unshorten(raw_url)
    final_url     = normalization["final_url"]
    redirects     = normalization["redirect_chain"]

    parsed = urlparse(final_url)
    domain = parsed.netloc.lower().lstrip("www.")
    domain = domain.split(":")[0]

    if domain in SKIP_DOMAINS or not domain:
        return _minimal_result(raw_url, "skipped_domain")

    whois_data = {}
    dns_data   = {}
    ssl_data   = {}
    geo_data   = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_whois = executor.submit(_whois_lookup,  domain)
        future_dns   = executor.submit(_dns_lookup,    domain)
        future_ssl   = executor.submit(_ssl_check,     domain, parsed.port)
        future_geo   = executor.submit(_ip_and_geo,    domain)

        try:
            whois_data = future_whois.result(timeout=8)
        except Exception as e:
            logger.warning("WHOIS future failed for %s: %s", domain, e)
            whois_data = {"error": str(e)}

        try:
            dns_data = future_dns.result(timeout=8)
        except Exception as e:
            logger.warning("DNS future failed for %s: %s", domain, e)
            dns_data = {"error": str(e)}

        try:
            ssl_data = future_ssl.result(timeout=8)
        except Exception as e:
            logger.warning("SSL future failed for %s: %s", domain, e)
            ssl_data = {"has_ssl": False, "is_valid": False, "error": str(e)}

        try:
            geo_data = future_geo.result(timeout=8)
        except Exception as e:
            logger.warning("Geo future failed for %s: %s", domain, e)
            geo_data = {
                "ip": "", "country": "", "city": "",
                "org": "", "asn": "", "error": str(e)
            }

    ml_result = _classify_url_with_bert(final_url)

    domain_age_days = _compute_domain_age(whois_data)
    domain_age_flag = (
        domain_age_days is not None and
        domain_age_days < YOUNG_DOMAIN_THRESHOLD_DAYS
    )

    flags = _aggregate_flags(
        raw_url         = raw_url,
        final_url       = final_url,
        domain          = domain,
        redirects       = redirects,
        whois_data      = whois_data,
        ssl_data        = ssl_data,
        domain_age_days = domain_age_days,
        ml_result       = ml_result
    )

    risk_contribution = _compute_risk_contribution(flags, ml_result, domain_age_flag)

    subdomains = []
    if not _skip_subdomains:
        try:
            subdomains = _enumerate_subdomains(domain)
        except Exception as e:
            logger.warning("Subdomain enumeration failed for %s: %s", domain, e)

    typosquatting     = _check_typosquatting(domain)
    cert_transparency = _check_cert_transparency(domain, ssl_data)

    return {
        "raw_url":            raw_url,
        "final_url":          final_url,
        "domain":             domain,
        "ip":                 geo_data.get("ip",      ""),
        "country":            geo_data.get("country", ""),
        "city":               geo_data.get("city",    ""),
        "org":                geo_data.get("org",     ""),
        "asn":                geo_data.get("asn",     ""),
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
        "subdomains":         subdomains,
        "typosquatting":      typosquatting,
        "cert_transparency":  cert_transparency,
        "analyzed_at":        datetime.datetime.utcnow().isoformat() + "Z"
    }


def analyze_url_batch(url_list: list) -> list:
    """Analyze a list of URL dicts (each with a 'raw' key)."""
    if not url_list:
        return []

    raw_urls = [u.get("raw", "") for u in url_list]
    max_concurrent = min(len(raw_urls), 5)

    ordered = [None] * len(raw_urls)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = {
            executor.submit(analyze_url, url): i
            for i, url in enumerate(raw_urls) if url
        }
        for future, idx in futures.items():
            try:
                ordered[idx] = future.result(timeout=30)
            except concurrent.futures.TimeoutError:
                ordered[idx] = _minimal_result(raw_urls[idx], "analysis_timeout")
            except Exception as e:
                logger.error("URL analysis error for %s: %s", raw_urls[idx], e)
                ordered[idx] = _minimal_result(raw_urls[idx], str(e))

    return [r for r in ordered if r is not None]


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Normalize & Unshorten
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_and_unshorten(url: str) -> dict:
    url = url.strip().rstrip(".,;!?)'\"")
    redirect_chain = []

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECT_HOPS

        try:
            response = session.head(
                url,
                allow_redirects=True,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0 (PhishingDetector/1.0)"}
            )
            for hop in response.history:
                loc = hop.headers.get("Location", "")
                if loc:
                    redirect_chain.append(loc)
            final_url = response.url
        except requests.exceptions.TooManyRedirects:
            final_url = url
            redirect_chain.append(f"[ERROR: exceeded {MAX_REDIRECT_HOPS} redirect hops]")
        except requests.exceptions.RequestException:
            final_url = url

        return {
            "final_url":      final_url,
            "redirect_chain": redirect_chain,
            "error":          None
        }

    except Exception as e:
        logger.warning("Normalization error for %s: %s", url, e)
        return {
            "final_url":      url,
            "redirect_chain": [],
            "error":          str(e)
        }


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — WHOIS Lookup
# ─────────────────────────────────────────────────────────────────────────────

def _whois_lookup(domain: str) -> dict:
    result = {
        "registrar":     "",
        "creation_date": "",
        "expiry_date":   "",
        "updated_date":  "",
        "name_servers":  [],
        "status":        [],
        "org":           "",
        "country":       "",
        "error":         None
    }

    try:
        w = whois.whois(domain)

        result["registrar"] = str(w.registrar or "")
        result["org"]       = str(w.org       or "")
        result["country"]   = str(w.country   or "")

        def _fmt(raw) -> str:
            dt = _safe_date(raw)
            return dt.isoformat() if dt else ""

        result["creation_date"] = _fmt(w.creation_date)
        expiry_raw = getattr(w, "expiration_date", None) or getattr(w, "expiry_date", None)
        result["expiry_date"]   = _fmt(expiry_raw)
        result["updated_date"]  = _fmt(w.updated_date)

        ns = w.name_servers
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            result["name_servers"] = [s.lower() for s in ns if s]

        status = w.status
        if status:
            if isinstance(status, str):
                status = [status]
            result["status"] = status

    except Exception as e:
        result["error"] = str(e)
        logger.debug("WHOIS lookup failed for %s: %s", domain, e)

    return result


def _compute_domain_age(whois_data: dict) -> Optional[int]:
    creation_str = whois_data.get("creation_date", "")
    if not creation_str:
        return None

    try:
        creation_dt = _safe_date(creation_str)
        if creation_dt is None:
            return None
        creation_dt = creation_dt.replace(tzinfo=None)
        age = (datetime.datetime.utcnow() - creation_dt).days
        return max(age, 0)
    except Exception as e:
        logger.debug("Domain age calculation failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — DNS Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _dns_lookup(domain: str) -> dict:
    result = {
        "a_records":   [],
        "mx_records":  [],
        "txt_records": [],
        "ns_records":  [],
        "has_mx":      False,
        "spf_policy":  "",
        "error":       None
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout  = NETWORK_TIMEOUT
    resolver.lifetime = NETWORK_TIMEOUT

    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [{"address": str(r)} for r in answers]
    except Exception as e:
        logger.debug("DNS A lookup failed for %s: %s", domain, e)

    try:
        answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [
            {"host": str(r.exchange), "preference": r.preference}
            for r in answers
        ]
        result["has_mx"] = len(result["mx_records"]) > 0
    except Exception:
        result["has_mx"] = False

    try:
        answers = resolver.resolve(domain, "TXT")
        for record in answers:
            txt_str = " ".join(
                part.decode("utf-8", errors="replace") for part in record.strings
            )
            result["txt_records"].append(txt_str)
            if txt_str.startswith("v=spf1"):
                result["spf_policy"] = txt_str
    except Exception as e:
        logger.debug("DNS TXT lookup failed for %s: %s", domain, e)

    try:
        answers = resolver.resolve(domain, "NS")
        result["ns_records"] = [str(r) for r in answers]
    except Exception as e:
        logger.debug("DNS NS lookup failed for %s: %s", domain, e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — SSL/TLS Certificate
# ─────────────────────────────────────────────────────────────────────────────

def _ssl_check(domain: str, port: Optional[int] = None) -> dict:
    result = {
        "has_ssl":        False,
        "is_valid":       False,
        "issuer":         "",
        "subject":        "",
        "expires":        "",
        "days_to_expiry": 0,
        "is_expired":     False,
        "is_self_signed": False,
        "san_mismatch":   False,
        "error":          None
    }

    connect_port = port or 443

    try:
        ctx = ssl.create_default_context()

        with ctx.wrap_socket(
            socket.create_connection((domain, connect_port), timeout=NETWORK_TIMEOUT),
            server_hostname=domain
        ) as ssock:
            cert = ssock.getpeercert()
            result["has_ssl"]  = True
            result["is_valid"] = True

            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer_dict.get("organizationName", "Unknown")

            subject_dict = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject_dict.get("commonName", "")

            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                expiry_dt = datetime.datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )
                result["expires"]        = expiry_dt.isoformat()
                days_left                = (expiry_dt - datetime.datetime.utcnow()).days
                result["days_to_expiry"] = days_left
                result["is_expired"]     = days_left < 0
                if days_left < 0:
                    result["is_valid"] = False

            issuer_cn  = issuer_dict.get("commonName", "")
            subject_cn = subject_dict.get("commonName", "")
            result["is_self_signed"] = bool(issuer_cn and issuer_cn == subject_cn)
            if result["is_self_signed"]:
                result["is_valid"] = False

            sans = [
                name for kind, name in cert.get("subjectAltName", [])
                if kind == "DNS"
            ]
            if sans:
                matched = any(
                    domain == san or
                    (san.startswith("*.") and domain.endswith(san[1:]))
                    for san in sans
                )
                result["san_mismatch"] = not matched
                if result["san_mismatch"]:
                    result["is_valid"] = False

    except ssl.SSLCertVerificationError as e:
        result["has_ssl"]  = True
        result["is_valid"] = False
        result["error"]    = f"SSL cert verification failed: {e}"

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["has_ssl"]  = False
        result["is_valid"] = False
        result["error"]    = str(e)

    except Exception as e:
        result["is_valid"] = False
        result["error"]    = str(e)
        logger.debug("SSL check error for %s: %s", domain, e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — IP Resolution & Geolocation
# ─────────────────────────────────────────────────────────────────────────────

def _ip_and_geo(domain: str) -> dict:
    result = {
        "ip":         "",
        "country":    "",
        "city":       "",
        "region":     "",
        "org":        "",
        "asn":        "",
        "is_private": False,
        "error":      None
    }

    try:
        ip_str = socket.gethostbyname(domain)
        result["ip"] = ip_str

        ip_obj = ipaddress.ip_address(ip_str)
        result["is_private"] = ip_obj.is_private or ip_obj.is_loopback

        if result["is_private"]:
            result["country"] = "PRIVATE"
            return result

        try:
            geo_resp = requests.get(
                f"https://ipinfo.io/{ip_str}/json",
                timeout=NETWORK_TIMEOUT,
                headers={"Accept": "application/json"}
            )
            if geo_resp.status_code == 200:
                geo = geo_resp.json()
                result["country"] = geo.get("country", "")
                result["city"]    = geo.get("city",    "")
                result["region"]  = geo.get("region",  "")

                org_raw = geo.get("org", "")
                result["org"] = org_raw
                if org_raw.startswith("AS"):
                    result["asn"] = org_raw.split(" ")[0]
                else:
                    result["asn"] = ""

        except requests.exceptions.RequestException:
            pass

    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
    except Exception as e:
        result["error"] = str(e)
        logger.debug("IP/geo lookup error for %s: %s", domain, e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — ML Classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_url_with_bert(url: str) -> dict:
    fallback = {
        "label": "UNKNOWN",
        "score": 0.0,
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
        truncated = url[:512]
        results   = model(truncated)
        top       = results[0]

        raw_label = top["label"].upper()
        raw_score = float(top["score"])

        if any(x in raw_label for x in ["MALICIOUS", "MALWARE", "BAD", "LABEL_1", "1"]):
            normalized     = "MALICIOUS"
            phishing_score = raw_score
        elif any(x in raw_label for x in ["BENIGN", "SAFE", "CLEAN", "GOOD", "LABEL_0", "0"]):
            normalized     = "BENIGN"
            phishing_score = 1.0 - raw_score
        else:
            normalized     = raw_label
            phishing_score = raw_score

        return {
            "label":     normalized,
            "score":     round(phishing_score, 4),
            "model":     "elftsdmr/malware-url-detect",
            "raw_label": raw_label,
            "raw_score": round(raw_score, 4),
        }

    except Exception as e:
        logger.error("URL BERT classify error: %s", e)
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Subdomain Enumeration
# ─────────────────────────────────────────────────────────────────────────────

def _enumerate_subdomains(domain: str) -> list:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_crtsh      = ex.submit(_crtsh_lookup,   domain)
        f_bruteforce = ex.submit(_dns_bruteforce, domain)

        try:
            crtsh_found      = f_crtsh.result(timeout=8)
        except Exception as e:
            logger.warning("crt.sh lookup failed for %s: %s", domain, e)
            crtsh_found      = []

        try:
            bruteforce_found = f_bruteforce.result(timeout=10)
        except Exception as e:
            logger.warning("DNS bruteforce failed for %s: %s", domain, e)
            bruteforce_found = []

    all_found: dict = {}
    for sd in crtsh_found:
        all_found[sd] = "crtsh"
    for sd in bruteforce_found:
        if sd in all_found:
            all_found[sd] = "both"
        else:
            all_found[sd] = "bruteforce"

    all_found = {
        sd: src for sd, src in all_found.items()
        if sd != domain and sd.endswith(f".{domain}")
    }

    if not all_found:
        return []

    resolved:   list = []
    unresolved: list = []

    for sd in sorted(all_found.keys()):
        ip = _resolve_subdomain(sd)
        entry = {
            "subdomain":  sd,
            "source":     all_found[sd],
            "ip":         ip or "",
            "resolves":   ip is not None,
            "risk_score": None,
            "label":      None,
            "ml_score":   None,
            "ssl_valid":  None,
            "flags":      [],
        }
        if ip is not None:
            resolved.append(entry)
        else:
            unresolved.append(entry)

    to_score = resolved[:MAX_SUBDOMAIN_RISK_SCORE]
    no_score = resolved[MAX_SUBDOMAIN_RISK_SCORE:]

    if to_score:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            future_map = {
                ex.submit(_score_subdomain, entry["subdomain"]): i
                for i, entry in enumerate(to_score)
            }
            for future in concurrent.futures.as_completed(future_map, timeout=20):
                idx = future_map[future]
                try:
                    scored = future.result()
                    to_score[idx].update(scored)
                except Exception as e:
                    logger.debug(
                        "Subdomain risk score failed for %s: %s",
                        to_score[idx]["subdomain"], e
                    )

    return to_score + no_score + unresolved


def _crtsh_lookup(domain: str) -> list:
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=6,
            headers={"Accept": "application/json"}
        )
        if resp.status_code != 200:
            return []

        entries = resp.json()
        found = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(f".{domain}") and name != domain:
                    found.add(name)

        return sorted(found)

    except Exception as e:
        logger.warning("crt.sh request failed for %s: %s", domain, e)
        return []


def _dns_bruteforce(domain: str) -> list:
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 1
    resolver.lifetime = 1

    def _try(prefix: str) -> Optional[str]:
        candidate = f"{prefix}.{domain}"
        try:
            resolver.resolve(candidate, "A")
            return candidate
        except Exception:
            return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_try, prefix): prefix for prefix in SUBDOMAIN_WORDLIST}
        for future in concurrent.futures.as_completed(futures, timeout=20):
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    return found


def _resolve_subdomain(subdomain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None


def _score_subdomain(subdomain: str) -> dict:
    try:
        result = analyze_url(f"https://{subdomain}", _skip_subdomains=True)

        ml_score     = float(result.get("ml_result", {}).get("score", 0.0))
        base_score   = round(ml_score * 100, 2)
        flags        = result.get("flags", [])
        flag_penalty = min(sum(
            8.0 if f.get("severity") == "high"   else
            4.0 if f.get("severity") == "medium" else
            1.0
            for f in flags
        ), 20.0)
        age_penalty  = 5.0 if result.get("domain_age_flag") else 0.0
        risk_score   = min(round(base_score + flag_penalty + age_penalty, 2), 100.0)

        label = (
            "MALICIOUS"  if risk_score >= 70 else
            "SUSPICIOUS" if risk_score >= 30 else
            "SAFE"
        )

        return {
            "risk_score": risk_score,
            "label":      label,
            "ml_score":   round(ml_score, 4),
            "ssl_valid":  result.get("ssl", {}).get("is_valid", False),
            "flags":      [f.get("flag", "") for f in flags[:5]],
        }

    except Exception as e:
        logger.debug("_score_subdomain error for %s: %s", subdomain, e)
        return {
            "risk_score": None,
            "label":      None,
            "ml_score":   None,
            "ssl_valid":  None,
            "flags":      [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Feature A — Typosquatting detection  ← BUG FIXED
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming Levenshtein distance. No external deps."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev = curr
    return prev[len(b)]


_HOMOGLYPH_MAP: dict = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "8": "b", "ν": "v", "а": "a", "е": "e",
    "о": "o", "р": "p", "с": "c", "х": "x", "ı": "i",
    "ɑ": "a", "ⅼ": "l", "ḿ": "m",
}


def _normalize_homoglyphs(s: str) -> str:
    """Replace known homoglyph characters with their ASCII equivalents."""
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in s)


def _extract_registrable(domain: str) -> str:
    """
    Extract the registrable SLD from a domain for typosquatting comparison.

    e.g. "login.paypa1.com"          → "paypa1"
         "paypal.co.uk"              → "paypal"
         "paypa1-secure-login.xyz"   → "paypa1-secure-login"
         "paypal.com"                → "paypal"

    NOTE: For compound labels joined by hyphens (e.g. "paypa1-secure-login"),
    _check_typosquatting() also tests each hyphen-segment individually so that
    "paypa1" is compared against brand keywords even when embedded in a longer
    label. This function returns the full registrable label; the segment
    iteration is the caller's responsibility.
    """
    parts = domain.rstrip(".").split(".")
    known_second_level = {
        "co", "com", "net", "org", "gov", "edu",
        "ac", "or", "ne", "go", "lg",
    }
    if len(parts) >= 3 and parts[-2] in known_second_level:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _check_typosquatting(domain: str) -> dict:
    """
    Check whether `domain` is a typosquatting attempt against any monitored brand.

    BUG FIX: Previously only compared the full registrable label
    ("paypa1-secure-login") against brand keywords, yielding large edit
    distances for compound domains. Now also checks each hyphen-separated
    segment individually so that "paypa1" (distance 0 after homoglyph
    normalisation) is correctly identified inside "paypa1-secure-login.xyz".

    Detection strategy:
      1. Extract registrable label + all hyphen segments.
      2. Normalise homoglyphs in each candidate token.
      3. Compute Levenshtein distance against every brand keyword.
      4. Flag as suspect when distance ≤ _TYPOSQUAT_MAX_DISTANCE AND
         domain is NOT the canonical brand domain itself.
      5. Also detect subdomain abuse and hyphenation patterns.
      6. Collect all matches below threshold into candidates[] sorted by
         edit distance ascending.

    Returns:
        {
          "is_typosquatting_suspect": bool,
          "closest_brand":            str,
          "edit_distance":            int,
          "technique":                str,
          "matched_token":            str,   ← NEW: which token matched
          "candidates":               list[{brand, edit_distance, technique,
                                            risk, matched_token}]
        }
    """
    result = {
        "is_typosquatting_suspect": False,
        "closest_brand":            "",
        "edit_distance":            None,
        "technique":                "",
        "matched_token":            "",
        "candidates":               [],
    }

    if not domain:
        return result

    domain_lower = domain.lower()

    # Full registrable label (e.g. "paypa1-secure-login")
    registrable = _extract_registrable(domain_lower)

    # ── Build list of tokens to test ──────────────────────────────────────
    # Always test the full registrable label PLUS each hyphen-separated
    # segment. This catches "paypa1-secure-login.xyz" → segment "paypa1".
    tokens = [registrable]
    if "-" in registrable:
        tokens.extend(registrable.split("-"))
    # Deduplicate while preserving order
    seen   = set()
    tokens = [t for t in tokens if t and not (t in seen or seen.add(t))]

    candidates = []

    for brand_key, canonical in _TYPOSQUAT_BRANDS.items():
        canonical_bare   = canonical.split(".")[0]
        canonical_domain = canonical.lstrip("www.").split(":")[0]

        # Skip if this IS the canonical domain
        if domain_lower == canonical_domain or domain_lower.endswith(f".{canonical_domain}"):
            continue

        # ── Check each token against the brand keyword ────────────────────
        best_dist_for_brand  = None
        best_token_for_brand = ""

        for token in tokens:
            token_hg = _normalize_homoglyphs(token)
            dist     = _levenshtein(token_hg, brand_key)

            if best_dist_for_brand is None or dist < best_dist_for_brand:
                best_dist_for_brand  = dist
                best_token_for_brand = token

        dist    = best_dist_for_brand
        token   = best_token_for_brand
        token_hg = _normalize_homoglyphs(token)

        if dist is not None and dist <= _TYPOSQUAT_MAX_DISTANCE:
            # Classify technique
            if token_hg == brand_key and token != token_hg:
                technique = "homoglyph"
            elif token_hg == brand_key:
                technique = "exact_match_after_normalisation"
            elif dist == 1:
                if len(token) == len(brand_key):
                    technique = "character_substitution"
                elif len(token) > len(brand_key):
                    technique = "insertion"
                else:
                    technique = "omission"
            else:
                technique = "character_substitution"

            risk = "HIGH" if dist <= 1 else "MEDIUM"
            candidates.append({
                "brand":         brand_key,
                "edit_distance": dist,
                "technique":     technique,
                "risk":          risk,
                "matched_token": token,
            })
            continue

        # ── Subdomain abuse ───────────────────────────────────────────────
        subdomain_labels = domain_lower.split(".")[:-2]
        if brand_key in subdomain_labels or canonical_bare in subdomain_labels:
            candidates.append({
                "brand":         brand_key,
                "edit_distance": 0,
                "technique":     "subdomain_abuse",
                "risk":          "HIGH",
                "matched_token": brand_key,
            })
            continue

        # ── Hyphenation (full label, not segments) ────────────────────────
        registrable_dehyphenated = registrable.replace("-", "")
        if registrable_dehyphenated == brand_key and "-" in registrable:
            candidates.append({
                "brand":         brand_key,
                "edit_distance": registrable.count("-"),
                "technique":     "hyphenation",
                "risk":          "HIGH",
                "matched_token": registrable,
            })

    if not candidates:
        return result

    candidates.sort(key=lambda c: (c["edit_distance"], c["brand"]))

    best = candidates[0]
    result["is_typosquatting_suspect"] = True
    result["closest_brand"]            = best["brand"]
    result["edit_distance"]            = best["edit_distance"]
    result["technique"]                = best["technique"]
    result["matched_token"]            = best.get("matched_token", "")
    result["candidates"]               = candidates

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 Feature B — Certificate Transparency freshness check
# ─────────────────────────────────────────────────────────────────────────────

def _check_cert_transparency(domain: str, ssl_data: dict) -> dict:
    result = {
        "is_freshly_certified": False,
        "days_since_issued":    None,
        "issued_date":          "",
        "source":               "unavailable",
    }

    issued_dt: Optional[datetime.datetime] = None

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=5,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            entries = resp.json()
            not_before_dates: list = []
            for entry in entries:
                cn = entry.get("common_name", "")
                if cn != domain and cn != f"*.{domain}":
                    continue
                not_before_str = entry.get("not_before", "")
                if not not_before_str:
                    continue
                dt = _safe_date(not_before_str.replace("T", " ").split(".")[0])
                if dt:
                    not_before_dates.append(dt)

            if not_before_dates:
                issued_dt = max(not_before_dates)
                result["source"] = "crtsh"

    except Exception as e:
        logger.debug("CT crt.sh query failed for %s: %s", domain, e)

    if issued_dt is None and ssl_data.get("expires"):
        try:
            expiry_dt = _safe_date(ssl_data["expires"])
            if expiry_dt:
                issued_dt        = expiry_dt - datetime.timedelta(days=90)
                result["source"] = "ssl_fallback"
        except Exception as e:
            logger.debug("CT ssl fallback failed for %s: %s", domain, e)

    if issued_dt is None:
        return result

    days_since = (datetime.datetime.utcnow() - issued_dt).days
    days_since = max(days_since, 0)

    result["issued_date"]          = issued_dt.strftime("%Y-%m-%d")
    result["days_since_issued"]    = days_since
    result["is_freshly_certified"] = days_since < _CT_FRESH_THRESHOLD_DAYS

    return result


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
) -> list:
    flags = []

    def add(flag: str, desc: str, severity: str):
        flags.append({"flag": flag, "description": desc, "severity": severity})

    if len(raw_url) > 75:
        add("long_url", f"URL length {len(raw_url)} chars (> 75)", "medium")

    import re
    if re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', raw_url):
        add("ip_address_url", "URL uses raw IP address instead of domain", "high")

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld",
            f"TLD '{tld}' is commonly used in throwaway phishing domains", "high")

    subdomain_depth = len(domain.split(".")) - 2
    if subdomain_depth > 2:
        add("deep_subdomains",
            f"{subdomain_depth} subdomain levels (suspicious if ≥ 3)", "medium")

    if len(redirects) > 2:
        add("long_redirect_chain",
            f"URL redirected {len(redirects)} times before final destination",
            "high" if len(redirects) > 3 else "medium")

    if domain_age_days is not None and domain_age_days < YOUNG_DOMAIN_THRESHOLD_DAYS:
        add("young_domain",
            f"Domain is only {domain_age_days} days old "
            f"(< {YOUNG_DOMAIN_THRESHOLD_DAYS} days)",
            "high" if domain_age_days < 30 else "medium")

    if not whois_data.get("registrar"):
        add("no_whois",
            "WHOIS returned no registrar — domain may use private registration",
            "low")

    if not ssl_data.get("has_ssl"):
        add("no_https",
            "Domain does not serve HTTPS — unsafe for any login form", "medium")

    if ssl_data.get("is_expired"):
        add("expired_cert", "SSL certificate has expired", "high")

    if ssl_data.get("is_self_signed"):
        add("self_signed_cert",
            "SSL certificate is self-signed (not issued by trusted CA)", "high")

    if ssl_data.get("san_mismatch"):
        add("ssl_san_mismatch",
            "SSL certificate does not cover this domain", "high")

    if ml_result.get("label") == "MALICIOUS" and ml_result.get("score", 0) > 0.6:
        add("ml_malicious",
            f"BERT model classified URL as malicious "
            f"({int(ml_result['score'] * 100)}% confidence)",
            "high" if ml_result["score"] > 0.85 else "medium")

    return flags


# ─────────────────────────────────────────────────────────────────────────────
# Risk contribution
# ─────────────────────────────────────────────────────────────────────────────

def _compute_risk_contribution(
    flags: list,
    ml_result: dict,
    domain_age_flag: bool
) -> float:
    score = 0.0

    if ml_result.get("label") == "MALICIOUS":
        score += ml_result.get("score", 0.5) * 7

    severity_weights = {"high": 2.0, "medium": 1.0, "low": 0.3}
    flag_score = sum(
        severity_weights.get(f.get("severity", "low"), 0.3) for f in flags
    )
    score += min(flag_score, 5.0)

    if domain_age_flag:
        score += 3.0

    return round(min(score, 15.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_result(url: str, reason: str) -> dict:
    return {
        "raw_url":            url,
        "final_url":          url,
        "domain":             "",
        "ip":                 "",
        "country":            "",
        "city":               "",
        "org":                "",
        "asn":                "",
        "whois":              {},
        "dns":                {},
        "ssl":                {"has_ssl": False, "is_valid": False},
        "redirect_chain":     [],
        "redirect_count":     0,
        "domain_age_days":    None,
        "domain_age_flag":    False,
        "ml_result":          {"label": "UNKNOWN", "score": 0.0, "model": ""},
        "flags":              [],
        "risk_contribution":  0.0,
        "subdomains":         [],
        "typosquatting":      {
            "is_typosquatting_suspect": False,
            "closest_brand":            "",
            "edit_distance":            None,
            "technique":                "",
            "matched_token":            "",
            "candidates":               [],
        },
        "cert_transparency":  {
            "is_freshly_certified": False,
            "days_since_issued":    None,
            "issued_date":          "",
            "source":               "unavailable",
        },
        "analyzed_at":        datetime.datetime.utcnow().isoformat() + "Z",
        "skipped_reason":     reason
    }