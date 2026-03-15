"""
backend/modules/file_analyzer.py
Phase 6 — File & Attachment Analysis Engine
"""

import os
import re
import math
import hashlib
import zipfile
from collections import Counter
from typing import Optional

# ── Optional dependencies (graceful fallback if not installed) ─────────────────
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import io as _io
    from pdfminer.high_level import extract_text as pdf_extract_text
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfparser import PDFParser
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

# ── Paths ──────────────────────────────────────────────────────────────────────
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_MODULE_DIR)

YARA_RULES_DIR = os.path.join(_BACKEND_DIR, "yara_rules")
KNOWN_BAD_HASHES_FILE = os.path.join(
    _BACKEND_DIR, "ml", "datasets", "known_bad_hashes.txt"
)

# ── Constants ──────────────────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 7.2
MIN_STRING_LEN = 6
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

SUSPICIOUS_PATTERNS = [
    "cmd.exe", "powershell", "wget", "curl", "eval(",
    "exec(", "document.write(", "createobject", "wscript.shell",
    "shell.application", "unescape(", "fromcharcode", "activexobject",
    "base64_decode", "system.reflection", "invoke-expression",
    "iex(", "-encodedcommand", "-enc ", "downloadstring",
    "net user", "net localgroup", "reg add", "schtasks",
    "/bin/bash", "/bin/sh", "chmod +x", "nc -e", "meterpreter",
    "mimikatz", "cobalt strike", "shellcode", "mshta",
]

EXTENSION_MIME_MAP = {
    ".pdf":  "application/pdf",
    ".doc":  "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls":  "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt":  "application/vnd.ms-powerpoint",
    ".zip":  "application/zip",
    ".exe":  "application/x-dosexec",
    ".dll":  "application/x-dosexec",
    ".html": "text/html",
    ".htm":  "text/html",
    ".js":   "application/javascript",
    ".vbs":  "text/vbscript",
    ".ps1":  "text/x-powershell",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
}


# ══════════════════════════════════════════════════════════════════════════════
# HASH UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def check_known_bad(sha256: str) -> bool:
    if not os.path.exists(KNOWN_BAD_HASHES_FILE):
        return False
    try:
        with open(KNOWN_BAD_HASHES_FILE, "r") as fh:
            for line in fh:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    if line == sha256.lower():
                        return True
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY
# ══════════════════════════════════════════════════════════════════════════════

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (c / length) * math.log2(c / length) for c in counter.values()
    )
    return round(entropy, 4)


# ══════════════════════════════════════════════════════════════════════════════
# FILE TYPE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_file_type(data: bytes, filename: str) -> str:
    if MAGIC_AVAILABLE:
        try:
            return magic.from_buffer(data, mime=True)
        except Exception:
            pass
    ext = os.path.splitext(filename)[1].lower()
    return EXTENSION_MIME_MAP.get(ext, "application/octet-stream")


# ══════════════════════════════════════════════════════════════════════════════
# STRING EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_printable_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list:
    pattern = re.compile(
        rb"(?:[\x20-\x7e]{" + str(min_len).encode() + rb",})"
    )
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def detect_suspicious_strings(strings: list) -> list:
    found = set()
    combined = " ".join(strings).lower()
    for pat in SUSPICIOUS_PATTERNS:
        if pat.lower() in combined:
            found.add(pat)
    # Base64 blob detection (40+ char blobs)
    b64_re = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for s in strings:
        if b64_re.search(s):
            found.add("base64_blob_detected")
            break
    return sorted(found)


# ══════════════════════════════════════════════════════════════════════════════
# YARA SCANNING
# ══════════════════════════════════════════════════════════════════════════════

def run_yara_scan(data: bytes) -> list:
    if not YARA_AVAILABLE or not os.path.isdir(YARA_RULES_DIR):
        return []
    matches = []
    for fname in os.listdir(YARA_RULES_DIR):
        if not fname.endswith(".yar"):
            continue
        rule_path = os.path.join(YARA_RULES_DIR, fname)
        try:
            rules = yara.compile(filepath=rule_path)
            hits = rules.match(data=data)
            for h in hits:
                matches.append(h.rule)
        except Exception:
            continue
    return matches


# ══════════════════════════════════════════════════════════════════════════════
# FORMAT-SPECIFIC ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_html(data: bytes) -> dict:
    findings = []
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        return {"html_findings": ["decode_error"]}

    if re.search(r'<input[^>]+type=["\']?password["\']?', text):
        findings.append("credential_harvesting_password_field")

    # Hidden iframe patterns
    if re.search(r'<iframe[^>]+(?:display\s*:\s*none|width=["\']?0|height=["\']?0)', text):
        findings.append("hidden_iframe_detected")
    elif "<iframe" in text:
        findings.append("iframe_present")

    for tag in [("eval(", "obfuscated_js_eval"),
                ("unescape(", "obfuscated_js_unescape"),
                ("fromcharcode", "obfuscated_js_fromcharcode"),
                ("document.write(", "obfuscated_js_document_write")]:
        if tag[0] in text:
            findings.append(tag[1])

    if re.search(r'<form[^>]+action=["\']https?://', text):
        findings.append("external_form_action")

    if "data:text/html" in text or "data:application/javascript" in text:
        findings.append("data_uri_redirect")

    if re.search(r'<meta[^>]+refresh', text):
        findings.append("meta_refresh_redirect")

    return {"html_findings": findings}


def analyze_pdf(data: bytes) -> dict:
    findings = []
    urls = []
    if not PDFMINER_AVAILABLE:
        findings.append("pdfminer_not_installed")
        return {"pdf_findings": findings, "embedded_urls": urls}
    try:
        import io
        raw_str = data[:16384].decode("latin-1", errors="ignore")
        for marker, label in [
            ("/JavaScript",    "embedded_javascript"),
            ("/JS ",           "embedded_javascript_js"),
            ("/OpenAction",    "open_action_detected"),
            ("/AA ",           "additional_actions_aa"),
            ("/Launch",        "launch_action_detected"),
            ("/EmbeddedFile",  "embedded_file_detected"),
            ("/URI",           "uri_action_detected"),
            ("/SubmitForm",    "submit_form_action"),
        ]:
            if marker in raw_str:
                findings.append(label)

        text = pdf_extract_text(io.BytesIO(data))
        url_pat = re.compile(r"https?://[^\s\"'<>\]\[]{4,}")
        urls = list(set(url_pat.findall(text)))[:25]
        if urls:
            findings.append(f"embedded_urls_count_{len(urls)}")
    except Exception as ex:
        findings.append(f"pdf_parse_error")
    return {"pdf_findings": findings, "embedded_urls": urls}


def analyze_office_macros(data: bytes) -> dict:
    findings = []
    if not OLEFILE_AVAILABLE:
        findings.append("olefile_not_installed")
        return {"macro_findings": findings}
    try:
        import io
        if not olefile.isOleFile(io.BytesIO(data)):
            findings.append("no_ole_structure")
            return {"macro_findings": findings}
        ole = olefile.OleFileIO(io.BytesIO(data))
        all_entries = ["/".join(e).lower() for e in ole.listdir()]
        if any("vba" in e for e in all_entries):
            findings.append("vba_macros_detected")
        if any("autoopen" in e or "auto_open" in e for e in all_entries):
            findings.append("autoopen_macro_detected")
        if any("document_open" in e or "documentopen" in e for e in all_entries):
            findings.append("document_open_macro_detected")
        if any("workbook_open" in e for e in all_entries):
            findings.append("workbook_open_macro_detected")
        ole.close()
    except Exception:
        findings.append("macro_analysis_error")
    return {"macro_findings": findings}


def analyze_zip(data: bytes) -> dict:
    findings = []
    executables = []
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                lower = name.lower()
                if lower.endswith((".exe", ".dll", ".sys")):
                    executables.append(name)
                elif lower.endswith((".js", ".vbs", ".ps1", ".bat", ".cmd")):
                    findings.append(f"script_file_in_zip:{name}")
                elif lower.endswith(".lnk"):
                    findings.append(f"lnk_shortcut_in_zip:{name}")
            if executables:
                findings.append(f"executables_in_zip:{','.join(executables[:5])}")
    except zipfile.BadZipFile:
        findings.append("bad_zip_file")
    except Exception:
        findings.append("zip_analysis_error")
    return {"zip_findings": findings, "nested_executables": executables}


# ══════════════════════════════════════════════════════════════════════════════
# VERDICT SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _compute_risk_score(result: dict) -> float:
    score = 5.0
    if result.get("known_bad"):
        return 98.0
    if result.get("high_entropy"):
        score += 25.0
    sus_count = len(result.get("suspicious_strings", []))
    score += min(sus_count * 8.0, 30.0)
    score += min(len(result.get("yara_matches", [])) * 12.0, 36.0)
    html_hits = result.get("html_analysis", {}).get("html_findings", [])
    score += min(len(html_hits) * 6.0, 20.0)
    pdf_hits = result.get("pdf_analysis", {}).get("pdf_findings", [])
    score += min(len(pdf_hits) * 7.0, 21.0)
    macro_hits = result.get("macro_analysis", {}).get("macro_findings", [])
    score += min(len(macro_hits) * 10.0, 25.0)
    if result.get("zip_analysis", {}).get("nested_executables"):
        score += 20.0
    return min(round(score, 1), 100.0)


def _determine_verdict(score: float, result: dict) -> str:
    if result.get("known_bad"):
        return "MALICIOUS"
    hard_malicious = [
        "hash_matches_known_malware", "embedded_javascript",
        "launch_action_detected", "autoopen_macro_detected",
        "document_open_macro_detected", "workbook_open_macro_detected",
    ]
    all_flags = (
        result.get("verdict_reasons", []) +
        result.get("html_analysis", {}).get("html_findings", []) +
        result.get("pdf_analysis", {}).get("pdf_findings", []) +
        result.get("macro_analysis", {}).get("macro_findings", [])
    )
    for flag in all_flags:
        if any(m in flag for m in hard_malicious):
            return "MALICIOUS"
    if score >= 70:
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "CLEAN"


# ══════════════════════════════════════════════════════════════════════════════
# MASTER ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze_file(file_bytes: bytes, filename: str) -> dict:
    """
    Main entry point called by FastAPI scan endpoint.
    Returns a flat dict compatible with the standard module_results schema.
    """
    result = {
        "filename":          filename,
        "file_size":         len(file_bytes),
        "file_type":         "",
        "hashes":            {},
        "known_bad":         False,
        "entropy":           0.0,
        "high_entropy":      False,
        "strings_count":     0,
        "suspicious_strings": [],
        "yara_matches":      [],
        "verdict_reasons":   [],
        "html_analysis":     {},
        "pdf_analysis":      {},
        "macro_analysis":    {},
        "zip_analysis":      {},
        "risk_score":        5.0,
        "verdict":           "CLEAN",
    }

    if len(file_bytes) > MAX_FILE_SIZE:
        result["verdict_reasons"].append("file_too_large_partial_analysis")

    # ── Hashes ──
    result["hashes"] = compute_hashes(file_bytes)
    sha256 = result["hashes"]["sha256"]
    if check_known_bad(sha256):
        result["known_bad"] = True
        result["verdict_reasons"].append("hash_matches_known_malware")

    # ── File type ──
    result["file_type"] = detect_file_type(file_bytes, filename)
    mime = result["file_type"]

    # ── Entropy ──
    result["entropy"] = compute_entropy(file_bytes)
    result["high_entropy"] = result["entropy"] > ENTROPY_THRESHOLD
    if result["high_entropy"]:
        result["verdict_reasons"].append(
            f"high_entropy_{result['entropy']}_possible_packing"
        )

    # ── Strings ──
    strings = extract_printable_strings(file_bytes)
    result["strings_count"] = len(strings)
    result["suspicious_strings"] = detect_suspicious_strings(strings)
    if result["suspicious_strings"]:
        result["verdict_reasons"].append(
            "suspicious_strings_found:" + ",".join(result["suspicious_strings"][:4])
        )

    # ── YARA ──
    result["yara_matches"] = run_yara_scan(file_bytes)
    if result["yara_matches"]:
        result["verdict_reasons"].append(
            "yara_matches:" + ",".join(result["yara_matches"])
        )

    # ── Format-specific ──
    fn_lower = filename.lower()
    if mime == "text/html" or fn_lower.endswith((".html", ".htm")):
        result["html_analysis"] = analyze_html(file_bytes)

    elif mime == "application/pdf" or fn_lower.endswith(".pdf"):
        result["pdf_analysis"] = analyze_pdf(file_bytes)

    elif mime in ("application/msword", "application/vnd.ms-excel",
                  "application/vnd.ms-powerpoint") or fn_lower.endswith(
                      (".doc", ".xls", ".ppt", ".docm", ".xlsm")):
        result["macro_analysis"] = analyze_office_macros(file_bytes)

    elif mime == "application/zip" or fn_lower.endswith(".zip"):
        result["zip_analysis"] = analyze_zip(file_bytes)

    # ── Final scoring ──
    result["risk_score"] = _compute_risk_score(result)
    result["verdict"] = _determine_verdict(result["risk_score"], result)

    return result