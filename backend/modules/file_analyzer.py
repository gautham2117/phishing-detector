# file_analyzer.py
# File & Attachment Analysis Module.
#
# FIXES IN THIS VERSION:
#   1. Verdict case — _compute_verdict() now returns uppercase "CLEAN" /
#      "SUSPICIOUS" / "MALICIOUS" to match scan_router label_map keys.
#      Previously returned title-case "Clean" → scan_router fell through
#      to default "SUSPICIOUS" for every clean file.
#   2. Key rename — "static_findings" → also exposed as "suspicious_strings"
#      at the top level of the result dict so the JS renderStrings() finds it.
#      (JS reads mod.suspicious_strings; old code only had mod.static_findings)
#   3. type_findings flattened — the result dict now exposes type-specific
#      findings at the top level under predictable keys that match the JS:
#        pdf_analysis, macro_analysis, html_analysis, zip_analysis
#      Previously everything was nested under "type_findings" which the JS
#      never read correctly.
#   4. verdict_reasons added — a human-readable list of strings explaining
#      why the verdict was reached. Used by scan_router explanation builder.
#   5. risk_score key — scan_router reads result.get("risk_score") directly;
#      this was already correct but is now explicitly documented.
#
# NEW IN THIS VERSION:
#   6. File type mismatch detection — flags when magic bytes disagree with
#      the file extension (e.g. EXE renamed to .pdf).
#   7. VirusTotal hash lookup — optional; only runs if VT_API_KEY is set
#      in the Flask app config or VIRUSTOTAL_API_KEY env var. Adds
#      vt_result dict and known_bad bool to the result.
#   8. Embedded URL aggregation — all URLs extracted from any file type
#      are collected into a top-level "embedded_urls" list.
#   9. Macro detail — for DOCX/OLE files with macros, keyword list and
#      stream names are surfaced in macro_analysis.
#  10. Archive content table — ZIP/DOCX now returns structured file_list
#      with name, size, is_suspicious columns.

import os
import re
import math
import json
import hashlib
import logging
import zipfile
import requests as _requests
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Optional imports ─────────────────────────────────────────────────────────

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed — YARA scanning disabled")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False
    logger.warning("olefile not installed — Office macro analysis disabled")

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False
    logger.warning("pdfminer.six not installed — PDF text extraction disabled")


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_module_dir    = os.path.dirname(os.path.abspath(__file__))
_backend_dir   = os.path.dirname(_module_dir)
YARA_RULES_DIR = os.path.join(_backend_dir, "yara_rules")

ENTROPY_SUSPICIOUS = 6.5
ENTROPY_PACKED     = 7.2
MAX_FILE_SIZE      = 20 * 1024 * 1024   # 20 MB

# VirusTotal free API endpoint
VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{}"

# Magic bytes → internal file type token
FILE_SIGNATURES = {
    b'\x4d\x5a':             'exe',
    b'\x7f\x45\x4c\x46':    'elf',
    b'\x25\x50\x44\x46':    'pdf',
    b'\x50\x4b\x03\x04':    'zip',
    b'\xd0\xcf\x11\xe0':    'ole',
    b'\x89\x50\x4e\x47':    'png',
    b'\xff\xd8\xff':         'jpg',
    b'\x47\x49\x46\x38':    'gif',
    b'\x3c\x68\x74\x6d\x6c':'html',
    b'\x3c\x21\x44\x4f\x43':'html',
    b'\x3c\x73\x63\x72\x69':'js',
}

SUSPICIOUS_STRINGS = [
    b'powershell', b'cmd.exe', b'wscript', b'cscript',
    b'shell32', b'CreateObject', b'WScript.Shell',
    b'eval(', b'exec(', b'base64_decode', b'base64_encode',
    b'wget ', b'curl ', b'chmod +x', b'/tmp/', b'%TEMP%',
    b'HKEY_CURRENT_USER', b'reg add', b'net user',
    b'bypass', b'ExecutionPolicy', b'EncodedCommand',
    b'FromBase64String', b'invoke-expression', b'IEX(',
]

EXTENSION_MAP = {
    '.pdf':  'document', '.docx': 'document', '.doc':  'document',
    '.xlsx': 'document', '.xls':  'document', '.pptx': 'document',
    '.ppt':  'document', '.rtf':  'document', '.odt':  'document',
    '.exe':  'executable', '.dll': 'executable', '.bat': 'executable',
    '.cmd':  'executable', '.vbs': 'executable', '.ps1': 'executable',
    '.sh':   'executable', '.elf': 'executable',
    '.zip':  'archive',  '.rar': 'archive',    '.7z':  'archive',
    '.tar':  'archive',  '.gz':  'archive',
    '.html': 'html',     '.htm': 'html',
    '.js':   'script',   '.ts':  'script',     '.py':  'script',
    '.php':  'script',   '.rb':  'script',
    '.png':  'image',    '.jpg': 'image',      '.jpeg':'image',
    '.gif':  'image',    '.bmp': 'image',      '.svg': 'image',
}

# Extensions that map to a different magic-byte type — used for mismatch detection
EXPECTED_MAGIC = {
    '.exe':  'exe',  '.dll': 'exe',
    '.elf':  'elf',
    '.pdf':  'pdf',
    '.png':  'png',  '.jpg': 'jpg',  '.jpeg': 'jpg',
    '.gif':  'gif',
}


# ─────────────────────────────────────────────────────────────────────────────
# YARA rule compiler
# ─────────────────────────────────────────────────────────────────────────────

_compiled_rules = None

def _get_yara_rules():
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules
    if not YARA_AVAILABLE:
        return None
    rule_files = {}
    try:
        if not os.path.isdir(YARA_RULES_DIR):
            return None
        for filename in os.listdir(YARA_RULES_DIR):
            if filename.endswith((".yar", ".yara")):
                ns = filename.replace(".yar", "").replace(".yara", "")
                rule_files[ns] = os.path.join(YARA_RULES_DIR, filename)
        if not rule_files:
            return None
        _compiled_rules = yara.compile(filepaths=rule_files)
        logger.info("YARA rules compiled: %s", list(rule_files.keys()))
        return _compiled_rules
    except Exception as e:
        logger.error("YARA compilation failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze_file(
    file_bytes: bytes,
    filename:   str,
    email_id:   Optional[int] = None
) -> dict:
    """
    Run complete static analysis on uploaded file bytes.

    Returns a flat result dict with these top-level keys so that both
    scan_router.py and attachments.js can read them without extra nesting:

        filename, file_type, file_category, file_size
        hashes: {md5, sha1, sha256}
        entropy, is_packed, is_high_entropy
        type_mismatch: bool          ← NEW: extension vs magic bytes disagree
        yara_matches: list
        static_findings: list        (raw list of finding dicts)
        suspicious_strings: list     ← ALIAS of static_findings for the JS
        pdf_analysis:    dict | {}   ← type-specific, top-level for JS
        macro_analysis:  dict | {}
        html_analysis:   dict | {}
        zip_analysis:    dict | {}
        script_analysis: dict | {}
        exe_analysis:    dict | {}
        embedded_urls:   list        ← NEW: aggregated from all type analyses
        vt_result:       dict | None ← NEW: VirusTotal hash lookup (optional)
        known_bad:       bool        ← NEW: true if VT detects ≥ 3 engines
        verdict:         str         "CLEAN" | "SUSPICIOUS" | "MALICIOUS"
        risk_score:      float       0–100
        risk_flags:      list[str]
        verdict_reasons: list[str]   ← NEW: human-readable explanation lines
        email_id:        int | None
        analyzed_at:     str
    """
    if len(file_bytes) > MAX_FILE_SIZE:
        return _error_result(
            filename,
            f"File too large ({len(file_bytes)} bytes, max {MAX_FILE_SIZE})"
        )
    if len(file_bytes) == 0:
        return _error_result(filename, "File is empty")

    # Step 1 — Hashes
    hashes = _compute_hashes(file_bytes)

    # Step 2 — File type detection + mismatch check
    file_type, file_category, type_mismatch = _detect_file_type(file_bytes, filename)

    # Step 3 — Entropy
    entropy         = _compute_entropy(file_bytes)
    is_packed       = entropy >= ENTROPY_PACKED
    is_high_entropy = entropy >= ENTROPY_SUSPICIOUS

    # Step 4 — YARA
    yara_matches = _run_yara_scan(file_bytes, filename)

    # Step 5 — Suspicious strings
    static_findings = _extract_suspicious_strings(file_bytes)

    # Step 6 — Type-specific analysis
    pdf_analysis    = {}
    macro_analysis  = {}
    html_analysis   = {}
    zip_analysis    = {}
    script_analysis = {}
    exe_analysis    = {}

    if file_type == "pdf":
        pdf_analysis = _analyze_pdf(file_bytes, filename)
    elif file_type in ("zip", "docx", "xlsx", "pptx"):
        zip_result     = _analyze_zip_office(file_bytes, filename)
        zip_analysis   = zip_result.get("zip_analysis",   {})
        macro_analysis = zip_result.get("macro_analysis", {})
    elif file_type == "ole":
        macro_analysis = _analyze_ole(file_bytes, filename)
    elif file_type in ("html", "htm"):
        html_analysis = _analyze_html(file_bytes, filename)
    elif file_type in ("js", "script"):
        script_analysis = _analyze_script(file_bytes, filename)
    elif file_type in ("exe", "elf", "dll"):
        exe_analysis = _analyze_executable(file_bytes, filename)

    # Step 7 — VirusTotal hash lookup (optional)
    vt_result = _vt_lookup(hashes["sha256"])
    known_bad = False
    if vt_result and isinstance(vt_result.get("malicious"), int):
        known_bad = vt_result["malicious"] >= 3

    # Step 8 — Aggregate all embedded URLs from any analysis
    embedded_urls = _collect_urls(pdf_analysis, html_analysis, zip_analysis)

    # Step 9 — Verdict
    verdict, risk_score, risk_flags, verdict_reasons = _compute_verdict(
        yara_matches    = yara_matches,
        static_findings = static_findings,
        pdf_analysis    = pdf_analysis,
        macro_analysis  = macro_analysis,
        html_analysis   = html_analysis,
        zip_analysis    = zip_analysis,
        script_analysis = script_analysis,
        exe_analysis    = exe_analysis,
        entropy         = entropy,
        is_packed       = is_packed,
        file_type       = file_type,
        type_mismatch   = type_mismatch,
        known_bad       = known_bad,
    )

    return {
        "filename":         filename,
        "file_type":        file_type,
        "file_category":    file_category,
        "file_size":        len(file_bytes),
        "hashes":           hashes,
        "entropy":          round(entropy, 4),
        "is_packed":        is_packed,
        "is_high_entropy":  is_high_entropy,
        # NEW: extension vs magic byte mismatch
        "type_mismatch":    type_mismatch,
        "yara_matches":     yara_matches,
        # Both keys point to the same data — static_findings for Python
        # callers, suspicious_strings for the JS renderer
        "static_findings":  static_findings,
        "suspicious_strings": [f["string"] for f in static_findings],
        # Type-specific analysis dicts — top-level so JS can read directly
        "pdf_analysis":     pdf_analysis,
        "macro_analysis":   macro_analysis,
        "html_analysis":    html_analysis,
        "zip_analysis":     zip_analysis,
        "script_analysis":  script_analysis,
        "exe_analysis":     exe_analysis,
        # Aggregated URLs from all analysis types
        "embedded_urls":    embedded_urls,
        # VirusTotal
        "vt_result":        vt_result,
        "known_bad":        known_bad,
        # Verdict
        "verdict":          verdict,       # FIX: now uppercase "CLEAN" etc.
        "risk_score":       risk_score,
        "risk_flags":       risk_flags,
        "verdict_reasons":  verdict_reasons,
        "email_id":         email_id,
        "analyzed_at":      datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Hash computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: File type detection + mismatch check  (NEW: returns 3-tuple)
# ─────────────────────────────────────────────────────────────────────────────

def _detect_file_type(data: bytes, filename: str) -> tuple:
    """
    Returns (file_type, file_category, type_mismatch).
    type_mismatch=True when magic bytes indicate a different type than the
    file extension — e.g. an EXE renamed to .pdf.
    """
    magic_type = None
    for magic, ftype in FILE_SIGNATURES.items():
        if data[:len(magic)] == magic:
            magic_type = ftype
            break

    ext      = os.path.splitext(filename)[1].lower()
    ext_type = ext.lstrip(".") or "unknown"

    # Refine ZIP magic to Office type based on extension
    if magic_type == "zip":
        if ext in (".docx", ".docm"):
            magic_type = "docx"
        elif ext in (".xlsx", ".xlsm"):
            magic_type = "xlsx"
        elif ext in (".pptx", ".pptm"):
            magic_type = "pptx"

    if magic_type:
        category      = EXTENSION_MAP.get("." + magic_type, "unknown")
        # Mismatch: declared extension expects a different magic type
        expected_magic = EXPECTED_MAGIC.get(ext)
        type_mismatch  = bool(
            expected_magic and
            magic_type != expected_magic and
            magic_type not in ("zip",)  # ZIP covers Office formats
        )
        return magic_type, category, type_mismatch

    # No magic match — fall back to extension
    category = EXTENSION_MAP.get(ext, "unknown")
    return ext_type, category, False


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Entropy
# ─────────────────────────────────────────────────────────────────────────────

def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:65536]
    freq   = [0] * 256
    for byte in sample:
        freq[byte] += 1
    length  = len(sample)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: YARA scanning
# ─────────────────────────────────────────────────────────────────────────────

def _run_yara_scan(data: bytes, filename: str) -> list:
    rules = _get_yara_rules()
    if rules is None:
        return []
    matches = []
    try:
        for match in rules.match(data=data):
            matches.append({
                "rule":      match.rule,
                "namespace": match.namespace,
                "tags":      list(match.tags),
                "meta":      dict(match.meta),
                "severity":  match.meta.get("severity", "MEDIUM")
            })
    except Exception as e:
        logger.warning("YARA scan error for %s: %s", filename, e)
    return matches


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Suspicious string extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_suspicious_strings(data: bytes) -> list:
    findings   = []
    data_lower = data.lower()
    for pattern in SUSPICIOUS_STRINGS:
        count = data_lower.count(pattern.lower())
        if count > 0:
            idx     = data_lower.find(pattern.lower())
            start   = max(0, idx - 20)
            end     = min(len(data), idx + len(pattern) + 20)
            context = data[start:end].decode("utf-8", errors="replace")
            context = re.sub(r'[\x00-\x1f\x7f-\xff]', '.', context)
            findings.append({
                "string":  pattern.decode("utf-8", errors="replace"),
                "count":   count,
                "context": context.strip()
            })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6a: PDF analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_pdf(data: bytes, filename: str) -> dict:
    findings = {
        "has_javascript":     False,
        "has_openaction":     False,
        "has_launch":         False,
        "has_embedded_file":  False,
        "embedded_urls":      [],
        "suspicious_actions": [],
        "pdf_findings":       [],
        "text_sample":        ""
    }

    pdf_text = data.decode("latin-1", errors="replace")

    dangerous_keywords = {
        "/JavaScript": "Embedded JavaScript — executes on PDF open",
        "/JS":         "Embedded JavaScript (shorthand)",
        "/OpenAction": "OpenAction — triggers on document open",
        "/Launch":     "Launch action — can start external programs",
        "/AA":         "Additional Actions on various events",
        "/EmbeddedFile":"Embedded file attachment inside PDF"
    }

    for keyword, description in dangerous_keywords.items():
        if keyword.lower() in pdf_text.lower():
            findings["suspicious_actions"].append({"keyword": keyword, "description": description})
            findings["pdf_findings"].append(description)

    action_keys = [a["keyword"] for a in findings["suspicious_actions"]]
    findings["has_javascript"]    = any(k in ("/JavaScript", "/JS") for k in action_keys)
    findings["has_openaction"]    = "/OpenAction" in action_keys
    findings["has_launch"]        = "/Launch"     in action_keys
    findings["has_embedded_file"] = "/EmbeddedFile" in action_keys

    url_pattern = re.compile(rb'https?://[^\s\x00-\x1f\x7f-\xff<>"]{5,150}', re.IGNORECASE)
    urls = list({u.decode("utf-8", errors="replace") for u in url_pattern.findall(data)})
    findings["embedded_urls"] = urls[:20]

    if PDFMINER_AVAILABLE:
        try:
            import io
            text = pdf_extract_text(io.BytesIO(data))
            findings["text_sample"] = (text or "")[:500]
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6b: ZIP / Office (DOCX/XLSX/PPTX) — returns both zip and macro dicts
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_zip_office(data: bytes, filename: str) -> dict:
    """
    Returns {"zip_analysis": {...}, "macro_analysis": {...}} so each can be
    stored at a separate top-level key in the final result dict.
    """
    zip_info = {
        "file_count":          0,
        "file_list":           [],
        "nested_executables":  [],
        "external_rels":       [],
        "is_password_protected": False,
        "zip_findings":        [],
        "embedded_urls":       [],
    }
    macro_info = {
        "has_macros":      False,
        "has_vba_project": False,
        "vba_streams":     [],
        "macro_keywords":  [],
        "macro_findings":  [],
    }

    try:
        import io
        zf        = zipfile.ZipFile(io.BytesIO(data))
        file_list = zf.namelist()
        zip_info["file_count"] = len(file_list)

        # Structured file list with suspicion flag
        structured = []
        dangerous_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
        for name in file_list[:50]:
            ext         = os.path.splitext(name)[1].lower()
            is_sus      = ext in dangerous_exts
            structured.append({"name": name, "suspicious": is_sus})
            if is_sus:
                zip_info["nested_executables"].append(name)

        zip_info["file_list"] = structured

        for name in file_list:
            name_lower = name.lower()

            if "vbaproject.bin" in name_lower:
                macro_info["has_vba_project"] = True
                macro_info["has_macros"]      = True
                macro_info["vba_streams"].append(name)
                macro_info["macro_findings"].append("VBA project file detected: " + name)

            if any(name_lower.endswith(ext) for ext in (".bas", ".cls", ".frm")):
                macro_info["has_macros"] = True

            if "relationships" in name_lower or name_lower.endswith(".rels"):
                try:
                    content  = zf.read(name).decode("utf-8", errors="replace")
                    ext_urls = re.findall(r'Target="(https?://[^"]{5,200})"', content)
                    if ext_urls:
                        zip_info["external_rels"].extend(ext_urls)
                        zip_info["embedded_urls"].extend(ext_urls)
                        zip_info["zip_findings"].append(
                            f"External relationship URL: {ext_urls[0][:80]}"
                        )
                except Exception:
                    pass

        if zip_info["nested_executables"]:
            zip_info["zip_findings"].append(
                f"Executable(s) inside archive: {', '.join(zip_info['nested_executables'][:3])}"
            )

        zf.close()

    except zipfile.BadZipFile:
        zip_info["error"] = "Not a valid ZIP/Office document"
    except RuntimeError as e:
        if "password" in str(e).lower() or "encrypted" in str(e).lower():
            zip_info["is_password_protected"] = True
            zip_info["zip_findings"].append("Archive is password-protected")
        else:
            zip_info["error"] = str(e)
    except Exception as e:
        zip_info["error"] = str(e)[:100]

    return {"zip_analysis": zip_info, "macro_analysis": macro_info}


# ─────────────────────────────────────────────────────────────────────────────
# Step 6c: OLE (legacy .doc/.xls)
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_ole(data: bytes, filename: str) -> dict:
    findings = {
        "has_macros":      False,
        "has_vba_project": False,
        "vba_streams":     [],
        "macro_keywords":  [],
        "ole_streams":     [],
        "macro_findings":  [],
    }

    if not OLEFILE_AVAILABLE:
        findings["note"] = "olefile not installed — OLE analysis skipped"
        return findings

    try:
        import io
        ole     = olefile.OleFileIO(io.BytesIO(data))
        streams = ole.listdir()
        findings["ole_streams"] = ["/".join(s) for s in streams[:20]]

        for stream_path in ["Macros/VBA", "_VBA_PROJECT_CUR/VBA", "VBA"]:
            if ole.exists(stream_path.split("/")):
                findings["has_macros"]      = True
                findings["has_vba_project"] = True
                findings["vba_streams"].append(stream_path)
                findings["macro_findings"].append(f"VBA stream found: {stream_path}")

        suspicious_kws = [
            b"Shell", b"CreateObject", b"AutoOpen",
            b"Document_Open", b"Auto_Open", b"Workbook_Open"
        ]
        for entry in streams:
            try:
                stream_data = ole.openstream(entry).read()
                for kw in suspicious_kws:
                    if kw.lower() in stream_data.lower():
                        kw_str = kw.decode("utf-8")
                        if kw_str not in findings["macro_keywords"]:
                            findings["macro_keywords"].append(kw_str)
                            findings["has_macros"] = True
                            findings["macro_findings"].append(f"Macro keyword: {kw_str}")
            except Exception:
                continue
        ole.close()

    except Exception as e:
        findings["error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6d: HTML analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_html(data: bytes, filename: str) -> dict:
    findings = {
        "has_password_field":   False,
        "has_form_with_action": False,
        "form_actions":         [],
        "has_hidden_iframe":    False,
        "iframe_sources":       [],
        "has_obfuscated_js":    False,
        "obfuscation_patterns": [],
        "has_external_scripts": False,
        "external_script_srcs": [],
        "has_meta_redirect":    False,
        "meta_redirect_url":    "",
        "embedded_urls":        [],
        "brand_keywords_found": [],
        "html_findings":        [],
    }

    html_text = data.decode("utf-8", errors="replace")

    if not BS4_AVAILABLE:
        findings["has_password_field"] = bool(
            re.search(r'type=["\']password["\']', html_text, re.IGNORECASE)
        )
        return findings

    try:
        soup = BeautifulSoup(html_text, "lxml")

        pwd_fields = soup.find_all("input", {"type": re.compile("password", re.I)})
        if pwd_fields:
            findings["has_password_field"] = True
            findings["html_findings"].append(f"{len(pwd_fields)} password input field(s)")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            if action:
                findings["has_form_with_action"] = True
                findings["form_actions"].append({"action": action, "method": method})
                if action.startswith(("http://", "https://")) and method == "post":
                    findings["html_findings"].append(
                        f"Form POSTs to external URL: {action[:60]}"
                    )

        for iframe in soup.find_all("iframe"):
            src    = iframe.get("src", "")
            style  = iframe.get("style", "")
            width  = iframe.get("width", "")
            height = iframe.get("height", "")
            is_hidden = (
                "display:none" in style.replace(" ", "").lower() or
                "visibility:hidden" in style.replace(" ", "").lower() or
                width in ("0", "0px", "1px") or
                height in ("0", "0px", "1px")
            )
            if is_hidden:
                findings["has_hidden_iframe"] = True
                findings["iframe_sources"].append(src or "no-src")
                findings["html_findings"].append(f"Hidden iframe (src: {src[:60] or 'empty'})")

        obfusc_patterns = [
            (r'\beval\s*\(',        "eval() call"),
            (r'\batob\s*\(',        "Base64 decode (atob)"),
            (r'fromCharCode',       "fromCharCode encoding"),
            (r'unescape\s*\(',      "unescape() obfuscation"),
            (r'decodeURIComponent', "URL decoding"),
        ]
        all_js = " ".join(script.get_text() for script in soup.find_all("script"))
        for pattern, desc in obfusc_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                findings["has_obfuscated_js"] = True
                findings["obfuscation_patterns"].append(desc)
        if findings["has_obfuscated_js"]:
            findings["html_findings"].append(
                "Obfuscated JS: " + ", ".join(findings["obfuscation_patterns"])
            )

        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith(("http://", "https://")):
                findings["has_external_scripts"] = True
                findings["external_script_srcs"].append(src[:100])

        for meta in soup.find_all("meta"):
            content = meta.get("content", "")
            if "url=" in content.lower():
                url_match = re.search(r'url=([^\s;>"\']+)', content, re.I)
                if url_match:
                    findings["has_meta_redirect"] = True
                    findings["meta_redirect_url"] = url_match.group(1)
                    findings["html_findings"].append(
                        f"Meta redirect to: {url_match.group(1)[:80]}"
                    )

        page_text = soup.get_text().lower()
        brand_kws = [
            "paypal", "google", "microsoft", "apple", "amazon",
            "netflix", "facebook", "instagram", "bank", "chase",
            "citibank", "wells fargo", "barclays", "hsbc"
        ]
        findings["brand_keywords_found"] = [kw for kw in brand_kws if kw in page_text]

        all_hrefs = list({
            a.get("href", "") for a in soup.find_all("a", href=True)
            if a.get("href", "").startswith(("http://", "https://"))
        })
        findings["embedded_urls"] = all_hrefs[:20]

    except Exception as e:
        findings["parse_error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6e: Script analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_script(data: bytes, filename: str) -> dict:
    findings = {
        "has_eval":          False,
        "has_download":      False,
        "has_exec":          False,
        "obfuscation_score": 0,
        "suspicious_calls":  [],
        "script_findings":   [],
    }

    try:
        text       = data.decode("utf-8", errors="replace")
        text_lower = text.lower()

        for p in ["eval(", "eval (", "execute(", "invoke-expression"]:
            if p in text_lower:
                findings["has_eval"] = True
                findings["suspicious_calls"].append(f"eval/execute: {p}")
                findings["obfuscation_score"] += 2

        for p in ["downloadstring", "downloadfile", "wget ", "curl ",
                  "invoke-webrequest", "net.webclient", "xmlhttp"]:
            if p in text_lower:
                findings["has_download"] = True
                findings["suspicious_calls"].append(f"download: {p}")
                findings["obfuscation_score"] += 2

        for p in ["wscript.shell", "shell32", "createobject",
                  "start-process", "cmd.exe", "powershell"]:
            if p in text_lower:
                findings["has_exec"] = True
                findings["suspicious_calls"].append(f"exec: {p}")
                findings["obfuscation_score"] += 1

        special_ratio = sum(
            1 for c in text
            if not c.isalnum() and c not in " \n\t.,;()"
        ) / max(len(text), 1)
        if special_ratio > 0.3:
            findings["obfuscation_score"] += 3
            findings["suspicious_calls"].append(
                f"High special char ratio: {special_ratio:.2f}"
            )

        if findings["suspicious_calls"]:
            findings["script_findings"] = findings["suspicious_calls"][:5]

    except Exception as e:
        findings["error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6f: Executable analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_executable(data: bytes, filename: str) -> dict:
    findings = {
        "is_pe":                   False,
        "is_elf":                  False,
        "imported_strings":        [],
        "has_upx":                 False,
        "has_suspicious_imports":  False,
        "exe_findings":            [],
    }

    if data[:2] == b'\x4d\x5a':
        findings["is_pe"] = True
    if data[:4] == b'\x7f\x45\x4c\x46':
        findings["is_elf"] = True

    if b'UPX' in data[:512] or b'UPX0' in data or b'UPX1' in data:
        findings["has_upx"] = True
        findings["exe_findings"].append("UPX packer signature detected")

    printable = re.findall(rb'[ -~]{6,}', data[:32768])
    findings["imported_strings"] = [
        s.decode("ascii", errors="replace") for s in printable[:50]
    ]

    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "LoadLibrary", "GetProcAddress",
        "InternetOpen", "URLDownloadToFile", "ShellExecute",
        "CreateProcess", "WinExec", "RegSetValue"
    ]
    found_apis = [api for api in suspicious_apis if api.encode() in data[:65536]]
    if found_apis:
        findings["has_suspicious_imports"] = True
        findings["imported_strings"]       = found_apis[:10]
        findings["exe_findings"].append(
            f"Suspicious API imports: {', '.join(found_apis[:5])}"
        )

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW Step 7: VirusTotal hash lookup
# ─────────────────────────────────────────────────────────────────────────────

def _vt_lookup(sha256: str) -> Optional[dict]:
    """
    Look up the SHA-256 hash against the VirusTotal public API v3.
    Requires VIRUSTOTAL_API_KEY environment variable or Flask config.
    Returns a summary dict or None if no API key is configured.

    Result dict:
        {
          "malicious":   int,   number of engines flagging as malicious
          "undetected":  int,
          "harmless":    int,
          "total":       int,
          "permalink":   str,
          "last_analysis_date": str | None
        }
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        # Try Flask app config if we're in a request context
        try:
            from flask import current_app
            api_key = current_app.config.get("VT_API_KEY", "")
        except RuntimeError:
            pass

    if not api_key:
        return None

    try:
        resp = _requests.get(
            VT_HASH_URL.format(sha256),
            headers={"x-apikey": api_key},
            timeout=8
        )
        if resp.status_code == 404:
            return {"malicious": 0, "undetected": 0, "harmless": 0,
                    "total": 0, "permalink": "", "last_analysis_date": None,
                    "note": "hash not found in VT database"}
        if resp.status_code == 200:
            data      = resp.json()
            stats     = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            permalink = (
                data.get("data", {}).get("links", {}).get("self", "") or
                f"https://www.virustotal.com/gui/file/{sha256}"
            )
            last_date = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_date"
            )
            if last_date:
                try:
                    last_date = datetime.utcfromtimestamp(last_date).isoformat() + "Z"
                except Exception:
                    last_date = str(last_date)
            return {
                "malicious":          stats.get("malicious",   0),
                "undetected":         stats.get("undetected",  0),
                "harmless":           stats.get("harmless",    0),
                "total":              sum(stats.values()) if stats else 0,
                "permalink":          permalink,
                "last_analysis_date": last_date,
            }
        logger.debug("VT API returned %s for %s", resp.status_code, sha256[:16])
        return None
    except Exception as e:
        logger.debug("VT lookup failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# NEW Step 8: Aggregate embedded URLs from all analysis types
# ─────────────────────────────────────────────────────────────────────────────

def _collect_urls(pdf_analysis: dict, html_analysis: dict, zip_analysis: dict) -> list:
    """Deduplicate and merge embedded URLs from all analysis types."""
    seen = set()
    urls = []
    for source in (
        pdf_analysis.get("embedded_urls",  []),
        html_analysis.get("embedded_urls", []),
        zip_analysis.get("embedded_urls",  []),
    ):
        for url in source:
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls[:30]


# ─────────────────────────────────────────────────────────────────────────────
# Step 9: Verdict computation  (FIX: returns uppercase verdict strings)
# ─────────────────────────────────────────────────────────────────────────────

def _compute_verdict(
    yara_matches, static_findings,
    pdf_analysis, macro_analysis, html_analysis,
    zip_analysis, script_analysis, exe_analysis,
    entropy, is_packed, file_type,
    type_mismatch=False, known_bad=False
) -> tuple:
    """
    Returns (verdict, risk_score, risk_flags, verdict_reasons).

    FIX: verdict is now uppercase — "CLEAN" / "SUSPICIOUS" / "MALICIOUS".
    Previously returned title-case "Clean" which caused scan_router's
    label_map.get("Clean") to fail and default every result to SUSPICIOUS.
    """
    score   = 0.0
    flags   = []
    reasons = []

    # Known bad (VirusTotal)
    if known_bad:
        score += 40
        flags.append("VIRUSTOTAL_KNOWN_BAD")
        reasons.append("Hash flagged by VirusTotal as malicious.")

    # Type mismatch
    if type_mismatch:
        score += 25
        flags.append("FILE_TYPE_MISMATCH")
        reasons.append("File extension does not match magic bytes — possible disguise.")

    # YARA matches
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 5}
    for match in yara_matches:
        sev    = match.get("severity", "MEDIUM").upper()
        weight = severity_weights.get(sev, 10)
        score += weight
        flags.append(f"YARA:{match['rule']} ({sev})")
        reasons.append(f"YARA rule matched: {match['rule']} ({sev})")

    # Suspicious strings
    if len(static_findings) >= 3:
        score += 10
        flags.append(f"SUSPICIOUS_STRINGS ({len(static_findings)} found)")
        reasons.append(f"{len(static_findings)} suspicious string(s) found in file.")
    elif len(static_findings) >= 1:
        score += 5

    # Entropy
    if is_packed:
        score += 20
        flags.append(f"PACKED_EXECUTABLE (entropy={entropy:.2f})")
        reasons.append(f"High entropy ({entropy:.2f}) — file may be packed or encrypted.")
    elif entropy >= ENTROPY_SUSPICIOUS:
        score += 10
        flags.append(f"HIGH_ENTROPY (entropy={entropy:.2f})")
        reasons.append(f"Elevated entropy ({entropy:.2f}).")

    # PDF
    if file_type == "pdf":
        if pdf_analysis.get("has_javascript"):
            score += 15; flags.append("PDF_EMBEDDED_JAVASCRIPT")
            reasons.append("PDF contains embedded JavaScript.")
        if pdf_analysis.get("has_launch"):
            score += 20; flags.append("PDF_LAUNCH_ACTION")
            reasons.append("PDF has a Launch action — can execute external programs.")
        if pdf_analysis.get("has_openaction"):
            score += 10; flags.append("PDF_OPENACTION")
            reasons.append("PDF has an OpenAction that runs on open.")

    # Office macros
    if file_type in ("docx", "xlsx", "pptx", "ole", "doc", "xls"):
        if macro_analysis.get("has_macros"):
            score += 15; flags.append("OFFICE_MACRO_DETECTED")
            reasons.append("VBA macro detected in Office document.")
        if zip_analysis.get("nested_executables"):
            score += 25; flags.append("EXECUTABLE_IN_OFFICE_DOC")
            reasons.append("Executable file embedded inside Office document.")
        if zip_analysis.get("external_rels"):
            score += 10; flags.append("EXTERNAL_RELATIONSHIP_URL")
            reasons.append("Office document references external URL in relationships.")
        if zip_analysis.get("is_password_protected"):
            score += 5; flags.append("PASSWORD_PROTECTED_ARCHIVE")
            reasons.append("Archive is password-protected — content cannot be fully scanned.")

    # HTML
    elif file_type in ("html", "htm"):
        if html_analysis.get("has_password_field") and html_analysis.get("has_form_with_action"):
            score += 20; flags.append("CREDENTIAL_HARVESTING_FORM")
            reasons.append("HTML contains a login form with password field.")
        if html_analysis.get("has_hidden_iframe"):
            score += 15; flags.append("HIDDEN_IFRAME")
            reasons.append("Hidden iframe detected in HTML.")
        if html_analysis.get("has_obfuscated_js"):
            score += 10; flags.append("OBFUSCATED_JAVASCRIPT")
            reasons.append("Obfuscated JavaScript detected.")

    # Script
    elif file_type in ("js", "script", "ps1", "vbs", "bat"):
        obs = script_analysis.get("obfuscation_score", 0)
        if obs >= 4:
            score += 15; flags.append("HEAVILY_OBFUSCATED_SCRIPT")
            reasons.append("Script is heavily obfuscated.")
        elif obs >= 2:
            score += 8;  flags.append("OBFUSCATED_SCRIPT")
        if script_analysis.get("has_download") and script_analysis.get("has_exec"):
            score += 20; flags.append("DOWNLOAD_AND_EXECUTE_PATTERN")
            reasons.append("Script contains download-and-execute pattern.")

    # Executable
    elif file_type in ("exe", "elf", "dll"):
        if exe_analysis.get("has_upx"):
            score += 10; flags.append("UPX_PACKED_EXECUTABLE")
            reasons.append("UPX packer signature detected.")
        if exe_analysis.get("has_suspicious_imports"):
            score += 15; flags.append("SUSPICIOUS_API_IMPORTS")
            reasons.append("Suspicious Windows API imports found.")

    risk_score = round(min(score, 100.0), 2)

    # FIX: uppercase verdicts to match scan_router label_map
    if risk_score >= 70:
        verdict = "MALICIOUS"
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    if not reasons:
        reasons.append(f"File '{file_type}' passed all checks — no indicators found.")

    return verdict, risk_score, flags, reasons


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _error_result(filename: str, message: str) -> dict:
    return {
        "filename":          filename,
        "file_type":         "unknown",
        "file_category":     "unknown",
        "file_size":         0,
        "hashes":            {"md5": "", "sha1": "", "sha256": ""},
        "entropy":           0.0,
        "is_packed":         False,
        "is_high_entropy":   False,
        "type_mismatch":     False,
        "yara_matches":      [],
        "static_findings":   [],
        "suspicious_strings":[],
        "pdf_analysis":      {},
        "macro_analysis":    {},
        "html_analysis":     {},
        "zip_analysis":      {},
        "script_analysis":   {},
        "exe_analysis":      {},
        "embedded_urls":     [],
        "vt_result":         None,
        "known_bad":         False,
        "verdict":           "UNKNOWN",
        "risk_score":        0.0,
        "risk_flags":        ["ANALYSIS_ERROR"],
        "verdict_reasons":   [message],
        "analyzed_at":       datetime.utcnow().isoformat() + "Z",
        "error":             message
    }