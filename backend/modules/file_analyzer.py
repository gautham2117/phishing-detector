# file_analyzer.py
# File & Attachment Analysis Module.
#
# Analyzes uploaded files for malware indicators using:
#   1. Hash computation (MD5, SHA-1, SHA-256)
#   2. YARA rule scanning (custom + community rules)
#   3. Shannon entropy analysis (detects packed/encrypted executables)
#   4. Static analysis (extract strings, macros, embedded scripts)
#   5. File-type-specific analysis:
#      - PDF:  embedded JavaScript, /OpenAction, /Launch actions
#      - DOCX/XLSX: VBA macros, external relationships
#      - HTML/JS: credential forms, hidden iframes, obfuscated JS
#      - EXE:  PE header analysis, section entropy
#      - ZIP:  list contents, flag nested executables
#
# Returns a structured FileAnalysisResult dict with a final verdict:
#   Clean / Suspicious / Malicious

import os
import re
import math
import zlib
import json
import hashlib
import logging
import zipfile
import tempfile
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Optional imports with graceful fallback ──────────────────────────────────
# Each tool is wrapped in try/except so the module still works if a
# dependency is not installed. The result will note what was skipped.

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
    from pdfminer.pdfpage import PDFPage
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False
    logger.warning("pdfminer.six not installed — PDF analysis limited")


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Path to YARA rules directory (relative to this file)
_module_dir  = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_module_dir)
YARA_RULES_DIR = os.path.join(_backend_dir, "yara_rules")

# Entropy thresholds
# Normal text files: ~3.5–4.5 bits/byte
# Compressed/packed: > 7.0 bits/byte
# Encrypted:         ~7.9–8.0 bits/byte
ENTROPY_SUSPICIOUS = 6.5
ENTROPY_PACKED     = 7.2

# Maximum file size we will analyze (20 MB)
MAX_FILE_SIZE = 20 * 1024 * 1024

# File type signatures (magic bytes)
FILE_SIGNATURES = {
    b'\x4d\x5a':             'exe',        # PE executable (MZ header)
    b'\x7f\x45\x4c\x46':    'elf',        # ELF binary
    b'\x25\x50\x44\x46':    'pdf',        # PDF (%PDF)
    b'\x50\x4b\x03\x04':    'zip',        # ZIP archive (also DOCX/XLSX/PPTX)
    b'\xd0\xcf\x11\xe0':    'ole',        # OLE2 compound document (old Office)
    b'\x89\x50\x4e\x47':    'png',        # PNG image
    b'\xff\xd8\xff':         'jpg',        # JPEG image
    b'\x47\x49\x46\x38':    'gif',        # GIF image
    b'\x3c\x68\x74\x6d\x6c':'html',       # <html
    b'\x3c\x21\x44\x4f\x43':'html',       # <!DOC
    b'\x3c\x73\x63\x72\x69':'js',         # <scri (JS starting with <script)
}

# Suspicious strings to look for in any file
SUSPICIOUS_STRINGS = [
    b'powershell', b'cmd.exe', b'wscript', b'cscript',
    b'shell32', b'CreateObject', b'WScript.Shell',
    b'eval(', b'exec(', b'base64_decode', b'base64_encode',
    b'wget ', b'curl ', b'chmod +x', b'/tmp/', b'%TEMP%',
    b'HKEY_CURRENT_USER', b'reg add', b'net user',
    b'bypass', b'ExecutionPolicy', b'EncodedCommand',
    b'FromBase64String', b'invoke-expression', b'IEX(',
]

# Supported file extensions and their category
EXTENSION_MAP = {
    '.pdf':  'document', '.docx': 'document', '.doc':  'document',
    '.xlsx': 'document', '.xls':  'document', '.pptx': 'document',
    '.ppt':  'document', '.rtf':  'document', '.odt':  'document',
    '.exe':  'executable', '.dll': 'executable', '.bat': 'executable',
    '.cmd':  'executable', '.vbs': 'executable', '.ps1': 'executable',
    '.sh':   'executable', '.elf': 'executable',
    '.zip':  'archive',  '.rar':  'archive',   '.7z':  'archive',
    '.tar':  'archive',  '.gz':   'archive',
    '.html': 'html',     '.htm':  'html',
    '.js':   'script',   '.ts':   'script',    '.py':  'script',
    '.php':  'script',   '.rb':   'script',
    '.png':  'image',    '.jpg':  'image',     '.jpeg':'image',
    '.gif':  'image',    '.bmp':  'image',     '.svg': 'image',
}


# ─────────────────────────────────────────────────────────────────────────────
# YARA rule compiler (compiled once at module load)
# ─────────────────────────────────────────────────────────────────────────────

_compiled_rules = None

def _get_yara_rules():
    """
    Compile all YARA rules from the yara_rules/ directory.
    Compiled rules are cached in _compiled_rules for performance.
    Returns None if YARA is not available or rules fail to compile.
    """
    global _compiled_rules

    if _compiled_rules is not None:
        return _compiled_rules

    if not YARA_AVAILABLE:
        return None

    rule_files = {}
    try:
        for filename in os.listdir(YARA_RULES_DIR):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                namespace = filename.replace(".yar", "").replace(".yara", "")
                full_path = os.path.join(YARA_RULES_DIR, filename)
                rule_files[namespace] = full_path

        if not rule_files:
            logger.warning(f"No YARA rule files found in {YARA_RULES_DIR}")
            return None

        _compiled_rules = yara.compile(filepaths=rule_files)
        logger.info(f"YARA rules compiled from: {list(rule_files.keys())}")
        return _compiled_rules

    except Exception as e:
        logger.error(f"YARA rule compilation failed: {e}")
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

    Args:
        file_bytes: Raw file content as bytes.
        filename:   Original filename (used to determine file type).
        email_id:   Optional link to parent EmailScan record.

    Returns:
        FileAnalysisResult dict containing:
          - hashes (md5, sha1, sha256)
          - file_type, file_category, file_size
          - entropy + is_packed flag
          - yara_matches list
          - static_findings list
          - type_specific_findings dict
          - verdict: Clean / Suspicious / Malicious
          - risk_score: 0–100
          - risk_flags: list of flag strings
    """

    # ── Size check ────────────────────────────────────────────────────────
    if len(file_bytes) > MAX_FILE_SIZE:
        return _error_result(
            filename,
            f"File too large ({len(file_bytes)} bytes, max {MAX_FILE_SIZE})"
        )

    if len(file_bytes) == 0:
        return _error_result(filename, "File is empty")

    # ── Step 1: Hash computation ───────────────────────────────────────────
    hashes = _compute_hashes(file_bytes)

    # ── Step 2: File type detection ────────────────────────────────────────
    file_type, file_category = _detect_file_type(file_bytes, filename)

    # ── Step 3: Entropy analysis ───────────────────────────────────────────
    entropy    = _compute_entropy(file_bytes)
    is_packed  = entropy >= ENTROPY_PACKED
    is_high_entropy = entropy >= ENTROPY_SUSPICIOUS

    # ── Step 4: YARA scanning ─────────────────────────────────────────────
    yara_matches = _run_yara_scan(file_bytes, filename)

    # ── Step 5: Generic string extraction ─────────────────────────────────
    static_findings = _extract_suspicious_strings(file_bytes)

    # ── Step 6: Type-specific analysis ────────────────────────────────────
    type_findings = {}

    if file_type == "pdf":
        type_findings = _analyze_pdf(file_bytes, filename)
    elif file_type in ("zip", "docx", "xlsx", "pptx"):
        type_findings = _analyze_zip_office(file_bytes, filename)
    elif file_type == "ole":
        type_findings = _analyze_ole(file_bytes, filename)
    elif file_type in ("html", "htm"):
        type_findings = _analyze_html(file_bytes, filename)
    elif file_type in ("js", "script"):
        type_findings = _analyze_script(file_bytes, filename)
    elif file_type in ("exe", "elf", "dll"):
        type_findings = _analyze_executable(file_bytes, filename)

    # ── Step 7: Verdict + risk scoring ────────────────────────────────────
    verdict, risk_score, risk_flags = _compute_verdict(
        yara_matches=yara_matches,
        static_findings=static_findings,
        type_findings=type_findings,
        entropy=entropy,
        is_packed=is_packed,
        file_type=file_type
    )

    return {
        "filename":           filename,
        "file_type":          file_type,
        "file_category":      file_category,
        "file_size":          len(file_bytes),
        "hashes":             hashes,
        "entropy":            round(entropy, 4),
        "is_packed":          is_packed,
        "is_high_entropy":    is_high_entropy,
        "yara_matches":       yara_matches,
        "static_findings":    static_findings,
        "type_findings":      type_findings,
        "verdict":            verdict,
        "risk_score":         risk_score,
        "risk_flags":         risk_flags,
        "email_id":           email_id,
        "analyzed_at":        datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Hash computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_hashes(data: bytes) -> dict:
    """
    Compute MD5, SHA-1, and SHA-256 hashes of the file.
    These can be checked against threat intelligence databases
    like VirusTotal, MalwareBazaar, or local blocklists.
    """
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: File type detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_file_type(data: bytes, filename: str) -> tuple:
    """
    Detect the true file type using magic bytes (not just the extension).
    Attackers often rename executables to .pdf or .jpg to bypass filters.

    Priority: magic bytes > file extension
    Returns: (file_type: str, file_category: str)
    """
    # Check magic bytes first
    for magic, ftype in FILE_SIGNATURES.items():
        if data[:len(magic)] == magic:
            # ZIP magic bytes cover DOCX/XLSX/PPTX (they are ZIP archives)
            if ftype == "zip":
                ext = os.path.splitext(filename)[1].lower()
                if ext in (".docx", ".docm"):
                    ftype = "docx"
                elif ext in (".xlsx", ".xlsm"):
                    ftype = "xlsx"
                elif ext in (".pptx", ".pptm"):
                    ftype = "pptx"
                # else stays as "zip"
            ext      = "." + ftype
            category = EXTENSION_MAP.get(ext, "unknown")
            return ftype, category

    # Fall back to extension
    ext      = os.path.splitext(filename)[1].lower()
    ftype    = ext.lstrip(".")
    category = EXTENSION_MAP.get(ext, "unknown")
    return ftype or "unknown", category


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Entropy analysis
# ─────────────────────────────────────────────────────────────────────────────

def _compute_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of file bytes.

    Interpretation:
      0–3.5: mostly text / low complexity
      3.5–6: normal binary / compiled code
      6–7.2: compressed or partially encrypted
      7.2+:  packed executable or fully encrypted (malware signal)

    We sample up to 65536 bytes for performance on large files.
    """
    if not data:
        return 0.0

    # Sample first 64KB for performance
    sample = data[:65536]

    # Count byte frequency
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
    """
    Scan file bytes against all compiled YARA rules.

    Returns a list of match dicts:
    [{"rule": str, "namespace": str, "tags": list, "meta": dict}]
    """
    rules = _get_yara_rules()
    if rules is None:
        return []

    matches = []
    try:
        yara_matches = rules.match(data=data)
        for match in yara_matches:
            matches.append({
                "rule":      match.rule,
                "namespace": match.namespace,
                "tags":      list(match.tags),
                "meta":      dict(match.meta),
                "severity":  match.meta.get("severity", "MEDIUM")
            })

    except Exception as e:
        logger.warning(f"YARA scan error for {filename}: {e}")

    return matches


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Generic suspicious string extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_suspicious_strings(data: bytes) -> list:
    """
    Scan raw file bytes for known suspicious string patterns.
    Works on any file type — no parsing required.

    Returns a list of finding dicts:
    [{"string": str, "count": int, "context": str}]
    """
    findings = []
    data_lower = data.lower()

    for pattern in SUSPICIOUS_STRINGS:
        count = data_lower.count(pattern.lower())
        if count > 0:
            # Find the first occurrence for context
            idx = data_lower.find(pattern.lower())
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
    """
    Analyze a PDF file for embedded threats.

    Checks:
      - /JavaScript or /JS actions (auto-execute on open)
      - /OpenAction or /AA (additional actions)
      - /Launch (launches external programs)
      - /EmbeddedFile (attachments inside PDF)
      - /URI (suspicious embedded links)
      - Embedded executable signatures
    """
    findings = {
        "has_javascript":    False,
        "has_openaction":    False,
        "has_launch":        False,
        "has_embedded_file": False,
        "embedded_urls":     [],
        "suspicious_actions":[],
        "text_sample":       ""
    }

    pdf_text = data.decode("latin-1", errors="replace")

    # Check for dangerous PDF actions
    dangerous_keywords = {
        "/JavaScript": "Embedded JavaScript — can execute code on PDF open",
        "/JS":         "Embedded JavaScript shorthand",
        "/OpenAction": "OpenAction — executes on document open",
        "/Launch":     "Launch action — can start external programs",
        "/AA":         "Additional Actions — trigger on various events",
        "/EmbeddedFile":"Embedded file inside PDF"
    }

    for keyword, description in dangerous_keywords.items():
        if keyword.lower() in pdf_text.lower():
            findings["suspicious_actions"].append({
                "keyword":     keyword,
                "description": description
            })

    findings["has_javascript"]    = any(
        k in ("/JavaScript", "/JS")
        for k in [a["keyword"] for a in findings["suspicious_actions"]]
    )
    findings["has_openaction"]    = "/OpenAction" in [
        a["keyword"] for a in findings["suspicious_actions"]
    ]
    findings["has_launch"]        = "/Launch" in [
        a["keyword"] for a in findings["suspicious_actions"]
    ]
    findings["has_embedded_file"] = "/EmbeddedFile" in [
        a["keyword"] for a in findings["suspicious_actions"]
    ]

    # Extract embedded URLs
    url_pattern = re.compile(
        rb'https?://[^\s\x00-\x1f\x7f-\xff<>"]{5,100}',
        re.IGNORECASE
    )
    urls = [u.decode("utf-8", errors="replace")
            for u in url_pattern.findall(data)]
    findings["embedded_urls"] = list(set(urls))[:20]

    # Try to extract readable text
    if PDFMINER_AVAILABLE:
        try:
            import io
            text = pdf_extract_text(io.BytesIO(data))
            findings["text_sample"] = (text or "")[:500]
        except Exception:
            pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6b: ZIP / Office (DOCX/XLSX/PPTX) analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_zip_office(data: bytes, filename: str) -> dict:
    """
    Analyze ZIP archives and Office Open XML files (DOCX/XLSX/PPTX).
    Office documents are ZIP archives — we open them and inspect contents.

    Checks:
      - Embedded VBA macros (vbaProject.bin)
      - External relationship URLs (data exfiltration)
      - Nested executables inside ZIP
      - Password-protected archives
    """
    findings = {
        "file_count":        0,
        "has_macros":        False,
        "has_vba_project":   False,
        "external_rels":     [],
        "nested_executables":[],
        "file_list":         [],
        "is_password_protected": False
    }

    try:
        import io
        zf = zipfile.ZipFile(io.BytesIO(data))
        file_list = zf.namelist()
        findings["file_count"] = len(file_list)
        findings["file_list"]  = file_list[:30]

        for name in file_list:
            name_lower = name.lower()

            # VBA macro file
            if "vbaproject.bin" in name_lower:
                findings["has_vba_project"] = True
                findings["has_macros"]      = True

            # Any .bas, .cls, .frm files (VBA modules)
            if any(name_lower.endswith(ext)
                   for ext in (".bas", ".cls", ".frm")):
                findings["has_macros"] = True

            # Check for nested executables
            if any(name_lower.endswith(ext)
                   for ext in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs")):
                findings["nested_executables"].append(name)

            # Check relationships files for external URLs
            if "relationships" in name_lower or name_lower.endswith(".rels"):
                try:
                    content = zf.read(name).decode("utf-8", errors="replace")
                    ext_urls = re.findall(
                        r'Target="(https?://[^"]{5,200})"',
                        content
                    )
                    findings["external_rels"].extend(ext_urls)
                except Exception:
                    pass

        zf.close()

    except zipfile.BadZipFile:
        findings["error"] = "File is not a valid ZIP/Office document"
    except RuntimeError as e:
        if "password" in str(e).lower() or "encrypted" in str(e).lower():
            findings["is_password_protected"] = True
        else:
            findings["error"] = str(e)
    except Exception as e:
        findings["error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6c: OLE (old Office .doc/.xls) analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_ole(data: bytes, filename: str) -> dict:
    """
    Analyze legacy OLE2 Office documents (.doc, .xls, .ppt).
    These use the OLE Compound File format and can contain VBA macros
    directly embedded in the file structure.
    """
    findings = {
        "has_macros":    False,
        "vba_streams":   [],
        "macro_keywords":[],
        "ole_streams":   []
    }

    if not OLEFILE_AVAILABLE:
        findings["note"] = "olefile not installed — OLE analysis skipped"
        return findings

    try:
        import io
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = ole.listdir()
        findings["ole_streams"] = ["/".join(s) for s in streams[:20]]

        # Look for VBA project stream
        vba_stream_names = [
            "Macros/VBA",
            "_VBA_PROJECT_CUR/VBA",
            "VBA"
        ]
        for stream_path in vba_stream_names:
            if ole.exists(stream_path.split("/")):
                findings["has_macros"]  = True
                findings["vba_streams"].append(stream_path)

        # Check all streams for macro keywords
        suspicious_macro_kw = [
            b"Shell", b"CreateObject", b"AutoOpen",
            b"Document_Open", b"Auto_Open", b"Workbook_Open"
        ]
        for entry in streams:
            try:
                stream_data = ole.openstream(entry).read()
                for kw in suspicious_macro_kw:
                    if kw.lower() in stream_data.lower():
                        kw_str = kw.decode("utf-8")
                        if kw_str not in findings["macro_keywords"]:
                            findings["macro_keywords"].append(kw_str)
                            findings["has_macros"] = True
            except Exception:
                continue

        ole.close()

    except Exception as e:
        findings["error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6d: HTML attachment analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_html(data: bytes, filename: str) -> dict:
    """
    Analyze HTML files for credential harvesting indicators.

    Phishing HTML attachments typically:
      - Contain login forms with password fields
      - Use JavaScript to POST credentials to an attacker's server
      - Embed hidden iframes for tracking or redirection
      - Use heavy obfuscation (base64, eval, fromCharCode)
      - Mimic legitimate brand login pages

    Returns a detailed breakdown of all suspicious HTML elements found.
    """
    findings = {
        "has_password_field":     False,
        "has_form_with_action":   False,
        "form_actions":           [],
        "has_hidden_iframe":      False,
        "iframe_sources":         [],
        "has_obfuscated_js":      False,
        "obfuscation_patterns":   [],
        "has_external_scripts":   False,
        "external_script_srcs":   [],
        "has_meta_redirect":      False,
        "meta_redirect_url":      "",
        "embedded_urls":          [],
        "brand_keywords_found":   [],
        "suspicious_elements":    []
    }

    html_text = data.decode("utf-8", errors="replace")

    if not BS4_AVAILABLE:
        # Fallback: regex-based checks
        findings["has_password_field"] = bool(
            re.search(r'type=["\']password["\']', html_text, re.IGNORECASE)
        )
        return findings

    try:
        soup = BeautifulSoup(html_text, "lxml")

        # ── Password fields ────────────────────────────────────────────────
        pwd_fields = soup.find_all("input", {"type": re.compile("password", re.I)})
        if pwd_fields:
            findings["has_password_field"] = True
            findings["suspicious_elements"].append(
                f"{len(pwd_fields)} password input field(s) detected"
            )

        # ── Form actions ───────────────────────────────────────────────────
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            if action:
                findings["has_form_with_action"] = True
                findings["form_actions"].append({
                    "action": action,
                    "method": method
                })
                # Flag forms posting to external URLs
                if action.startswith(("http://", "https://")) and method == "post":
                    findings["suspicious_elements"].append(
                        f"Form POSTs credentials to external URL: {action[:60]}"
                    )

        # ── Hidden iframes ─────────────────────────────────────────────────
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            style = iframe.get("style", "")
            width = iframe.get("width", "")
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
                findings["suspicious_elements"].append(
                    f"Hidden iframe detected (src: {src[:60] or 'empty'})"
                )

        # ── Obfuscated JavaScript ──────────────────────────────────────────
        obfusc_patterns = [
            (r'\beval\s*\(',        "eval() call"),
            (r'\batob\s*\(',        "Base64 decode (atob)"),
            (r'fromCharCode',       "fromCharCode encoding"),
            (r'unescape\s*\(',      "unescape() obfuscation"),
            (r'decodeURIComponent', "URL decoding"),
            (r'String\.fromChar',   "String.fromCharCode"),
        ]
        all_js = " ".join(
            script.get_text() for script in soup.find_all("script")
        )
        for pattern, desc in obfusc_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                findings["has_obfuscated_js"] = True
                findings["obfuscation_patterns"].append(desc)

        # ── External scripts ───────────────────────────────────────────────
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith(("http://", "https://")):
                findings["has_external_scripts"] = True
                findings["external_script_srcs"].append(src[:100])

        # ── Meta redirects ─────────────────────────────────────────────────
        for meta in soup.find_all("meta"):
            content = meta.get("content", "")
            if "url=" in content.lower():
                url_match = re.search(r'url=([^\s;>"\']+)', content, re.I)
                if url_match:
                    findings["has_meta_redirect"] = True
                    findings["meta_redirect_url"] = url_match.group(1)

        # ── Brand keywords ─────────────────────────────────────────────────
        page_text = soup.get_text().lower()
        brand_kws = [
            "paypal", "google", "microsoft", "apple", "amazon",
            "netflix", "facebook", "instagram", "bank", "chase",
            "citibank", "wells fargo", "barclays", "hsbc"
        ]
        findings["brand_keywords_found"] = [
            kw for kw in brand_kws if kw in page_text
        ]

        # ── Collect all URLs ───────────────────────────────────────────────
        all_hrefs = [
            a.get("href", "") for a in soup.find_all("a", href=True)
            if a.get("href", "").startswith(("http://", "https://"))
        ]
        findings["embedded_urls"] = list(set(all_hrefs))[:20]

    except Exception as e:
        findings["parse_error"] = str(e)[:100]
        logger.warning(f"HTML analysis error for {filename}: {e}")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6e: Script analysis (JS, PS1, VBS, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_script(data: bytes, filename: str) -> dict:
    """
    Analyze script files (JavaScript, PowerShell, VBScript, Bash).
    Focuses on detecting download cradles, execution chains, and obfuscation.
    """
    findings = {
        "has_eval":          False,
        "has_download":      False,
        "has_exec":          False,
        "obfuscation_score": 0,
        "suspicious_calls":  []
    }

    try:
        text       = data.decode("utf-8", errors="replace")
        text_lower = text.lower()

        eval_patterns = ["eval(", "eval (", "execute(", "invoke-expression"]
        for p in eval_patterns:
            if p in text_lower:
                findings["has_eval"] = True
                findings["suspicious_calls"].append(f"eval/execute: {p}")
                findings["obfuscation_score"] += 2

        download_patterns = [
            "downloadstring", "downloadfile", "wget ", "curl ",
            "invoke-webrequest", "net.webclient", "xmlhttp"
        ]
        for p in download_patterns:
            if p in text_lower:
                findings["has_download"] = True
                findings["suspicious_calls"].append(f"download: {p}")
                findings["obfuscation_score"] += 2

        exec_patterns = [
            "wscript.shell", "shell32", "createobject",
            "start-process", "cmd.exe", "powershell"
        ]
        for p in exec_patterns:
            if p in text_lower:
                findings["has_exec"] = True
                findings["suspicious_calls"].append(f"exec: {p}")
                findings["obfuscation_score"] += 1

        # Obfuscation detection: high ratio of special chars
        special_ratio = sum(
            1 for c in text
            if not c.isalnum() and c not in (" ", "\n", "\t", ".", ",", ";", "(", ")")
        ) / max(len(text), 1)
        if special_ratio > 0.3:
            findings["obfuscation_score"] += 3
            findings["suspicious_calls"].append(
                f"High special character ratio: {special_ratio:.2f}"
            )

    except Exception as e:
        findings["error"] = str(e)[:100]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 6f: Executable analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_executable(data: bytes, filename: str) -> dict:
    """
    Analyze PE executables and ELF binaries.
    Focuses on high-level indicators without full disassembly.
    """
    findings = {
        "is_pe":            False,
        "is_elf":           False,
        "section_entropies":[],
        "imported_strings": [],
        "has_upx":          False,
        "has_suspicious_imports": False
    }

    # PE header check (MZ)
    if data[:2] == b'\x4d\x5a':
        findings["is_pe"] = True

    # ELF header check
    if data[:4] == b'\x7f\x45\x4c\x46':
        findings["is_elf"] = True

    # UPX packer detection
    if b'UPX' in data[:512] or b'UPX0' in data or b'UPX1' in data:
        findings["has_upx"] = True

    # Extract readable ASCII strings (length > 6)
    # This gives a quick view of what functions/APIs the executable uses
    printable = re.findall(rb'[ -~]{6,}', data[:32768])
    str_list  = [s.decode("ascii", errors="replace") for s in printable[:50]]
    findings["imported_strings"] = str_list

    # Check for suspicious Windows API imports
    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "LoadLibrary", "GetProcAddress",
        "InternetOpen", "URLDownloadToFile", "ShellExecute",
        "CreateProcess", "WinExec", "RegSetValue"
    ]
    found_apis = [api for api in suspicious_apis
                  if api.encode() in data[:65536]]
    if found_apis:
        findings["has_suspicious_imports"] = True
        findings["imported_strings"] = found_apis[:10]

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Verdict computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_verdict(
    yara_matches, static_findings, type_findings,
    entropy, is_packed, file_type
) -> tuple:
    """
    Aggregate all analysis signals into a verdict and risk score.

    Verdict thresholds:
      0–29:  Clean
      30–69: Suspicious
      70–100:Malicious

    Returns: (verdict: str, risk_score: float, risk_flags: list)
    """
    score = 0.0
    flags = []

    # ── YARA matches ───────────────────────────────────────────────────────
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 5}
    for match in yara_matches:
        sev    = match.get("severity", "MEDIUM").upper()
        weight = severity_weights.get(sev, 10)
        score += weight
        flags.append(f"YARA:{match['rule']} ({sev})")

    # ── Static string findings ─────────────────────────────────────────────
    if len(static_findings) >= 3:
        score += 10
        flags.append(f"SUSPICIOUS_STRINGS ({len(static_findings)} found)")
    elif len(static_findings) >= 1:
        score += 5

    # ── Entropy ───────────────────────────────────────────────────────────
    if is_packed:
        score += 20
        flags.append(f"PACKED_EXECUTABLE (entropy={entropy:.2f})")
    elif entropy >= ENTROPY_SUSPICIOUS:
        score += 10
        flags.append(f"HIGH_ENTROPY (entropy={entropy:.2f})")

    # ── Type-specific findings ─────────────────────────────────────────────
    if file_type == "pdf":
        if type_findings.get("has_javascript"):
            score += 15; flags.append("PDF_EMBEDDED_JAVASCRIPT")
        if type_findings.get("has_launch"):
            score += 20; flags.append("PDF_LAUNCH_ACTION")
        if type_findings.get("has_openaction"):
            score += 10; flags.append("PDF_OPENACTION")

    elif file_type in ("docx", "xlsx", "pptx", "ole"):
        if type_findings.get("has_macros"):
            score += 15; flags.append("OFFICE_MACRO_DETECTED")
        if type_findings.get("nested_executables"):
            score += 25; flags.append("EXECUTABLE_IN_OFFICE_DOC")
        if type_findings.get("external_rels"):
            score += 10; flags.append("EXTERNAL_RELATIONSHIP_URL")

    elif file_type in ("html", "htm"):
        if type_findings.get("has_password_field") and type_findings.get("has_form_with_action"):
            score += 20; flags.append("CREDENTIAL_HARVESTING_FORM")
        if type_findings.get("has_hidden_iframe"):
            score += 15; flags.append("HIDDEN_IFRAME")
        if type_findings.get("has_obfuscated_js"):
            score += 10; flags.append("OBFUSCATED_JAVASCRIPT")

    elif file_type in ("js", "script"):
        obs_score = type_findings.get("obfuscation_score", 0)
        if obs_score >= 4:
            score += 15; flags.append("HEAVILY_OBFUSCATED_SCRIPT")
        elif obs_score >= 2:
            score += 8;  flags.append("OBFUSCATED_SCRIPT")
        if type_findings.get("has_download") and type_findings.get("has_exec"):
            score += 20; flags.append("DOWNLOAD_AND_EXECUTE_PATTERN")

    elif file_type in ("exe", "elf", "dll"):
        if type_findings.get("has_upx"):
            score += 10; flags.append("UPX_PACKED_EXECUTABLE")
        if type_findings.get("has_suspicious_imports"):
            score += 15; flags.append("SUSPICIOUS_API_IMPORTS")

    # ── Cap and determine verdict ─────────────────────────────────────────
    risk_score = round(min(score, 100.0), 2)

    if risk_score >= 70:
        verdict = "Malicious"
    elif risk_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return verdict, risk_score, flags


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _error_result(filename: str, message: str) -> dict:
    """Return a minimal error result when analysis cannot proceed."""
    return {
        "filename":        filename,
        "file_type":       "unknown",
        "file_category":   "unknown",
        "file_size":       0,
        "hashes":          {"md5": "", "sha1": "", "sha256": ""},
        "entropy":         0.0,
        "is_packed":       False,
        "is_high_entropy": False,
        "yara_matches":    [],
        "static_findings": [],
        "type_findings":   {},
        "verdict":         "Unknown",
        "risk_score":      0.0,
        "risk_flags":      ["ANALYSIS_ERROR"],
        "analyzed_at":     datetime.utcnow().isoformat() + "Z",
        "error":           message
    }