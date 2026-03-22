# backend/modules/file_analyzer.py
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
#
# PDF DECOMPRESSION FIX (latest):
#  11. _extract_pdf_raw_text() — decompresses all FlateDecode (zlib) streams
#      before string scanning and YARA scanning. Without this, ReportLab and
#      most real-world PDFs store content as compressed binary, so patterns
#      like "powershell" or "cmd.exe" are invisible to raw-byte scanners.
#      _run_yara_scan() and _extract_suspicious_strings() both now accept a
#      file_type argument and automatically decompress PDF streams first.
#
# CAPA INTEGRATION (this version):
#  12. _run_capa_analysis() — behavioral capability detection using Mandiant
#      CAPA. Maps capabilities to MITRE ATT&CK tactics and MBC objectives.
#      Only runs on PE (EXE/DLL) and ELF binaries. Requires flare-capa and
#      backend/capa_rules to be present; degrades gracefully if either is
#      missing. Adds capa_analysis to the result dict and feeds into
#      _compute_verdict() for risk scoring.

import os
import re
import math
import json
import zlib
import hashlib
import logging
import zipfile
import tempfile
import subprocess
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
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
    logger.info("oletools available — VBA source extraction enabled")
except ImportError:
    OLETOOLS_AVAILABLE = False
    logger.warning(
        "oletools not installed — VBA source preview disabled. "
        "Run: pip install oletools"
    )
 

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False
    logger.warning("pdfminer.six not installed — PDF text extraction disabled")

# ── CAPA optional import ──────────────────────────────────────────────────────
try:
    import capa.main  # noqa: F401 — imported for availability check only
    CAPA_AVAILABLE = True
    logger.info("CAPA available — behavioral capability detection enabled")
except ImportError:
    CAPA_AVAILABLE = False
    logger.warning(
        "flare-capa not installed — CAPA detection disabled. "
        "Run: pip install flare-capa && "
        "git clone https://github.com/mandiant/capa-rules backend/capa_rules"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_module_dir    = os.path.dirname(os.path.abspath(__file__))
_backend_dir   = os.path.dirname(_module_dir)
YARA_RULES_DIR = os.path.join(_backend_dir, "yara_rules")
CAPA_RULES_PATH = os.path.join(_backend_dir, "capa_rules")

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
    # Extra patterns useful for PDF payloads
    b'mshta', b'certutil', b'regsvr32',
    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
    b'ADODB.Stream', b'unescape', b'launchURL',
]

_VBA_SUSPICIOUS_KEYWORDS = [
    "Shell", "CreateObject", "AutoOpen", "URLDownloadToFile",
    "WScript", "PowerShell", "cmd.exe", "reg add", "net user",
    "Base64", "EncodedCommand", "Document_Open", "Auto_Open",
    "Workbook_Open", "GetObject", "environ", "Chr(", "Asc(",
    "CallByName", "Application.Run", "MacroSecurity",
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

# CAPA: file types that are eligible for behavioral analysis
_CAPA_ELIGIBLE_TYPES = frozenset({"exe", "elf", "dll"})

# CAPA: namespace prefix → severity label
_CAPA_SEVERITY_MAP = {
    "ransomware":         "CRITICAL",
    "command-and-control":"CRITICAL",
    "exfiltration":       "CRITICAL",
    "credential-access":  "CRITICAL",
    "spyware":            "CRITICAL",
    "anti-analysis":      "HIGH",
    "defense-evasion":    "HIGH",
    "execution":          "HIGH",
    "persistence":        "HIGH",
    "privilege-escalation":"HIGH",
    "lateral-movement":   "HIGH",
    "impact":             "HIGH",
    "collection":         "MEDIUM",
    "data-manipulation":  "MEDIUM",
    "discovery":          "MEDIUM",
}

# CAPA: namespace prefix → risk score contribution (total capped at 35)
_CAPA_SCORE_MAP = {
    "anti-analysis":       25.0,
    "collection":          20.0,
    "command-and-control": 30.0,
    "credential-access":   28.0,
    "data-manipulation":   20.0,
    "defense-evasion":     25.0,
    "discovery":           10.0,
    "execution":           22.0,
    "exfiltration":        28.0,
    "impact":              30.0,
    "lateral-movement":    25.0,
    "persistence":         22.0,
    "privilege-escalation":28.0,
    "ransomware":          35.0,
    "spyware":             28.0,
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
# PDF stream decompressor  ← Fix #11
# ─────────────────────────────────────────────────────────────────────────────

def _extract_pdf_raw_text(data: bytes) -> bytes:
    """
    Decompress all FlateDecode (zlib) content streams inside a PDF so that
    string scanners and YARA rules can find plaintext patterns that were
    compressed by the PDF writer (e.g. ReportLab always uses zlib by default).
    """
    stream_re = re.compile(rb'stream\r?\n(.*?)\r?\nendstream', re.DOTALL)
    extra = bytearray()

    for m in stream_re.finditer(data):
        blob = m.group(1)
        try:
            extra += zlib.decompress(blob)
        except Exception:
            extra += blob

    return bytes(data) + bytes(extra)


# ─────────────────────────────────────────────────────────────────────────────
# CAPA behavioral analysis  ← NEW (Fix #12)
# ─────────────────────────────────────────────────────────────────────────────

def _run_capa_analysis(file_bytes: bytes, filename: str, file_type: str) -> dict:
    """
    Run Mandiant CAPA behavioral capability detection on the file.

    CAPA maps binary capabilities to MITRE ATT&CK tactics and the Malware
    Behavior Catalog (MBC). Unlike YARA (byte signatures), CAPA identifies
    WHAT a binary can DO — e.g. "receive data on TCP socket", "persist via
    registry run key", "encrypt data using AES".

    Supported file types: PE (exe/dll) and ELF binaries only.
    Requires: pip install flare-capa
              git clone https://github.com/mandiant/capa-rules backend/capa_rules

    Returns a dict with keys:
        available         bool   — False if CAPA unavailable or unsupported type
        capabilities      list   — up to 50 capability dicts, CRITICAL-first
        attack_tactics    list   — sorted unique ATT&CK tactic strings
        mbc_objectives    list   — sorted unique MBC objective strings
        namespace_summary dict   — namespace → count mapping
        highest_severity  str    — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
        risk_contribution float  — score contribution (0–35)
        error             str|None
    """
    _empty = {
        "available":        False,
        "capabilities":     [],
        "attack_tactics":   [],
        "mbc_objectives":   [],
        "namespace_summary":{},
        "highest_severity": "NONE",
        "risk_contribution":0.0,
        "error":            None,
    }

    # ── Guard: only PE/ELF binaries ──────────────────────────────────────────
    if file_type not in _CAPA_ELIGIBLE_TYPES:
        result = dict(_empty)
        result["error"] = (
            f"CAPA only analyses PE (EXE/DLL) and ELF binaries. "
            f"This file was identified as '{file_type}'. "
            f"CAPA is automatically applied to executable file uploads."
        )
        return result

    # ── Guard: CAPA Python package ────────────────────────────────────────────
    if not CAPA_AVAILABLE:
        result = dict(_empty)
        result["error"] = (
            "flare-capa is not installed. "
            "Run: pip install flare-capa && "
            "git clone https://github.com/mandiant/capa-rules backend/capa_rules"
        )
        return result

    # ── Guard: rules directory ────────────────────────────────────────────────
    if not os.path.isdir(CAPA_RULES_PATH):
        result = dict(_empty)
        result["error"] = (
            f"CAPA rules directory not found at: {CAPA_RULES_PATH}. "
            "Run: git clone https://github.com/mandiant/capa-rules backend/capa_rules"
        )
        return result

    # ── Write to temp file, run CAPA, delete in finally ──────────────────────
    tmp_path = None
    try:
        suffix = ".exe" if file_type in ("exe", "dll") else ".elf"
        with tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, prefix="phishguard_capa_"
        ) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        # Run CAPA as a subprocess: capa --format json -q -r <rules> <file>
        proc = subprocess.run(
            [
                "capa",
                "--format", "json",
                "-q",
                "-r", CAPA_RULES_PATH,
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute hard limit
        )

        raw_output = proc.stdout.strip()
        if not raw_output:
            # CAPA may write errors to stderr on unsupported files
            err_msg = proc.stderr.strip()[:300] if proc.stderr else "No output from CAPA."
            result = dict(_empty)
            result["error"] = f"CAPA produced no output: {err_msg}"
            return result

        capa_json = json.loads(raw_output)

    except subprocess.TimeoutExpired:
        result = dict(_empty)
        result["error"] = "CAPA analysis timed out (>120s)."
        return result
    except json.JSONDecodeError as je:
        result = dict(_empty)
        result["error"] = f"Failed to parse CAPA JSON output: {je}"
        return result
    except FileNotFoundError:
        # 'capa' binary not on PATH even though the Python package is installed
        result = dict(_empty)
        result["error"] = (
            "CAPA binary not found on PATH. "
            "Ensure flare-capa is installed in the active virtualenv: "
            "pip install flare-capa"
        )
        return result
    except Exception as e:
        result = dict(_empty)
        result["error"] = f"CAPA execution error: {str(e)[:200]}"
        return result
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    # ── Parse CAPA JSON output ────────────────────────────────────────────────
    capabilities     = []
    attack_tactics   = set()
    mbc_objectives   = set()
    namespace_counts = {}
    seen_namespaces_for_score = set()
    risk_contribution = 0.0

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    try:
        rules_data = capa_json.get("rules", {})
        for rule_name, rule_info in rules_data.items():
            meta      = rule_info.get("meta", {})
            namespace = meta.get("namespace", "other") or "other"

            # Determine severity from namespace prefix
            severity = "LOW"
            for ns_key, sev in _CAPA_SEVERITY_MAP.items():
                if namespace.lower().startswith(ns_key):
                    severity = sev
                    break

            # Extract ATT&CK mappings
            attack_info   = meta.get("attack", []) or []
            tactic_list   = []
            technique_list = []
            for entry in attack_info:
                tactic = entry.get("tactic", "")
                tech   = entry.get("technique", "")
                sub    = entry.get("subtechnique", "")
                if tactic:
                    attack_tactics.add(tactic)
                    tactic_list.append(tactic)
                if tech:
                    label = f"{tech} ({sub})" if sub else tech
                    technique_list.append(label)

            # Extract MBC mappings
            mbc_info = meta.get("mbc", []) or []
            mbc_list = []
            for entry in mbc_info:
                obj  = entry.get("objective", "")
                beh  = entry.get("behavior",  "")
                if obj:
                    mbc_objectives.add(obj)
                    label = f"{obj}: {beh}" if beh else obj
                    mbc_list.append(label)

            # Count namespaces
            ns_root = namespace.split("/")[0].lower()
            namespace_counts[ns_root] = namespace_counts.get(ns_root, 0) + 1

            # Accumulate risk score — each unique namespace prefix contributes once
            if ns_root not in seen_namespaces_for_score:
                seen_namespaces_for_score.add(ns_root)
                contrib = _CAPA_SCORE_MAP.get(ns_root, 5.0)
                risk_contribution = min(risk_contribution + contrib, 35.0)

            capabilities.append({
                "name":       rule_name,
                "namespace":  namespace,
                "severity":   severity,
                "attack_tactics":   tactic_list,
                "attack_techniques":technique_list,
                "mbc":        mbc_list,
                "scope":      meta.get("scope", "function"),
            })

    except Exception as parse_err:
        logger.warning("CAPA JSON parse error: %s", parse_err)
        result = dict(_empty)
        result["error"] = f"CAPA output parse error: {str(parse_err)[:200]}"
        return result

    # ── Sort capabilities: CRITICAL → HIGH → MEDIUM → LOW ────────────────────
    capabilities.sort(key=lambda c: severity_order.get(c["severity"], 3))

    # ── Determine highest severity ────────────────────────────────────────────
    highest_severity = "NONE"
    if capabilities:
        highest_severity = capabilities[0]["severity"]

    return {
        "available":         True,
        "capabilities":      capabilities[:50],
        "attack_tactics":    sorted(attack_tactics),
        "mbc_objectives":    sorted(mbc_objectives),
        "namespace_summary": namespace_counts,
        "highest_severity":  highest_severity,
        "risk_contribution": round(risk_contribution, 2),
        "error":             None,
    }


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

    Returns a flat result dict. See inline documentation for all keys.
    New key in this version: capa_analysis (dict).
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
    yara_matches = _run_yara_scan(file_bytes, filename, file_type)

    # Step 5 — Suspicious strings
    static_findings = _extract_suspicious_strings(file_bytes, file_type)

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

    # Step 6g — CAPA behavioral analysis (PE/ELF only)
    capa_analysis = _run_capa_analysis(file_bytes, filename, file_type)

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
        capa_analysis   = capa_analysis,  # ← NEW
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
        "type_mismatch":      type_mismatch,
        "yara_matches":       yara_matches,
        "static_findings":    static_findings,
        "suspicious_strings": [f["string"] for f in static_findings],
        "pdf_analysis":       pdf_analysis,
        "macro_analysis":     macro_analysis,
        "html_analysis":      html_analysis,
        "zip_analysis":       zip_analysis,
        "script_analysis":    script_analysis,
        "exe_analysis":       exe_analysis,
        "capa_analysis":      capa_analysis,   # ← NEW
        "embedded_urls":      embedded_urls,
        "vt_result":          vt_result,
        "known_bad":          known_bad,
        "verdict":            verdict,
        "risk_score":         risk_score,
        "risk_flags":         risk_flags,
        "verdict_reasons":    verdict_reasons,
        "email_id":           email_id,
        "analyzed_at":        datetime.utcnow().isoformat() + "Z"
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
# Step 2: File type detection + mismatch check
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
        expected_magic = EXPECTED_MAGIC.get(ext)
        type_mismatch  = bool(
            expected_magic and
            magic_type != expected_magic and
            magic_type not in ("zip",)
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

def _run_yara_scan(data: bytes, filename: str, file_type: str = "") -> list:
    rules = _get_yara_rules()
    if rules is None:
        return []

    scan_data = _extract_pdf_raw_text(data) if file_type == "pdf" else data

    matches = []
    try:
        for match in rules.match(data=scan_data):
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

def _extract_suspicious_strings(data: bytes, file_type: str = "") -> list:
    scan_data  = _extract_pdf_raw_text(data) if file_type == "pdf" else data
    data_lower = scan_data.lower()

    findings = []
    for pattern in SUSPICIOUS_STRINGS:
        pat_lower = pattern.lower()
        count     = data_lower.count(pat_lower)
        if count > 0:
            idx     = data_lower.find(pat_lower)
            start   = max(0, idx - 20)
            end     = min(len(scan_data), idx + len(pattern) + 20)
            context = scan_data[start:end].decode("utf-8", errors="replace")
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

    pdf_text = _extract_pdf_raw_text(data).decode("latin-1", errors="replace")

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

    decompressed = _extract_pdf_raw_text(data)
    url_pattern  = re.compile(rb'https?://[^\s\x00-\x1f\x7f-\xff<>"]{5,150}', re.IGNORECASE)
    urls = list({u.decode("utf-8", errors="replace") for u in url_pattern.findall(decompressed)})
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
# Step 6b: ZIP / Office (DOCX/XLSX/PPTX)
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_zip_office(data: bytes, filename: str) -> dict:
    zip_info = {
        "file_count":            0,
        "file_list":             [],
        "nested_executables":    [],
        "external_rels":         [],
        "is_password_protected": False,
        "zip_findings":          [],
        "embedded_urls":         [],
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

        dangerous_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
        structured = []
        for name in file_list[:50]:
            ext    = os.path.splitext(name)[1].lower()
            is_sus = ext in dangerous_exts
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
    """
    Analyse a legacy OLE/CFB Office file (.doc, .xls, .ppt etc.)
 
    Phase 6 addition:
      - If oletools is installed, attempts to extract VBA source code using
        VBA_Parser. Extracts up to 3000 chars of raw source, sanitises
        non-printable characters, and scans for a set of suspicious keywords.
      - vba_source_preview: str   — sanitised VBA source (max 3000 chars)
      - suspicious_vba_keywords: list[str] — keywords found in source
 
    Returns dict with keys:
        has_macros, has_vba_project, vba_streams, macro_keywords,
        ole_streams, macro_findings,
        vba_source_preview, suspicious_vba_keywords   ← NEW
    """
    findings = {
        "has_macros":              False,
        "has_vba_project":         False,
        "vba_streams":             [],
        "macro_keywords":          [],
        "ole_streams":             [],
        "macro_findings":          [],
        "vba_source_preview":      "",        # ← NEW
        "suspicious_vba_keywords": [],        # ← NEW
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
            parts = stream_path.split("/")
            if ole.exists(parts):
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
 
    # ── Phase 6: VBA source extraction via oletools ────────────────────────
    if OLETOOLS_AVAILABLE:
        try:
            import io as _io
            vba_parser = VBA_Parser(filename, data=data)
 
            if vba_parser.detect_vba_macros():
                findings["has_macros"]      = True
                findings["has_vba_project"] = True
 
                # Collect raw VBA source from all modules
                source_parts = []
                for (vba_filename, vba_stream, vba_type, vba_code) in \
                        vba_parser.extract_macros():
                    if vba_code and isinstance(vba_code, str):
                        header = f"' ── Module: {vba_filename} ({vba_type}) ──\n"
                        source_parts.append(header + vba_code.strip())
 
                if source_parts:
                    raw_source = "\n\n".join(source_parts)
 
                    # Sanitise: remove non-printable chars except newline/tab
                    sanitised = re.sub(
                        r'[^\x09\x0a\x0d\x20-\x7e]', '.', raw_source
                    )
 
                    # Cap at 3000 characters
                    preview = sanitised[:3000]
                    if len(sanitised) > 3000:
                        preview += "\n\n[... truncated — showing first 3000 chars ...]"
 
                    findings["vba_source_preview"] = preview
 
                    # Scan source for suspicious keywords
                    source_lower = raw_source.lower()
                    found_kws = []
                    for kw in _VBA_SUSPICIOUS_KEYWORDS:
                        if kw.lower() in source_lower and kw not in found_kws:
                            found_kws.append(kw)
                    findings["suspicious_vba_keywords"] = found_kws
 
                    if found_kws:
                        findings["macro_findings"].append(
                            f"Suspicious VBA keywords in source: {', '.join(found_kws[:5])}"
                        )
 
            vba_parser.close()
 
        except Exception as vba_err:
            logger.debug("oletools VBA extraction failed for %s: %s", filename, vba_err)
            findings["vba_source_note"] = f"VBA source extraction failed: {str(vba_err)[:100]}"
 
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
        "is_pe":                  False,
        "is_elf":                 False,
        "imported_strings":       [],
        "has_upx":                False,
        "has_suspicious_imports": False,
        "exe_findings":           [],
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
# Step 7: VirusTotal hash lookup
# ─────────────────────────────────────────────────────────────────────────────

def _vt_lookup(sha256: str) -> Optional[dict]:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
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
# Step 8: Aggregate embedded URLs from all analysis types
# ─────────────────────────────────────────────────────────────────────────────

def _collect_urls(pdf_analysis: dict, html_analysis: dict, zip_analysis: dict) -> list:
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
# Step 9: Verdict computation  ← UPDATED: accepts capa_analysis
# ─────────────────────────────────────────────────────────────────────────────

def _compute_verdict(
    yara_matches, static_findings,
    pdf_analysis, macro_analysis, html_analysis,
    zip_analysis, script_analysis, exe_analysis,
    entropy, is_packed, file_type,
    type_mismatch=False, known_bad=False,
    capa_analysis=None,         # ← NEW parameter
) -> tuple:
    """
    Returns (verdict, risk_score, risk_flags, verdict_reasons).
    Verdict is uppercase — "CLEAN" / "SUSPICIOUS" / "MALICIOUS".
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
    elif file_type in ("docx", "xlsx", "pptx", "ole", "doc", "xls"):
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

    # ── CAPA behavioral analysis contribution ─────────────────────────────────
    if capa_analysis and capa_analysis.get("available") and capa_analysis.get("capabilities"):
        cap_count  = len(capa_analysis["capabilities"])
        risk_contrib = capa_analysis.get("risk_contribution", 0.0)
        highest_sev  = capa_analysis.get("highest_severity", "NONE")
        tactics      = capa_analysis.get("attack_tactics", [])

        # Add CAPA risk contribution to total score
        score += risk_contrib

        if highest_sev == "CRITICAL":
            top3_tactics = ", ".join(tactics[:3]) if tactics else "unknown"
            flags.append(f"CAPA_CRITICAL: {cap_count} capabilities detected")
            reasons.append(
                f"CAPA detected {cap_count} behavioral capability(-ies) at CRITICAL severity. "
                f"Top ATT&CK tactics: {top3_tactics}."
            )
        elif highest_sev == "HIGH":
            flags.append(f"CAPA_HIGH: {cap_count} capabilities detected")
            reasons.append(
                f"CAPA detected {cap_count} behavioral capability(-ies) at HIGH severity."
            )
        elif cap_count > 0:
            flags.append(f"CAPA_FINDINGS: {cap_count} capabilities detected")
            reasons.append(
                f"CAPA detected {cap_count} behavioral indicator(s) in this binary."
            )

    # ── Final verdict ─────────────────────────────────────────────────────────
    risk_score = round(min(score, 100.0), 2)

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
        "filename":           filename,
        "file_type":          "unknown",
        "file_category":      "unknown",
        "file_size":          0,
        "hashes":             {"md5": "", "sha1": "", "sha256": ""},
        "entropy":            0.0,
        "is_packed":          False,
        "is_high_entropy":    False,
        "type_mismatch":      False,
        "yara_matches":       [],
        "static_findings":    [],
        "suspicious_strings": [],
        "pdf_analysis":       {},
        "macro_analysis":     {},
        "html_analysis":      {},
        "zip_analysis":       {},
        "script_analysis":    {},
        "exe_analysis":       {},
        "capa_analysis":      {          # ← NEW in error fallback
            "available":         False,
            "capabilities":      [],
            "attack_tactics":    [],
            "mbc_objectives":    [],
            "namespace_summary": {},
            "highest_severity":  "NONE",
            "risk_contribution": 0.0,
            "error":             message,
        },
        "embedded_urls":      [],
        "vt_result":          None,
        "known_bad":          False,
        "verdict":            "UNKNOWN",
        "risk_score":         0.0,
        "risk_flags":         ["ANALYSIS_ERROR"],
        "verdict_reasons":    [message],
        "analyzed_at":        datetime.utcnow().isoformat() + "Z",
        "error":              message
    }