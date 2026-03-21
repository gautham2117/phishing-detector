"""
PhishGuard - YARA + Suspicious Strings Diagnostic
Run from your project root:  python diagnose.py
"""
import os, sys

PDF_PATH   = r"phishguard_test_sample_v2.pdf"   # adjust if needed
RULES_PATH = "backend/yara_rules/phishing_html.yar"   # adjust if needed

SUSPICIOUS_PATTERNS = [
    "powershell", "cmd.exe", "mshta", "certutil", "regsvr32",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "WScript.Shell", "ADODB.Stream", "eval(unescape",
    "ExecutionPolicy Bypass", "EncodedCommand",
    "net user", "net localgroup", "TVqQAAM",
]

print("=" * 60)
print("1. PDF STRING CHECK")
print("=" * 60)
if not os.path.exists(PDF_PATH):
    print(f"  [!] PDF not found at: {PDF_PATH}")
    print("      Place phishguard_test_sample.pdf in the same folder.")
else:
    with open(PDF_PATH, "rb") as f:
        raw = f.read()
    content = raw.decode("latin-1", errors="ignore")
    for pat in SUSPICIOUS_PATTERNS:
        found = pat.lower() in content.lower()
        print(f"  {'[+]' if found else '[ ]'} {pat}")

print()
print("=" * 60)
print("2. YARA RULES CHECK")
print("=" * 60)
try:
    import yara
    print("  [+] yara-python installed")
    if not os.path.exists(RULES_PATH):
        print(f"  [!] Rules file not found at: {RULES_PATH}")
        print("      Adjust RULES_PATH at the top of this script.")
    else:
        rules = yara.compile(RULES_PATH)
        print(f"  [+] Rules compiled OK from {RULES_PATH}")
        if os.path.exists(PDF_PATH):
            with open(PDF_PATH, "rb") as f:
                data = f.read()
            matches = rules.match(data=data)
            if matches:
                print(f"  [+] YARA matched {len(matches)} rule(s):")
                for m in matches:
                    print(f"       - {m.rule}")
            else:
                print("  [!] YARA matched 0 rules — check your .yar rule content")
except ImportError:
    print("  [!] yara-python not installed: pip install yara-python")

print()
print("=" * 60)
print("3. DONE — paste output to Claude for diagnosis")
print("=" * 60)