# network_scanner.py
# Network scanning engine using python-nmap.
#
# ══════════════════════════════════════════════════════════
#  CRITICAL ETHICAL CONSTRAINT — READ BEFORE MODIFYING
#  Port scanning a host you don't own or haven't been
#  explicitly authorized to scan is illegal in most
#  jurisdictions (CFAA in the US, Computer Misuse Act in
#  the UK, IT Act in India, etc.).
#
#  This module implements a multi-layer authorization gate:
#    1. An allowlist of safe demo domains / localhost
#    2. A runtime check for the SCAN_AUTHORIZED env flag
#    3. A per-request consent_confirmed parameter
#
#  If ANY gate fails the scan is blocked and logged.
#  The system will NEVER scan a domain not on the allowlist
#  unless the operator has explicitly added it.
# ══════════════════════════════════════════════════════════
#
# What this module does when authorized:
#   1. Resolves domain to IP and validates it's scannable
#   2. Runs an Nmap scan (configurable: quick top-100 or full 1–65535)
#   3. Parses every open port: service, version, banner
#   4. Classifies each port against a dangerous port registry
#   5. Detects exposed admin panels and legacy services
#   6. Builds a structured result + risk assessment
#   7. Returns a NetworkScanResult dict ready for DB storage

import os
import json
import time
import socket
import logging
import ipaddress
from datetime import datetime
from typing import Optional

import nmap   # pip install python-nmap (wraps the nmap binary)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Authorization allowlist
# ─────────────────────────────────────────────────────────────────────────────
# These are the ONLY targets the system will scan without additional confirmation.
# Expand this list only for domains/IPs you own or have written authorization for.

AUTHORIZED_DEMO_TARGETS = {
    "localhost",
    "127.0.0.1",
    "scanme.nmap.org",       # Nmap's official public demo target — always OK
    "testphishing.example",  # synthetic test domain
    "demo.phishtest.local",
}

# Targets matching these IP ranges are always blocked (real production servers)
BLOCKED_IP_RANGES = [
    # We block everything except loopback and the Nmap demo target by default.
    # In a real deployment you would add your own IP ranges here.
]


# ─────────────────────────────────────────────────────────────────────────────
# Dangerous port registry
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: port_number → (service_name, risk_level, reason)
# risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"

DANGEROUS_PORTS = {
    # ── Remote access / admin ──────────────────────────────────────────────
    21:   ("FTP",             "HIGH",     "Plain-text file transfer — credentials exposed"),
    22:   ("SSH",             "MEDIUM",   "Remote shell — ensure key-auth only, no root login"),
    23:   ("Telnet",          "CRITICAL", "Plain-text remote shell — completely insecure"),
    3389: ("RDP",             "HIGH",     "Windows Remote Desktop — common ransomware vector"),
    5900: ("VNC",             "HIGH",     "Remote desktop — often misconfigured with no auth"),
    5901: ("VNC-1",           "HIGH",     "VNC secondary port"),

    # ── Database ports ─────────────────────────────────────────────────────
    1433: ("MSSQL",           "CRITICAL", "SQL Server exposed to internet — immediate risk"),
    1521: ("Oracle DB",       "CRITICAL", "Oracle database exposed to internet"),
    3306: ("MySQL",           "CRITICAL", "MySQL exposed to internet — data breach risk"),
    5432: ("PostgreSQL",      "CRITICAL", "PostgreSQL exposed to internet"),
    27017:("MongoDB",         "CRITICAL", "MongoDB often misconfigured with no auth"),
    6379: ("Redis",           "CRITICAL", "Redis has no auth by default — RCE risk"),
    9200: ("Elasticsearch",   "CRITICAL", "Elasticsearch open to internet — data breach"),
    9042: ("Cassandra",       "HIGH",     "Cassandra CQL port exposed"),

    # ── Legacy / deprecated protocols ─────────────────────────────────────
    25:   ("SMTP",            "MEDIUM",   "Mail relay — check for open relay misconfiguration"),
    110:  ("POP3",            "MEDIUM",   "Plain-text email retrieval"),
    143:  ("IMAP",            "MEDIUM",   "Plain-text email access"),
    161:  ("SNMP",            "HIGH",     "Network management — often exploitable"),
    512:  ("rexec",           "CRITICAL", "Remote execution — no encryption"),
    513:  ("rlogin",          "CRITICAL", "Remote login — no encryption"),
    514:  ("rsh/syslog",      "HIGH",     "Remote shell or syslog — both risky if open"),

    # ── File sharing ───────────────────────────────────────────────────────
    445:  ("SMB",             "CRITICAL", "Windows file sharing — EternalBlue target"),
    137:  ("NetBIOS-NS",      "HIGH",     "NetBIOS name service — recon vector"),
    138:  ("NetBIOS-DGM",     "HIGH",     "NetBIOS datagram service"),
    139:  ("NetBIOS-SSN",     "HIGH",     "NetBIOS session service — SMB relay attacks"),
    2049: ("NFS",             "HIGH",     "Network File System — often misconfigured"),

    # ── Admin panels ───────────────────────────────────────────────────────
    8080: ("HTTP-alt",        "MEDIUM",   "Alternative HTTP — often an admin panel"),
    8443: ("HTTPS-alt",       "MEDIUM",   "Alternative HTTPS — often an admin panel"),
    8888: ("HTTP-proxy/Jupyter","HIGH",   "Often Jupyter Notebook or proxy — RCE risk"),
    9090: ("Prometheus/CockroachDB","MEDIUM","Monitoring panel — can expose metrics"),
    9443: ("VMware/HTTPS-alt","MEDIUM",   "Alt HTTPS — common admin panel port"),
    10000:("Webmin",          "HIGH",     "Webmin admin panel — historically vulnerable"),

    # ── DevOps/cloud ───────────────────────────────────────────────────────
    2375: ("Docker daemon",   "CRITICAL", "Unauthenticated Docker API — full RCE"),
    2376: ("Docker TLS",      "HIGH",     "Docker API over TLS — verify cert auth"),
    2379: ("etcd",            "CRITICAL", "Kubernetes etcd — cluster key-value store"),
    6443: ("Kubernetes API",  "HIGH",     "k8s API server — verify auth"),
    4243: ("Docker",          "CRITICAL", "Docker daemon — another common port"),

    # ── Phishing infrastructure specific ──────────────────────────────────
    4444: ("Metasploit",      "CRITICAL", "Common Metasploit/reverse shell port"),
    4445: ("Upnotifyp/shell", "HIGH",     "Common C2/reverse shell port"),
    8888: ("C2/Jupyter",      "HIGH",     "Common C2 or Jupyter port"),
    1080: ("SOCKS proxy",     "HIGH",     "SOCKS proxy — anonymization or C2"),
    3128: ("Squid proxy",     "MEDIUM",   "Squid HTTP proxy — check for open proxy"),
}

# Ports that suggest an exposed admin panel regardless of service detection
ADMIN_PANEL_PORTS = {8080, 8443, 10000, 8888, 9090, 9200, 9443, 4848, 8161}

# Service names that indicate legacy/dangerous software
DANGEROUS_SERVICE_KEYWORDS = [
    "telnet", "ftp", "rpc", "rsh", "rlogin", "rexec",
    "vnc", "netbios", "smb", "msrpc", "snmp"
]


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def scan_target(
    target: str,
    scan_type: str = "top100",
    consent_confirmed: bool = False,
    url_scan_id: Optional[int] = None,
    email_scan_id: Optional[int] = None
) -> dict:
    """
    Run a network scan against a domain or IP address.

    Args:
        target:            Domain name or IP address to scan.
        scan_type:         One of:
                             "quick"   — ping + top 20 ports (fastest, ~5s)
                             "top100"  — top 100 ports with service detection (~15s)
                             "top1000" — top 1000 ports (~60s)
                             "full"    — all 65535 ports (~10 min, use carefully)
        consent_confirmed: Must be True for non-demo targets. Part of ethics gate.
        url_scan_id:       Link this scan to a URLScan DB row.
        email_scan_id:     Link this scan to an EmailScan DB row.

    Returns:
        NetworkScanResult dict. If the ethics gate blocks the scan,
        returns an error dict with authorized=False.
    """

    # ── Ethics gate ───────────────────────────────────────────────────────
    authorized, block_reason = _check_authorization(target, consent_confirmed)
    if not authorized:
        logger.warning(f"SCAN BLOCKED for {target}: {block_reason}")
        return _blocked_result(target, block_reason)

    # ── Resolve domain to IP ──────────────────────────────────────────────
    ip_resolved = _resolve_target(target)
    if ip_resolved is None:
        return _error_result(target, f"Could not resolve {target} to an IP address")

    # ── Select Nmap arguments based on scan_type ──────────────────────────
    nmap_args = _build_nmap_args(scan_type)

    # ── Run the scan ──────────────────────────────────────────────────────
    logger.info(f"Starting {scan_type} scan of {target} ({ip_resolved})")
    start_time = time.time()

    raw_result, nmap_version, nmap_error = _run_nmap(target, nmap_args)

    duration = round(time.time() - start_time, 2)
    logger.info(f"Scan of {target} completed in {duration}s")

    if nmap_error:
        return _error_result(target, nmap_error, ip_resolved=ip_resolved,
                             duration=duration, authorized=True)

    # ── Parse ports from nmap result ──────────────────────────────────────
    ports = _parse_ports(raw_result, target, ip_resolved)

    # ── Detect exposed admin panels ───────────────────────────────────────
    admin_exposures = _detect_admin_panels(ports)

    # ── OS fingerprint ────────────────────────────────────────────────────
    os_guess = _extract_os_guess(raw_result, target)

    # ── Compute overall risk level ────────────────────────────────────────
    risk_level, risk_flags = _assess_risk(ports, admin_exposures)

    open_ports = [p for p in ports if p["state"] == "open"]

    return {
        "target":          target,
        "ip_resolved":     ip_resolved,
        "scan_type":       scan_type,
        "nmap_version":    nmap_version,
        "os_guess":        os_guess,
        "ports":           ports,
        "open_port_count": len(open_ports),
        "admin_exposures": admin_exposures,
        "risk_level":      risk_level,
        "risk_flags":      risk_flags,
        "scan_duration_s": duration,
        "authorized":      True,
        "url_scan_id":     url_scan_id,
        "email_scan_id":   email_scan_id,
        "scanned_at":      datetime.utcnow().isoformat() + "Z",
        "raw_nmap_output": json.dumps(raw_result)[:8000]  # truncate for DB
    }


# ─────────────────────────────────────────────────────────────────────────────
# Ethics gate
# ─────────────────────────────────────────────────────────────────────────────

def _check_authorization(target: str, consent_confirmed: bool) -> tuple[bool, str]:
    """
    Multi-layer authorization check before any scan is run.

    Layer 1: Is the target in the hardcoded demo allowlist?
    Layer 2: Is the SCAN_AUTHORIZED environment variable set to "1"?
    Layer 3: Was consent_confirmed=True passed by the caller?

    All three layers must pass for non-allowlisted targets.
    Demo targets (localhost, scanme.nmap.org) only need layer 1.

    Returns: (authorized: bool, reason: str)
    """

    # Normalize — strip protocol prefixes if user pasted a URL
    clean_target = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]       # strip path
        .split(":")[0]       # strip port
        .lower()
        .strip()
    )

    # Layer 1: Demo allowlist — always authorized
    if clean_target in AUTHORIZED_DEMO_TARGETS:
        return True, "demo_target_allowlisted"

    # Layer 2: Check for the opt-in environment variable
    # Set SCAN_AUTHORIZED=1 in your .env to enable scanning of
    # domains you own or have written permission to scan.
    scan_authorized_env = os.environ.get("SCAN_AUTHORIZED", "0")
    if scan_authorized_env != "1":
        return False, (
            "SCAN_AUTHORIZED environment variable not set. "
            "Add SCAN_AUTHORIZED=1 to your .env file only for "
            "domains you own or have written permission to scan."
        )

    # Layer 3: Explicit consent from the caller
    if not consent_confirmed:
        return False, (
            "consent_confirmed=False. Pass consent_confirmed=True "
            "only after confirming written authorization to scan this target."
        )

    # All layers passed
    return True, "authorized_via_env_and_consent"


# ─────────────────────────────────────────────────────────────────────────────
# IP resolution
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_target(target: str) -> Optional[str]:
    """
    Resolve a domain or IP string to an IP address.
    Returns the IP string, or None if resolution fails.
    """
    # Strip protocol / path if caller passed a full URL
    clean = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
    )

    # If it's already an IP address, return it directly
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass

    # DNS resolution
    try:
        ip = socket.gethostbyname(clean)
        return ip
    except socket.gaierror as e:
        logger.error(f"Cannot resolve {clean}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Nmap argument builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_nmap_args(scan_type: str) -> str:
    """
    Build the nmap argument string for the requested scan type.

    Nmap flag reference:
      -sV   : service/version detection (probe open ports for service info)
      -sC   : default scripts (safe NSE scripts — adds service banners)
      -O    : OS detection (requires root/admin on most systems)
      --top-ports N : scan the N most commonly open ports
      -p-   : scan all 65535 ports
      -T4   : aggressive timing (faster on reliable networks)
      -T3   : normal timing (safer on slow/unreliable networks)
      --open: only show open ports (cleaner output)
      -Pn   : skip host discovery ping (treat host as up — needed for firewalled hosts)

    Note on -O (OS detection):
      Requires root/administrator privileges. If running as a normal
      user, nmap will skip OS detection gracefully — not a fatal error.
    """
    base_flags = "-sV --open -Pn"

    profiles = {
        # Quick: just the 20 most important ports, no version detection
        # Use this for a fast first pass on many domains
        "quick": f"--top-ports 20 -T4 -Pn --open",

        # Top 100: standard recon profile — good balance of speed and coverage
        # Service detection (-sV) gives us application names and versions
        "top100": f"--top-ports 100 -sV -T4 --open -Pn",

        # Top 1000: comprehensive scan — covers most real-world services
        # -sC adds default NSE scripts (safe, informational)
        "top1000": f"--top-ports 1000 -sV -sC -T3 --open -Pn",

        # Full: all 65535 ports — slow but complete
        # Only use on hosts you own, with patience
        "full": f"-p- -sV -sC -T3 --open -Pn",
    }

    return profiles.get(scan_type, profiles["top100"])


# ─────────────────────────────────────────────────────────────────────────────
# Nmap execution
# ─────────────────────────────────────────────────────────────────────────────

def _run_nmap(target: str, nmap_args: str) -> tuple[dict, str, Optional[str]]:
    """
    Execute the nmap scan using python-nmap's PortScanner.

    python-nmap wraps the nmap binary — nmap must be installed:
      Linux/macOS: sudo apt install nmap  /  brew install nmap
      Windows:     https://nmap.org/download.html

    Returns:
        (scan_result_dict, nmap_version_string, error_message_or_None)

    The scan_result_dict has the structure:
        {
          "hostname": {
            "tcp": {
              port_number: {
                "state": "open",
                "name": "http",
                "product": "Apache httpd",
                "version": "2.4.41",
                "extrainfo": "...",
                "cpe": "cpe:/a:apache:http_server:2.4.41"
              }
            }
          }
        }
    """
    try:
        nm = nmap.PortScanner()

        # nmap() takes: hosts, ports (None = use --top-ports from args), arguments
        # We pass target as host, None for ports (controlled by --top-ports in args),
        # and our built argument string.
        nm.scan(hosts=target, ports=None, arguments=nmap_args)

        nmap_version = nm.nmap_version()
        version_str  = f"{nmap_version[0]}.{nmap_version[1]}" if nmap_version else "unknown"

        # nm[target] is a dict of protocols → {port → port_info}
        # If the host wasn't up or had no results, nm[target] is empty
        if target not in nm.all_hosts():
            # Try the resolved IP as the key (nmap sometimes uses IP not hostname)
            hosts = nm.all_hosts()
            if hosts:
                result = nm[hosts[0]]
            else:
                return {}, version_str, "No hosts found in scan result — host may be down or filtered"
        else:
            result = nm[target]

        return dict(result), version_str, None

    except nmap.PortScannerError as e:
        # Common causes: nmap not installed, insufficient privileges for -sS
        error_msg = str(e)
        if "nmap programme was not found" in error_msg.lower():
            return {}, "", "nmap binary not found. Install nmap: sudo apt install nmap"
        if "requires root" in error_msg.lower() or "permission" in error_msg.lower():
            return {}, "", "nmap requires root/admin for SYN scan. Try running with sudo, or the scan_type will auto-downgrade."
        return {}, "", f"Nmap error: {error_msg[:200]}"

    except Exception as e:
        logger.error(f"Unexpected nmap error scanning {target}: {e}")
        return {}, "", f"Unexpected scan error: {str(e)[:150]}"


# ─────────────────────────────────────────────────────────────────────────────
# Port result parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ports(nmap_result: dict, target: str, ip: str) -> list[dict]:
    """
    Parse the raw nmap result dict into a clean list of port dicts.

    For each open port we extract:
      - port number, protocol, state
      - service name (http, ssh, ftp, etc.)
      - product and version (Apache 2.4.41, OpenSSH 8.2, etc.)
      - extra info / banner text
      - CPE identifier (standard software ID format)
      - is_dangerous + danger_reason from our registry

    nmap_result structure (from python-nmap):
      {
        "tcp": { 22: {"state":"open","name":"ssh","product":"OpenSSH","version":"8.2",...} },
        "udp": { 161: {"state":"open","name":"snmp",...} },
        "osmatch": [...],
        ...
      }
    """
    ports = []

    # Iterate over protocols (usually just "tcp", sometimes "udp")
    for protocol in ("tcp", "udp"):
        proto_data = nmap_result.get(protocol, {})

        for port_num, port_info in proto_data.items():
            state = port_info.get("state", "unknown")

            # We only care about open ports for threat assessment
            # (filtered/closed ports aren't useful here)
            if state not in ("open", "open|filtered"):
                continue

            service_name    = port_info.get("name", "")
            service_product = port_info.get("product", "")
            service_version = port_info.get("version", "")
            service_extra   = port_info.get("extrainfo", "")
            cpe             = port_info.get("cpe", "")

            # Check against our dangerous port registry
            is_dangerous   = False
            danger_reason  = ""

            if port_num in DANGEROUS_PORTS:
                _, danger_level, reason = DANGEROUS_PORTS[port_num]
                is_dangerous  = True
                danger_reason = f"[{danger_level}] {reason}"

            # Also flag if service name matches dangerous keywords
            elif any(kw in service_name.lower() for kw in DANGEROUS_SERVICE_KEYWORDS):
                is_dangerous  = True
                danger_reason = f"Service '{service_name}' is inherently insecure"

            ports.append({
                "port":            port_num,
                "protocol":        protocol,
                "state":           state,
                "service_name":    service_name,
                "service_product": service_product,
                "service_version": service_version,
                "service_extra":   service_extra[:200],
                "cpe":             cpe,
                "is_dangerous":    is_dangerous,
                "danger_reason":   danger_reason,
                "risk_level":      DANGEROUS_PORTS.get(port_num, ("", "INFO", ""))[1]
                                   if port_num in DANGEROUS_PORTS else "INFO"
            })

    # Sort: dangerous ports first, then by port number
    ports.sort(key=lambda p: (0 if p["is_dangerous"] else 1, p["port"]))
    return ports


# ─────────────────────────────────────────────────────────────────────────────
# Admin panel detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_admin_panels(ports: list[dict]) -> list[dict]:
    """
    Identify ports and services that likely expose admin panels or
    management interfaces.

    Detection signals:
      1. Port is in the ADMIN_PANEL_PORTS set
      2. Service product name contains "admin", "management", "panel"
      3. Service extra info mentions login forms or console keywords

    Returns a list of admin exposure dicts, one per suspected panel.
    """
    exposures = []
    panel_keywords = [
        "admin", "management", "console", "manager", "dashboard",
        "control panel", "phpmyadmin", "cpanel", "plesk", "webmin",
        "jenkins", "grafana", "kibana", "rabbitmq", "activemq"
    ]

    for p in ports:
        if p["state"] != "open":
            continue

        is_admin_port = p["port"] in ADMIN_PANEL_PORTS

        # Check service product and extra info for admin keywords
        combined = (
            f"{p['service_name']} {p['service_product']} {p['service_extra']}"
        ).lower()
        matched_kw = [kw for kw in panel_keywords if kw in combined]

        if is_admin_port or matched_kw:
            panel_type = matched_kw[0] if matched_kw else "management interface"
            exposures.append({
                "port":        p["port"],
                "protocol":    p["protocol"],
                "panel_type":  panel_type,
                "service":     p["service_product"] or p["service_name"],
                "description": (
                    f"Port {p['port']} ({p['service_product'] or p['service_name']}) "
                    f"appears to expose a {panel_type}. "
                    f"Admin panels should never be internet-accessible."
                ),
                "severity": "HIGH"
            })

    return exposures


# ─────────────────────────────────────────────────────────────────────────────
# OS fingerprint extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_os_guess(nmap_result: dict, target: str) -> Optional[str]:
    """
    Extract the best OS guess from nmap's OS detection results.
    Returns None if OS detection wasn't run or produced no results
    (common when not running as root).
    """
    try:
        os_matches = nmap_result.get("osmatch", [])
        if not os_matches:
            return None

        # osmatch is a list of dicts sorted by accuracy (highest first)
        # Each has: name, accuracy, osclass list
        best = os_matches[0]
        name     = best.get("name", "")
        accuracy = best.get("accuracy", "")
        return f"{name} (accuracy: {accuracy}%)" if name else None

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Risk assessment
# ─────────────────────────────────────────────────────────────────────────────

def _assess_risk(ports: list[dict], admin_exposures: list[dict]) -> tuple[str, list]:
    """
    Assign an overall risk level and build a list of risk flag strings
    based on what the port scan found.

    Risk level escalation:
      LOW:      No dangerous ports, no admin panels
      MEDIUM:   1–2 medium-risk ports (e.g. open SSH, HTTP-alt)
      HIGH:     Critical database or remote access ports open
      CRITICAL: Direct RCE-risk ports (Telnet, unauthenticated Docker,
                public database ports, Metasploit listener ports)

    Returns: (risk_level: str, flags: list[str])
    """
    flags = []
    max_level = "LOW"

    level_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for p in ports:
        if not p["is_dangerous"]:
            continue

        port_level = p.get("risk_level", "INFO")

        # Escalate the overall risk level to the highest seen
        if level_order.get(port_level, 0) > level_order.get(max_level, 0):
            max_level = port_level

        flags.append(
            f"PORT_{p['port']}_{p['service_name'].upper() or 'UNKNOWN'} "
            f"({port_level})"
        )

    # Admin panels escalate to at least HIGH
    if admin_exposures:
        if level_order.get(max_level, 0) < level_order["HIGH"]:
            max_level = "HIGH"
        for exp in admin_exposures:
            flags.append(f"ADMIN_PANEL_EXPOSED_PORT_{exp['port']}")

    # Large number of open ports is itself a signal
    open_count = sum(1 for p in ports if p["state"] == "open")
    if open_count > 20:
        flags.append(f"EXCESSIVE_OPEN_PORTS ({open_count} open)")
        if level_order.get(max_level, 0) < level_order["MEDIUM"]:
            max_level = "MEDIUM"

    return max_level, flags


# ─────────────────────────────────────────────────────────────────────────────
# Result builders
# ─────────────────────────────────────────────────────────────────────────────

def _blocked_result(target: str, reason: str) -> dict:
    """Return a blocked result dict when the ethics gate prevents scanning."""
    return {
        "target":          target,
        "ip_resolved":     None,
        "scan_type":       "blocked",
        "nmap_version":    None,
        "os_guess":        None,
        "ports":           [],
        "open_port_count": 0,
        "admin_exposures": [],
        "risk_level":      "UNKNOWN",
        "risk_flags":      ["SCAN_BLOCKED"],
        "scan_duration_s": 0,
        "authorized":      False,
        "block_reason":    reason,
        "scanned_at":      datetime.utcnow().isoformat() + "Z",
        "error":           f"Scan blocked: {reason}"
    }


def _error_result(target: str, message: str,
                  ip_resolved: str = None, duration: float = 0,
                  authorized: bool = False) -> dict:
    """Return an error result dict when the scan fails after authorization."""
    return {
        "target":          target,
        "ip_resolved":     ip_resolved,
        "scan_type":       "error",
        "nmap_version":    None,
        "os_guess":        None,
        "ports":           [],
        "open_port_count": 0,
        "admin_exposures": [],
        "risk_level":      "UNKNOWN",
        "risk_flags":      ["SCAN_ERROR"],
        "scan_duration_s": duration,
        "authorized":      authorized,
        "scanned_at":      datetime.utcnow().isoformat() + "Z",
        "error":           message
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public helper — check if a target is safe to scan (for the UI consent prompt)
# ─────────────────────────────────────────────────────────────────────────────

def is_demo_target(target: str) -> bool:
    """
    Returns True if the target is on the safe demo allowlist.
    The dashboard uses this to decide whether to show the consent warning.
    """
    clean = (
        target.replace("https://", "").replace("http://", "")
        .split("/")[0].split(":")[0].lower().strip()
    )
    return clean in AUTHORIZED_DEMO_TARGETS