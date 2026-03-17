"""
network_anomaly_detector.py - Detect suspicious network activity.
Fixed to avoid false positives from normal Windows network state.
Only flags genuinely suspicious activity.
"""

import json
import logging
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# Very specific C2/attacker ports — not common application ports
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default listener
    4445,   # Metasploit alternate
    1234,   # Common reverse shell
    31337,  # Elite/Back Orifice
    12345,  # NetBus
    54321,  # NetBus reverse
    1337,   # Common hacker port
    6666,   # IRC/backdoor
    9999,   # Common backdoor
}

# Known C2 and exfiltration domains
SUSPICIOUS_DOMAINS = [
    "ngrok.io",
    "serveo.net",
    "pagekite.me",
    "burpcollaborator.net",
    "canarytokens.com",
    "requestbin.com",
    "webhook.site",
    "interactsh.com",
]

# Local network ranges — connections to these are not suspicious
LOCAL_RANGES = [
    "127.", "10.", "192.168.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "::1", "fe80:",
]


def _run_safe(args: list, timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, shell=False
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _check_suspicious_ports_windows() -> list:
    """
    Check for connections on known attacker ports only.
    Do NOT flag high connection counts — normal for Windows.
    """
    indicators = []

    ps_cmd = (
        "Get-NetTCPConnection -State Established,Listen "
        "-ErrorAction SilentlyContinue "
        "| Select-Object LocalPort, RemotePort, RemoteAddress, State "
        "| ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=15)
    if not output or output.strip() in ["null", "[]"]:
        return []

    try:
        connections = json.loads(output)
        if isinstance(connections, dict):
            connections = [connections]

        for conn in connections:
            if not isinstance(conn, dict):
                continue

            local_port = conn.get("LocalPort", 0)
            remote_port = conn.get("RemotePort", 0)
            remote_addr = str(conn.get("RemoteAddress", ""))

            # Skip local connections
            if any(remote_addr.startswith(r) for r in LOCAL_RANGES):
                continue

            # Check for specific C2 ports
            if local_port in SUSPICIOUS_PORTS:
                indicators.append(f"LISTENING_ON_C2_PORT:{local_port}")
            if remote_port in SUSPICIOUS_PORTS:
                indicators.append(f"CONNECTED_TO_C2_PORT:{remote_port}")

    except (json.JSONDecodeError, TypeError):
        pass

    return indicators


def _check_dns_cache_windows() -> list:
    """
    Check DNS cache for known C2/exfiltration domains only.
    Very specific list — no false positives.
    """
    indicators = []

    ps_cmd = (
        "Get-DnsClientCache -ErrorAction SilentlyContinue "
        "| Select-Object Entry, Data "
        "| ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if not output or output.strip() in ["null", "[]"]:
        return []

    output_lower = output.lower()
    for domain in SUSPICIOUS_DOMAINS:
        if domain in output_lower:
            safe_domain = domain.upper().replace(".", "_")
            indicators.append(f"C2_DOMAIN_IN_DNS_CACHE:{safe_domain}")

    return indicators


def _check_large_outbound_transfer() -> list:
    """
    Check for unusually large outbound data transfers.
    Only flag if significantly above normal — 1GB+ sent is suspicious.
    """
    indicators = []

    ps_cmd = (
        "Get-NetAdapterStatistics -ErrorAction SilentlyContinue "
        "| Select-Object Name, SentBytes "
        "| ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if not output:
        return []

    try:
        stats = json.loads(output)
        if isinstance(stats, dict):
            stats = [stats]

        for adapter in stats:
            if not isinstance(adapter, dict):
                continue
            sent = adapter.get("SentBytes", 0) or 0
            # Only flag if more than 1GB sent — 500MB was too sensitive
            if isinstance(sent, (int, float)) and sent > 1024 * 1024 * 1024:
                gb = round(sent / (1024 * 1024 * 1024), 2)
                indicators.append(f"LARGE_OUTBOUND_TRANSFER:{gb}GB_SENT")

    except (json.JSONDecodeError, TypeError):
        pass

    return indicators


def _check_linux_network() -> list:
    """Check network on Linux."""
    indicators = []

    output = _run_safe(["ss", "-tnp"]) or _run_safe(["netstat", "-tnp"])
    if output:
        for port in SUSPICIOUS_PORTS:
            if f":{port} " in output or f":{port}\t" in output:
                indicators.append(f"LISTENING_ON_C2_PORT:{port}")

    return indicators


def detect_network_anomalies() -> dict:
    indicators = []

    try:
        if platform.system() == "Windows":
            indicators.extend(_check_suspicious_ports_windows())
            indicators.extend(_check_dns_cache_windows())
            indicators.extend(_check_large_outbound_transfer())
        else:
            indicators.extend(_check_linux_network())
    except Exception as e:
        logger.error("Network anomaly detection error: %s", str(e)[:200])

    seen = set()
    unique = []
    for ind in indicators:
        key = ind.split(":")[0]
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    return {"indicators": unique, "details": {"platform": platform.system()}}
