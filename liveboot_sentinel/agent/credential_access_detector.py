"""
credential_access_detector.py - Detect credential theft attempts.
Monitors SAM, NTDS.dit, /etc/shadow access and common credential dumping tools.
Windows and Linux compatible.
"""

import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Known credential dumping tool names
CREDENTIAL_TOOLS = [
    "mimikatz", "wce", "fgdump", "pwdump", "gsecdump",
    "procdump", "ntdsutil", "secretsdump", "hashdump",
    "lsadump", "kerberoast", "rubeus", "bloodhound",
    "sharphound", "crackmapexec", "impacket",
]

# Sensitive credential file paths
WINDOWS_CRED_PATHS = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\NTDS\\ntds.dit",
    "C:\\Windows\\System32\\config\\SYSTEM",
]

LINUX_CRED_PATHS = [
    "/etc/shadow",
    "/etc/gshadow",
    "/var/lib/sss/db",
    "/etc/krb5.keytab",
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


def _check_process_list_windows() -> list:
    """Check running processes for credential dumping tools."""
    indicators = []
    ps_cmd = "Get-Process | Select-Object Name, Path | ConvertTo-Json"
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output:
        output_lower = output.lower()
        for tool in CREDENTIAL_TOOLS:
            if tool in output_lower:
                indicators.append(f"CREDENTIAL_TOOL_RUNNING:{tool.upper()}")

    return indicators


def _check_lsass_access_windows() -> list:
    """Check for LSASS process memory access (credential dumping indicator)."""
    indicators = []
    ps_cmd = (
        "Get-Process lsass -ErrorAction SilentlyContinue "
        "| Select-Object Id, CPU, WorkingSet | ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output and output.strip() not in ["null", ""]:
        # Check if any non-system process has a handle to lsass
        ps_cmd2 = (
            "Get-WinEvent -LogName Security -MaxEvents 100 "
            "-FilterXPath \"*[System[EventID=4656] and "
            "EventData[Data[@Name='ObjectName'] and "
            "Data[contains(text(),'lsass')]]]\" "
            "-ErrorAction SilentlyContinue | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        output2 = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd2])
        if output2 and output2.strip() not in ["0", "", "null"]:
            indicators.append("LSASS_ACCESS_DETECTED")

    return indicators


def _check_sam_access_windows() -> list:
    """Check Windows event log for SAM database access."""
    indicators = []
    ps_cmd = (
        "Get-WinEvent -LogName Security -MaxEvents 200 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 4663 -and "
        "$_.Message -like '*SAM*'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if output and output.strip() not in ["0", "", "null"]:
        indicators.append("SAM_DATABASE_ACCESS_DETECTED")

    return indicators


def _check_registry_credential_access() -> list:
    """Check for registry access to credential-related hives."""
    indicators = []
    ps_cmd = (
        "Get-WinEvent -LogName Security -MaxEvents 200 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -in @(4656,4663) -and "
        "($_.Message -like '*\\SAM*' -or "
        "$_.Message -like '*\\SECURITY*')} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if output and output.strip() not in ["0", "", "null"]:
        indicators.append("CREDENTIAL_REGISTRY_ACCESS")

    return indicators


def _check_linux_credentials() -> list:
    """Check for credential access on Linux."""
    indicators = []

    # Check if /etc/shadow was recently read
    try:
        shadow = Path("/etc/shadow")
        if shadow.exists():
            stat = shadow.stat()
            import time
            if time.time() - stat.st_atime < 3600:
                indicators.append("SHADOW_FILE_RECENTLY_ACCESSED")
    except OSError:
        pass

    # Check running processes for credential tools
    ps_output = _run_safe(["ps", "aux"])
    if ps_output:
        ps_lower = ps_output.lower()
        for tool in CREDENTIAL_TOOLS:
            if tool in ps_lower:
                indicators.append(f"CREDENTIAL_TOOL_RUNNING:{tool.upper()}")

    # Check bash history for credential commands
    history_paths = [
        Path("/root/.bash_history"),
        Path("/root/.zsh_history"),
    ]
    for hp in history_paths:
        if hp.exists():
            try:
                content = hp.read_text(errors="ignore").lower()
                for tool in CREDENTIAL_TOOLS:
                    if tool in content:
                        indicators.append(f"CREDENTIAL_TOOL_IN_HISTORY:{tool.upper()}")
                        break
            except OSError:
                pass

    return indicators


def detect_credential_access() -> dict:
    """
    Main function — detect credential theft attempts.
    Returns dict with indicators and details.
    """
    indicators = []
    details = {}

    try:
        if platform.system() == "Windows":
            indicators.extend(_check_process_list_windows())
            indicators.extend(_check_lsass_access_windows())
            indicators.extend(_check_sam_access_windows())
            indicators.extend(_check_registry_credential_access())
        else:
            indicators.extend(_check_linux_credentials())
    except Exception as e:
        logger.error("Credential access detection error: %s", str(e)[:200])

    # Deduplicate by prefix
    seen = set()
    unique = []
    for ind in indicators:
        key = ind.split(":")[0]
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    details["platform"] = platform.system()
    details["indicators_found"] = len(unique)

    return {
        "indicators": unique,
        "details": details,
    }
