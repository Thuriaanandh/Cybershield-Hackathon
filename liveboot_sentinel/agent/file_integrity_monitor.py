"""
file_integrity_monitor.py - Detect filesystem tampering on internal drives
during or after a live OS boot window.
Windows and Linux compatible.
"""

import hashlib
import logging
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# High-value targets to monitor for unauthorized access/modification
WINDOWS_SENSITIVE_PATHS = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\System32\\config\\SOFTWARE",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\tasks",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Users",
]

LINUX_SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/root/.ssh",
    "/home",
    "/var/spool/cron",
    "/etc/rc.local",
]

# Suspicious file extensions dropped by attackers
SUSPICIOUS_EXTENSIONS = {
    ".ps1", ".vbs", ".bat", ".cmd", ".hta", ".scr",
    ".dll", ".exe", ".sh", ".py", ".rb", ".php",
}

# Suspicious filenames
SUSPICIOUS_NAMES = [
    "mimikatz", "meterpreter", "payload", "backdoor",
    "keylogger", "rootkit", "exploit", "pwdump",
    "procdump", "wce", "fgdump", "gsecdump",
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


def _get_recently_modified_windows(hours: int = 24) -> list:
    """Find files modified in the last N hours on Windows using PowerShell."""
    indicators = []
    ps_cmd = (
        f"Get-ChildItem C:\\Users -Recurse -ErrorAction SilentlyContinue "
        f"| Where-Object {{$_.LastWriteTime -gt (Get-Date).AddHours(-{hours}) "
        f"-and !$_.PSIsContainer}} "
        f"| Select-Object FullName, LastWriteTime, Length "
        f"| ConvertTo-Json -Depth 1"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=30)
    if output:
        output_lower = output.lower()
        for name in SUSPICIOUS_NAMES:
            if name in output_lower:
                indicators.append(f"SUSPICIOUS_FILE_FOUND:{name.upper()}")

        for ext in SUSPICIOUS_EXTENSIONS:
            if ext in output_lower:
                indicators.append(f"SUSPICIOUS_EXTENSION:{ext.upper().replace('.', '')}")

    return indicators


def _check_sensitive_paths_windows() -> list:
    """Check if sensitive Windows paths were recently accessed."""
    indicators = []
    ps_cmd = (
        "Get-Item 'C:\\Windows\\System32\\config\\SAM' "
        "-ErrorAction SilentlyContinue "
        "| Select-Object LastAccessTime | ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output and "lastAccessTime" in output.lower():
        indicators.append("SENSITIVE_FILE_ACCESS:SAM_DATABASE")

    # Check startup folder for new entries
    ps_cmd2 = (
        "Get-ChildItem "
        "'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' "
        "-ErrorAction SilentlyContinue | ConvertTo-Json"
    )
    output2 = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd2])
    if output2 and output2.strip() not in ["null", "[]", ""]:
        indicators.append("STARTUP_FOLDER_MODIFIED")

    return indicators


def _check_new_accounts_windows() -> list:
    """Detect newly created user accounts on Windows."""
    indicators = []
    ps_cmd = (
        "Get-LocalUser | Where-Object "
        "{$_.Enabled -eq $true} "
        "| Select-Object Name, LastLogon | ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output:
        # Look for suspicious account names
        suspicious_names = ["hacker", "backdoor", "admin2", "test", "guest2", "support2"]
        output_lower = output.lower()
        for name in suspicious_names:
            if name in output_lower:
                indicators.append(f"SUSPICIOUS_ACCOUNT_FOUND:{name.upper()}")

    return indicators


def _check_linux_tampering() -> list:
    """Check for filesystem tampering on Linux."""
    indicators = []

    # Check recently modified sensitive files
    for path in LINUX_SENSITIVE_PATHS:
        p = Path(path)
        if p.exists():
            try:
                stat = p.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                age_hours = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600
                if age_hours < 24:
                    safe_path = re.sub(r"[^\w/.]", "", path)[:50]
                    indicators.append(f"SENSITIVE_FILE_RECENTLY_MODIFIED:{safe_path}")
            except OSError:
                pass

    # Check for new SUID binaries
    find_output = _run_safe(
        ["find", "/usr/bin", "/usr/local/bin", "-perm", "-4000", "-type", "f"],
        timeout=15
    )
    if find_output:
        known_suid = {"sudo", "su", "passwd", "newgrp", "gpasswd", "chsh", "chfn"}
        for line in find_output.strip().split("\n"):
            binary = Path(line.strip()).name
            if binary and binary not in known_suid:
                indicators.append(f"NEW_SUID_BINARY:{binary[:30]}")

    return indicators


def analyze_file_integrity() -> dict:
    """
    Main function — analyze filesystem for tampering indicators.
    Returns dict with indicators and details.
    """
    indicators = []
    details = {}

    try:
        if platform.system() == "Windows":
            indicators.extend(_get_recently_modified_windows())
            indicators.extend(_check_sensitive_paths_windows())
            indicators.extend(_check_new_accounts_windows())
        else:
            indicators.extend(_check_linux_tampering())
    except Exception as e:
        logger.error("File integrity check error: %s", str(e)[:200])
        indicators.append("FILE_INTEGRITY_CHECK_FAILED")

    # Deduplicate by prefix
    seen = set()
    unique = []
    for ind in indicators:
        key = ind.split(":")[0]
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    details["checks_run"] = platform.system()
    details["indicators_found"] = len(unique)

    return {
        "indicators": unique,
        "details": details,
    }
