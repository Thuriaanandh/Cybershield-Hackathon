"""
kernel_fingerprint.py - Read kernel information and detect live OS indicators.
Windows and Linux compatible.
"""

import logging
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

LIVE_OS_INDICATORS = {
    "kali": "Kali Linux",
    "tails": "Tails OS",
    "parrot": "Parrot OS",
    "live": "Generic Live Environment",
    "casper": "Ubuntu/Casper Live",
    "persistence": "Persistent Live OS",
    "backtrack": "BackTrack Linux",
    "blackarch": "BlackArch Linux",
    "remnux": "REMnux",
    "whonix": "Whonix",
    "pentoo": "Pentoo",
}


def _run_safe(args: list, timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _check_live_indicators(text: str) -> list:
    text_lower = text.lower()
    matched = []
    for keyword, label in LIVE_OS_INDICATORS.items():
        if keyword in text_lower:
            matched.append(f"LIVE_OS_KERNEL:{label.upper().replace(' ', '_')}")
    return matched


def _get_kernel_windows() -> dict:
    """Get system info on Windows."""
    indicators = []
    detected_os = None
    details = {}

    # Use platform module (always available)
    version = platform.version()
    system = platform.system()
    release = platform.release()
    kernel_version = f"{system} {release} {version}"
    details["kernel_version"] = kernel_version

    # Check WMI for OS info
    ps_cmd = "Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version | ConvertTo-Json"
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output:
        details["os_info"] = output[:300]
        os_indicators = _check_live_indicators(output)
        indicators.extend(os_indicators)
        for keyword, label in LIVE_OS_INDICATORS.items():
            if keyword in output.lower():
                detected_os = label
                break

    return {
        "kernel_version": kernel_version,
        "indicators": indicators,
        "detected_os": detected_os,
        "details": details,
    }


def _get_kernel_linux() -> dict:
    """Get kernel info on Linux."""
    indicators = []
    detected_os = None
    details = {}

    output = _run_safe(["uname", "-a"])
    kernel_version = output[:128] if output else "unknown"
    if not output:
        indicators.append("KERNEL_READ_FAILED")

    details["kernel_version"] = kernel_version
    indicators.extend(_check_live_indicators(kernel_version))

    # Read /etc/os-release
    for path in ["/etc/os-release", "/usr/lib/os-release"]:
        try:
            with open(path, "r") as f:
                content = f.read()
            os_indicators = _check_live_indicators(content)
            for ind in os_indicators:
                if ind not in indicators:
                    indicators.append(ind)
            for keyword, label in LIVE_OS_INDICATORS.items():
                if keyword in content.lower():
                    detected_os = label
                    break
            break
        except OSError:
            continue

    # Check /proc/cmdline
    try:
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read().lower()
        for key in ["boot=live", "casper", "live", "persistence", "toram"]:
            if key in cmdline:
                safe_key = re.sub(r"[^a-zA-Z0-9_=]", "", key).upper()
                ind = f"LIVE_CMDLINE:{safe_key}"
                if ind not in indicators:
                    indicators.append(ind)
    except OSError:
        pass

    return {
        "kernel_version": kernel_version,
        "indicators": indicators,
        "detected_os": detected_os,
        "details": details,
    }


def get_kernel_fingerprint() -> dict:
    if platform.system() == "Windows":
        return _get_kernel_windows()
    return _get_kernel_linux()
