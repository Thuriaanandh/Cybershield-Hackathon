"""
kernel_fingerprint.py - Read kernel information and detect live OS indicators.
Windows and Linux compatible.
On Windows, uses WMI and registry to identify live OS environments.
"""

import logging
import platform
import re
import subprocess
from pathlib import Path
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
        result = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, shell=False
        )
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


def _detect_os_from_usb_registry() -> Optional[str]:
    """
    Check registry for USB storage devices that match known live OS drive labels.
    This detects what OS was on the USB that was plugged in.
    """
    ps_cmd = (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' "
        "-ErrorAction SilentlyContinue "
        "| Select-Object FriendlyName "
        "| ConvertTo-Json -Depth 1"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=10)
    if not output:
        return None

    output_lower = output.lower()
    # Check for known live OS USB labels
    for keyword, label in LIVE_OS_INDICATORS.items():
        if keyword in output_lower:
            return label

    return None


def _detect_os_from_boot_logs() -> Optional[str]:
    """
    Check Windows boot logs and event logs for evidence of
    which OS was previously booted.
    """
    # Check bcdedit for non-Windows boot entries
    bcdedit = _run_safe(["bcdedit", "/enum", "all"])
    if bcdedit:
        bcdedit_lower = bcdedit.lower()
        for keyword, label in LIVE_OS_INDICATORS.items():
            if keyword in bcdedit_lower:
                return label

    # Check event log for previous OS boot
    ps_cmd = (
        "Get-WinEvent -LogName System -MaxEvents 200 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 12 -or $_.Id -eq 6005} "
        "| Select-Object TimeCreated, Message "
        "| ConvertTo-Json -Depth 1"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=15)
    if output:
        output_lower = output.lower()
        for keyword, label in LIVE_OS_INDICATORS.items():
            if keyword in output_lower:
                return label

    return None


def _detect_os_from_disk_labels() -> Optional[str]:
    """
    Check connected disk volume labels for live OS identifiers.
    A Kali USB will often have volume label 'Kali' or 'KALI'.
    """
    ps_cmd = (
        "Get-WmiObject Win32_LogicalDisk "
        "| Select-Object DeviceID,VolumeName,DriveType "
        "| ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=10)
    if not output:
        return None

    output_lower = output.lower()
    for keyword, label in LIVE_OS_INDICATORS.items():
        if keyword in output_lower:
            return label

    return None


def _get_windows_fingerprint() -> dict:
    """Get system fingerprint on Windows."""
    indicators = []
    detected_os = None

    # Get Windows version info
    kernel_version = f"{platform.system()} {platform.release()} {platform.version()}"[:128]

    # Try to detect live OS from multiple sources
    detected_os = (
        _detect_os_from_disk_labels() or
        _detect_os_from_usb_registry() or
        _detect_os_from_boot_logs()
    )

    if detected_os:
        safe_label = detected_os.upper().replace(" ", "_")
        indicators.append(f"LIVE_OS_KERNEL:{safe_label}")
        logger.warning("Live OS detected from system artifacts: %s", detected_os)

    # Check if Kali USB is currently plugged in via disk labels
    ps_cmd = (
        "Get-WmiObject Win32_LogicalDisk "
        "| Where-Object {$_.DriveType -eq 2} "
        "| Select-Object DeviceID,VolumeName "
        "| ConvertTo-Json"
    )
    removable_output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=10)
    if removable_output and removable_output.strip() not in ["null", ""]:
        removable_lower = removable_output.lower()
        for keyword, label in LIVE_OS_INDICATORS.items():
            if keyword in removable_lower:
                if not detected_os:
                    detected_os = label
                if f"LIVE_OS_KERNEL:{label.upper().replace(' ', '_')}" not in indicators:
                    indicators.append(f"LIVE_OS_KERNEL:{label.upper().replace(' ', '_')}")

    return {
        "kernel_version": kernel_version,
        "indicators": indicators,
        "detected_os": detected_os,
        "details": {"kernel_version": kernel_version},
    }


def _get_linux_fingerprint() -> dict:
    """Get kernel fingerprint on Linux."""
    indicators = []
    detected_os = None

    output = _run_safe(["uname", "-a"])
    kernel_version = output[:128] if output else "unknown"
    if not output:
        indicators.append("KERNEL_READ_FAILED")

    indicators.extend(_check_live_indicators(kernel_version))

    for path in ["/etc/os-release", "/usr/lib/os-release"]:
        try:
            content = Path(path).read_text(errors="ignore")
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

    try:
        cmdline = Path("/proc/cmdline").read_text().lower()
        for key in ["boot=live", "casper", "live", "persistence", "toram"]:
            if key in cmdline:
                safe = re.sub(r"[^a-zA-Z0-9_=]", "", key).upper()
                ind = f"LIVE_CMDLINE:{safe}"
                if ind not in indicators:
                    indicators.append(ind)
    except OSError:
        pass

    return {
        "kernel_version": kernel_version,
        "indicators": indicators,
        "detected_os": detected_os,
        "details": {"kernel_version": kernel_version},
    }


def get_kernel_fingerprint() -> dict:
    if platform.system() == "Windows":
        return _get_windows_fingerprint()
    return _get_linux_fingerprint()
