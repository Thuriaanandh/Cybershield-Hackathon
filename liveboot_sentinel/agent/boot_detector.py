"""
boot_detector.py - Detect if the system booted from removable/external media.
Windows and Linux compatible.
"""

import logging
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


def _run_safe(args: list, timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        logger.debug("Command %s failed: %s", args[0], str(e)[:100])
        return None


def _detect_windows() -> dict:
    """Detect boot source on Windows using PowerShell and WMI."""
    indicators = []
    boot_source = "disk"
    details = {}

    # Get disk drive info via PowerShell
    ps_cmd = (
        "Get-WmiObject Win32_DiskDrive | "
        "Select-Object MediaType,InterfaceType,Caption,Size | "
        "ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])

    if output:
        output_lower = output.lower()
        details["disk_info"] = output[:500]
        # Check for USB/removable media
        if any(k in output_lower for k in ["usb", "removable", "external"]):
            indicators.append("USB_BOOT_DETECTED")
            boot_source = "usb"

    # Check boot device via bcdedit
    bcdedit_output = _run_safe(["bcdedit", "/enum", "{current}"])
    if bcdedit_output:
        bcdedit_lower = bcdedit_output.lower()
        details["bcdedit"] = bcdedit_output[:500]
        if any(k in bcdedit_lower for k in ["usb", "removable"]):
            if "USB_BOOT_DETECTED" not in indicators:
                indicators.append("USB_BOOT_DETECTED")
            boot_source = "usb"
    else:
        indicators.append("BOOT_SOURCE_UNKNOWN")

    return {"indicators": indicators, "boot_source": boot_source, "details": details}


def _detect_linux() -> dict:
    """Detect boot source on Linux using lsblk and /proc/mounts."""
    indicators = []
    boot_source = "unknown"
    details = {}

    # Try lsblk
    output = _run_safe(["lsblk", "-o", "NAME,TYPE,MOUNTPOINT,RM,TRAN", "-J"])
    root_device = None

    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "/" and parts[0].startswith("/dev/"):
                    root_device = parts[0]
                    break
    except OSError:
        indicators.append("BOOT_SOURCE_UNKNOWN")

    if root_device:
        boot_source = "disk"
        if output:
            import json
            try:
                data = json.loads(output)
                for dev in data.get("blockdevices", []):
                    rm = str(dev.get("rm", "0"))
                    tran = str(dev.get("tran", "")).lower()
                    if rm == "1" or "usb" in tran:
                        indicators.append("USB_BOOT_DETECTED")
                        boot_source = "usb"
                        break
            except Exception:
                pass
    else:
        if "BOOT_SOURCE_UNKNOWN" not in indicators:
            indicators.append("BOOT_SOURCE_UNKNOWN")

    details["root_device"] = root_device or "unknown"
    return {"indicators": indicators, "boot_source": boot_source, "details": details}


def detect_boot_source() -> dict:
    if platform.system() == "Windows":
        return _detect_windows()
    return _detect_linux()
