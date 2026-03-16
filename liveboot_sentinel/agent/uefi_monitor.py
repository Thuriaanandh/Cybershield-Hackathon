"""
uefi_monitor.py - Analyze UEFI firmware variables and boot entries.
Windows and Linux compatible.
"""

import logging
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

USB_BOOT_PATTERNS = ["usb", "removable", "live", "kali", "tails", "parrot", "pendrive", "flash"]
EFI_VARS_PATH = Path("/sys/firmware/efi/efivars")


def _run_safe(args: list, timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _analyze_windows() -> dict:
    """Analyze UEFI boot entries on Windows via PowerShell/bcdedit."""
    indicators = []
    details = {}
    boot_entries = []

    # Get boot entries via bcdedit
    output = _run_safe(["bcdedit", "/enum", "all"])
    if output:
        output_lower = output.lower()
        details["bcdedit_entries"] = output[:1000]

        # Check for USB boot entries
        for pattern in USB_BOOT_PATTERNS:
            if pattern in output_lower:
                indicators.append(f"USB_UEFI_BOOT_ENTRY:{pattern.upper()}")
                break

        # Parse boot entries
        entries = output.split("\n\n")
        for entry in entries:
            if "description" in entry.lower():
                desc_match = re.search(r"description\s+(.+)", entry, re.IGNORECASE)
                if desc_match:
                    label = re.sub(r"[^\w\s.\-()]", "", desc_match.group(1).strip())[:100]
                    boot_entries.append({"label": label})

    # Check Secure Boot state
    sb_cmd = "Confirm-SecureBootUEFI 2>$null"
    sb_output = _run_safe(["powershell", "-NoProfile", "-Command", sb_cmd])
    if sb_output and "false" in sb_output.lower():
        indicators.append("SECURE_BOOT_DISABLED")

    return {
        "indicators": indicators,
        "boot_entries": boot_entries[:20],
        "boot_order": [],
        "is_uefi": True,
        "details": details,
    }


def _analyze_linux() -> dict:
    """Analyze UEFI on Linux via efibootmgr."""
    indicators = []
    boot_entries = []
    boot_order = []
    details = {}

    is_uefi = EFI_VARS_PATH.exists()
    details["is_uefi"] = is_uefi

    if not is_uefi:
        return {"indicators": indicators, "boot_entries": [], "boot_order": [], "is_uefi": False, "details": details}

    output = _run_safe(["efibootmgr", "-v"])
    if not output:
        indicators.append("UEFI_DATA_UNAVAILABLE")
        return {"indicators": indicators, "boot_entries": [], "boot_order": [], "is_uefi": True, "details": details}

    for line in output.splitlines()[:200]:
        if line.startswith("BootOrder:"):
            boot_order = [e.strip() for e in line.split(":")[1].split(",") if re.match(r"^[0-9A-Fa-f]{4}$", e.strip())]

        match = re.match(r"^Boot([0-9A-Fa-f]{4})([* ])\s+(.+?)(?:\t(.*))?$", line.strip())
        if match:
            label = re.sub(r"[^\w\s.\-()]", "", match.group(3).strip())[:100]
            entry = {"boot_num": match.group(1), "active": match.group(2) == "*", "label": label}
            boot_entries.append(entry)
            label_lower = label.lower()
            if any(p in label_lower for p in USB_BOOT_PATTERNS):
                indicators.append(f"USB_UEFI_BOOT_ENTRY:{label[:40]}")

    return {"indicators": indicators, "boot_entries": boot_entries[:50], "boot_order": boot_order, "is_uefi": True, "details": details}


def analyze_uefi() -> dict:
    if platform.system() == "Windows":
        return _analyze_windows()
    return _analyze_linux()
