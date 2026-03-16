"""
boot_fingerprint.py - Compare current boot fingerprint against stored baseline.
Windows and Linux compatible.
"""

import json
import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Baseline path — Windows uses user home, Linux uses /etc
if platform.system() == "Windows":
    BASELINE_PATH = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "liveboot_sentinel" / "baseline.json"
else:
    BASELINE_PATH = Path("/etc/liveboot_sentinel/baseline.json")


def _run_safe(args: list, timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as e:
        logger.warning("Command %s failed: %s", args[0], str(e)[:100])
        return None


def _get_secure_boot_windows() -> str:
    ps_cmd = (
        "Confirm-SecureBootUEFI 2>$null; "
        "if ($?) { 'enabled' } else { 'disabled' }"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output:
        if "true" in output.lower():
            return "enabled"
        elif "false" in output.lower():
            return "disabled"
    # Fallback via registry
    reg_output = _run_safe([
        "reg", "query",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "/v", "UEFISecureBootEnabled"
    ])
    if reg_output:
        if "0x1" in reg_output:
            return "enabled"
        elif "0x0" in reg_output:
            return "disabled"
    return "unknown"


def _get_secure_boot_linux() -> str:
    output = _run_safe(["mokutil", "--sb-state"])
    if output:
        if "enabled" in output.lower():
            return "enabled"
        elif "disabled" in output.lower():
            return "disabled"
    efi_path = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if efi_path.exists():
        try:
            data = efi_path.read_bytes()
            if len(data) >= 5:
                return "enabled" if data[4] == 1 else "disabled"
        except OSError:
            pass
    return "unknown"


def _get_boot_device_windows() -> str:
    ps_cmd = (
        "Get-WmiObject Win32_OperatingSystem | "
        "Select-Object -ExpandProperty SystemDrive"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    return output.strip() if output else "unknown"


def _get_kernel_version_windows() -> str:
    return f"{platform.system()} {platform.release()} {platform.version()}"[:128]


def _get_root_fs_windows() -> str:
    ps_cmd = (
        "Get-WmiObject Win32_LogicalDisk | "
        "Where-Object {$_.DeviceID -eq $env:SystemDrive} | "
        "Select-Object -ExpandProperty FileSystem"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    return output.strip() if output else "unknown"


def _get_disk_uuid_windows() -> str:
    ps_cmd = (
        "Get-WmiObject Win32_LogicalDisk | "
        "Where-Object {$_.DeviceID -eq $env:SystemDrive} | "
        "Select-Object -ExpandProperty VolumeSerialNumber"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output:
        uuid = re.sub(r"[^A-F0-9]", "", output.strip().upper())
        return uuid[:40] or "unknown"
    return "unknown"


def collect_current_fingerprint() -> dict:
    if platform.system() == "Windows":
        return {
            "boot_device": _get_boot_device_windows(),
            "kernel_version": _get_kernel_version_windows(),
            "secure_boot": _get_secure_boot_windows(),
            "root_filesystem": _get_root_fs_windows(),
            "disk_uuid": _get_disk_uuid_windows(),
        }
    else:
        # Linux implementation
        def get_root_device():
            try:
                with open("/proc/mounts") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == "/" and re.match(r"^/dev/[a-zA-Z0-9]+$", parts[0]):
                            return parts[0]
            except OSError:
                pass
            return None

        def get_root_fs():
            try:
                with open("/proc/mounts") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == "/" and re.match(r"^[a-z0-9]+$", parts[2]):
                            return parts[2]
            except OSError:
                pass
            return None

        root_device = get_root_device()
        kernel = _run_safe(["uname", "-r"])
        uuid = None
        if root_device:
            uuid_out = _run_safe(["blkid", "-s", "UUID", "-o", "value", root_device])
            if uuid_out and re.match(r"^[0-9a-fA-F\-]+$", uuid_out.strip()):
                uuid = uuid_out.strip()[:40]

        return {
            "boot_device": root_device or "unknown",
            "kernel_version": kernel[:128] if kernel else "unknown",
            "secure_boot": _get_secure_boot_linux(),
            "root_filesystem": get_root_fs() or "unknown",
            "disk_uuid": uuid or "unknown",
        }


def analyze_boot_fingerprint() -> dict:
    indicators = []
    current = collect_current_fingerprint()

    result = {
        "indicators": indicators,
        "current_fingerprint": current,
        "comparison": None,
        "secure_boot": current.get("secure_boot", "unknown"),
    }

    if current.get("secure_boot") == "disabled":
        indicators.append("SECURE_BOOT_DISABLED")

    if not BASELINE_PATH.exists():
        indicators.append("NO_BASELINE_FOUND")
        logger.warning("No baseline found at %s — run baseline_generator.py first", BASELINE_PATH)
        result["indicators"] = indicators
        return result

    try:
        baseline = json.loads(BASELINE_PATH.read_text())
    except Exception as e:
        indicators.append("BASELINE_READ_ERROR")
        logger.error("Cannot read baseline: %s", str(e)[:100])
        result["indicators"] = indicators
        return result

    mismatches = {}
    for field in ["boot_device", "kernel_version", "secure_boot", "root_filesystem", "disk_uuid"]:
        cur = current.get(field, "unknown")
        base = baseline.get(field, "unknown")
        if cur != base and base != "unknown":
            mismatches[field] = {"current": cur, "baseline": base}
            indicators.append(f"FINGERPRINT_MISMATCH:{field.upper()}")

    if baseline.get("secure_boot") == "enabled" and current.get("secure_boot") == "disabled":
        indicators.append("SECURE_BOOT_DISABLED")

    result["comparison"] = {"mismatches": mismatches, "match": len(mismatches) == 0}
    result["indicators"] = indicators
    return result
