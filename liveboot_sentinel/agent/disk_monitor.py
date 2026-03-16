"""
disk_monitor.py - Analyze mount points and detect abnormal disk behavior.
Windows and Linux compatible.
"""

import logging
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

VIRTUAL_FILESYSTEMS = {
    "sysfs", "proc", "devtmpfs", "devpts", "tmpfs", "cgroup",
    "cgroup2", "pstore", "efivarfs", "debugfs", "securityfs",
    "fusectl", "hugetlbfs", "mqueue", "tracefs", "bpf",
}

SUSPICIOUS_MOUNT_PREFIXES = ["/media", "/mnt", "/run/media"]
LIVE_FS_TYPES = {"squashfs", "overlayfs", "aufs", "unionfs"}


def _run_safe(args: list, timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _analyze_windows() -> dict:
    """Analyze disk mounts on Windows using PowerShell."""
    indicators = []
    details = {}
    suspicious_mounts = []

    # Get all volumes and drives
    ps_cmd = (
        "Get-WmiObject Win32_LogicalDisk | "
        "Select-Object DeviceID,DriveType,FileSystem,VolumeName,Size | "
        "ConvertTo-Json"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])

    if output:
        details["volumes"] = output[:500]
        output_lower = output.lower()

        # DriveType 2 = Removable, 5 = CD/DVD
        if '"drivetype":  2' in output_lower or '"drivetype": 2' in output_lower:
            indicators.append("REMOVABLE_DRIVE_PRESENT")

        # Check for live OS filesystem names
        for fs in ["squashfs", "live", "casper"]:
            if fs in output_lower:
                indicators.append(f"LIVE_FS_DETECTED:{fs.upper()}")

        # Check volume names for live OS indicators
        for keyword in ["kali", "tails", "parrot", "live", "persistence"]:
            if keyword in output_lower:
                indicators.append(f"LIVE_VOLUME_NAME:{keyword.upper()}")

    return {
        "indicators": indicators,
        "details": details,
        "suspicious_mounts": suspicious_mounts,
    }


def _analyze_linux() -> dict:
    """Analyze mounts on Linux via /proc/mounts."""
    indicators = []
    details = {}
    suspicious_mounts = []

    try:
        with open("/proc/mounts", "r") as f:
            mounts = [line.strip().split() for line in f if line.strip()]
    except OSError as e:
        logger.error("Cannot read /proc/mounts: %s", str(e)[:100])
        return {"indicators": indicators, "details": details, "suspicious_mounts": suspicious_mounts}

    squashfs_count = 0
    overlay_count = 0

    for parts in mounts:
        if len(parts) < 3:
            continue
        device, mountpoint, fstype = parts[0], parts[1], parts[2].lower()

        if fstype in VIRTUAL_FILESYSTEMS:
            continue

        if fstype == "squashfs":
            squashfs_count += 1
            indicators.append("SQUASHFS_MOUNT_DETECTED")

        if fstype in {"overlay", "overlayfs", "aufs", "unionfs"}:
            overlay_count += 1
            indicators.append(f"OVERLAY_FS_DETECTED:{fstype.upper()}")

        if mountpoint == "/" and fstype == "tmpfs":
            indicators.append("TMPFS_ROOT_DETECTED")

        if device.startswith("/dev/") and any(mountpoint.startswith(p) for p in SUSPICIOUS_MOUNT_PREFIXES):
            suspicious_mounts.append({"device": device, "mountpoint": mountpoint})
            indicators.append(f"INTERNAL_DISK_SUSPICIOUS_MOUNT:{mountpoint[:50]}")

    details["squashfs_count"] = squashfs_count
    details["overlay_count"] = overlay_count

    # Deduplicate
    seen = set()
    unique = []
    for ind in indicators:
        key = ind.split(":")[0]
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    return {"indicators": unique, "details": details, "suspicious_mounts": suspicious_mounts}


def analyze_mounts() -> dict:
    if platform.system() == "Windows":
        return _analyze_windows()
    return _analyze_linux()
