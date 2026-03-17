"""
baseline_generator.py - Generate a boot fingerprint baseline for comparison.
Run once on a known-good system state to create the reference baseline.
Windows and Linux compatible.
"""

import json
import logging
import os
import sys
import platform
from pathlib import Path

# Allow running standalone or as module
sys.path.insert(0, str(Path(__file__).parent))

from boot_fingerprint import collect_current_fingerprint

logger = logging.getLogger(__name__)

# Use user home directory on Windows, /etc on Linux
if platform.system() == "Windows":
    BASELINE_DIR = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "liveboot_sentinel"
else:
    BASELINE_DIR = Path("/etc/liveboot_sentinel")

BASELINE_PATH = BASELINE_DIR / "baseline.json"


def _check_root() -> bool:
    """
    Check for admin/root privileges.
    Works on both Windows and Linux.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return True  # Cannot check — proceed anyway
    else:
        return os.geteuid() == 0


def _ensure_baseline_dir() -> bool:
    """Create baseline directory."""
    try:
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        return True
    except PermissionError:
        logger.error("Cannot create baseline directory — permission denied")
        return False
    except OSError as e:
        logger.error("Cannot create baseline directory: %s", str(e)[:200])
        return False


def generate_baseline(force: bool = False) -> bool:
    """
    Collect and store the current boot fingerprint as the baseline.

    Args:
        force: If True, overwrite existing baseline without prompt.

    Returns:
        True if baseline was successfully written.
    """
    if BASELINE_PATH.exists() and not force:
        print(f"[WARNING] Baseline already exists at {BASELINE_PATH}")
        response = input("Overwrite existing baseline? [y/N]: ").strip().lower()
        if response != "y":
            print("Baseline generation cancelled.")
            return False

    if not _ensure_baseline_dir():
        return False

    print("[*] Collecting current boot fingerprint...")
    fingerprint = collect_current_fingerprint()

    print(f"[*] Boot device:      {fingerprint.get('boot_device', 'unknown')}")
    print(f"[*] Kernel version:   {fingerprint.get('kernel_version', 'unknown')}")
    print(f"[*] Secure Boot:      {fingerprint.get('secure_boot', 'unknown')}")
    print(f"[*] Root filesystem:  {fingerprint.get('root_filesystem', 'unknown')}")
    print(f"[*] Disk UUID:        {fingerprint.get('disk_uuid', 'unknown')}")

    # Write baseline
    try:
        tmp_path = BASELINE_PATH.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(fingerprint, f, indent=2)
        # Rename is atomic on both Windows and Linux
        if BASELINE_PATH.exists():
            BASELINE_PATH.unlink()
        tmp_path.rename(BASELINE_PATH)

        print(f"\n[+] Baseline written to: {BASELINE_PATH}")
        logger.info("Boot fingerprint baseline generated at %s", BASELINE_PATH)
        return True

    except PermissionError:
        logger.error("Cannot write baseline file — permission denied")
        print("[ERROR] Cannot write baseline file.")
        return False
    except OSError as e:
        logger.error("Cannot write baseline: %s", str(e)[:200])
        print(f"[ERROR] Cannot write baseline: {str(e)[:100]}")
        return False


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    import argparse
    parser = argparse.ArgumentParser(description="LiveBoot Sentinel — Baseline Generator")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing baseline without confirmation",
    )
    args = parser.parse_args()

    success = generate_baseline(force=args.force)
    sys.exit(0 if success else 1)
