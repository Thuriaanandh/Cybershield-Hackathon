"""
risk_engine.py - Aggregate all detection indicators and compute a risk score.
Applies weighted scoring and returns risk level classification.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from signature_db import get_threat_level

logger = logging.getLogger(__name__)

# ─── Risk Score Weights ───────────────────────────────────────────────────────
INDICATOR_WEIGHTS: dict[str, int] = {
    # Boot source
    "USB_BOOT_DETECTED": 40,
    "BOOT_SOURCE_UNKNOWN": 20,

    # Kernel fingerprint
    "LIVE_OS_KERNEL:KALI_LINUX": 30,
    "LIVE_OS_KERNEL:TAILS_OS": 30,
    "LIVE_OS_KERNEL:PARROT_OS": 30,
    "LIVE_OS_KERNEL:GENERIC_LIVE_ENVIRONMENT": 25,
    "LIVE_OS_KERNEL:UBUNTU/CASPER_LIVE": 20,
    "LIVE_OS_KERNEL:PERSISTENT_LIVE_OS": 25,
    "LIVE_OS_KERNEL:BLACKARCH_LINUX": 30,
    "LIVE_OS_KERNEL:REMNUX": 25,
    "LIVE_OS_KERNEL:WHONIX": 25,
    "KERNEL_READ_FAILED": 10,

    # Cmdline
    "LIVE_CMDLINE:BOOT=LIVE": 25,
    "LIVE_CMDLINE:CASPER": 20,
    "LIVE_CMDLINE:PERSISTENCE": 25,
    "LIVE_CMDLINE:TORAM": 20,
    "LIVE_CMDLINE:LIVE": 20,

    # Disk monitor
    "SQUASHFS_MOUNT_DETECTED": 30,
    "TMPFS_ROOT_DETECTED": 35,
    "OVERLAY_FS_DETECTED:OVERLAY": 20,
    "OVERLAY_FS_DETECTED:AUFS": 20,
    "OVERLAY_FS_DETECTED:OVERLAYFS": 20,
    "OVERLAY_FS_DETECTED:UNIONFS": 20,

    # Boot fingerprint
    "FINGERPRINT_MISMATCH:BOOT_DEVICE": 30,
    "FINGERPRINT_MISMATCH:KERNEL_VERSION": 20,
    "FINGERPRINT_MISMATCH:SECURE_BOOT": 25,
    "FINGERPRINT_MISMATCH:ROOT_FILESYSTEM": 25,
    "FINGERPRINT_MISMATCH:DISK_UUID": 30,
    "SECURE_BOOT_DISABLED": 20,
    "NO_BASELINE_FOUND": 5,
    "BASELINE_READ_ERROR": 10,

    # UEFI
    "USB_UEFI_BOOT_ENTRY": 35,
    "USB_FIRST_IN_BOOT_ORDER": 35,
    "UEFI_DATA_UNAVAILABLE": 5,

    # Log integrity
    "LOG_TAMPERING_DETECTED": 50,

    # Internal disk mounts
    "INTERNAL_DISK_SUSPICIOUS_MOUNT": 15,
}

# Prefix-based weight lookup (for parameterized indicators like USB_UEFI_BOOT_ENTRY:*)
PREFIX_WEIGHTS: dict[str, int] = {
    "USB_UEFI_BOOT_ENTRY": 35,
    "LIVE_OS_KERNEL": 28,
    "FINGERPRINT_MISMATCH": 25,
    "LIVE_CMDLINE": 20,
    "OVERLAY_FS_DETECTED": 20,
    "INTERNAL_DISK_SUSPICIOUS_MOUNT": 15,
    "LOOP_DEVICES_ACTIVE": 10,
}

# Risk level thresholds
RISK_THRESHOLDS = {
    "NORMAL": (0, 30),
    "WARNING": (30, 50),
    "CRITICAL": (50, float("inf")),
}

# Maximum cap for risk score (avoid integer overflow with many indicators)
MAX_SCORE = 200


@dataclass
class RiskResult:
    """Result of risk engine computation."""
    score: int
    level: str  # NORMAL, WARNING, CRITICAL
    indicators: list[str]
    weighted_hits: list[dict]
    detected_os: Optional[str] = None
    details: dict = field(default_factory=dict)


def _score_indicator(indicator: str) -> int:
    """
    Return weight for a single indicator.
    First tries exact match, then prefix match.
    """
    # Exact match
    if indicator in INDICATOR_WEIGHTS:
        return INDICATOR_WEIGHTS[indicator]

    # Prefix match (e.g., "USB_UEFI_BOOT_ENTRY:Ubuntu Live")
    prefix = indicator.split(":")[0]
    if prefix in PREFIX_WEIGHTS:
        return PREFIX_WEIGHTS[prefix]

    # Unknown indicator — small default weight
    return 5


def _determine_risk_level(score: int) -> str:
    """Return risk level string based on score."""
    if score < 30:
        return "NORMAL"
    elif score < 50:
        return "WARNING"
    else:
        return "CRITICAL"


def compute_risk_score(
    all_indicators: list[str],
    detected_os: Optional[str] = None,
) -> RiskResult:
    """
    Compute risk score from all aggregated indicators.

    Args:
        all_indicators: Deduplicated list of indicator strings from all modules.
        detected_os: Optional OS name detected by kernel/signature modules.

    Returns:
        RiskResult dataclass.
    """
    if not isinstance(all_indicators, list):
        logger.error("Invalid indicators type: %s", type(all_indicators))
        all_indicators = []

    total_score = 0
    weighted_hits = []
    seen_prefixes = set()

    # Deduplicate by prefix to avoid double-counting similar indicators
    unique_indicators = []
    for ind in all_indicators:
        prefix = ind.split(":")[0]
        if prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            unique_indicators.append(ind)

    for indicator in unique_indicators:
        weight = _score_indicator(indicator)
        total_score += weight
        weighted_hits.append({
            "indicator": indicator,
            "weight": weight,
        })

    # Bonus score from OS threat level
    if detected_os:
        threat = get_threat_level(detected_os)
        if threat > 0:
            os_bonus = threat * 5  # Max +25 from OS threat level
            total_score += os_bonus
            weighted_hits.append({
                "indicator": f"OS_THREAT_LEVEL:{detected_os}",
                "weight": os_bonus,
            })

    # Cap score
    final_score = min(total_score, MAX_SCORE)
    risk_level = _determine_risk_level(final_score)

    logger.info(
        "Risk computation: score=%d level=%s indicators=%d",
        final_score, risk_level, len(unique_indicators)
    )

    return RiskResult(
        score=final_score,
        level=risk_level,
        indicators=unique_indicators,
        weighted_hits=weighted_hits,
        detected_os=detected_os,
        details={
            "raw_score": total_score,
            "capped": total_score > MAX_SCORE,
            "indicator_count": len(unique_indicators),
        },
    )
