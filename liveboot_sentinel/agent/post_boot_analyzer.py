"""
post_boot_analyzer.py - Aggregate all post-boot attack indicators
into a forensic timeline and attack summary.
Windows and Linux compatible.
"""

import logging
import platform
from datetime import datetime, timezone
from typing import Optional

from file_integrity_monitor import analyze_file_integrity
from credential_access_detector import detect_credential_access
from network_anomaly_detector import detect_network_anomalies
from persistence_detector import detect_persistence

logger = logging.getLogger(__name__)

# Attack technique categories mapped to indicator prefixes
ATTACK_TECHNIQUES = {
    "Credential Access": [
        "CREDENTIAL_TOOL_RUNNING",
        "LSASS_ACCESS_DETECTED",
        "SAM_DATABASE_ACCESS_DETECTED",
        "CREDENTIAL_REGISTRY_ACCESS",
        "SHADOW_FILE_RECENTLY_ACCESSED",
        "CREDENTIAL_TOOL_IN_HISTORY",
    ],
    "Persistence": [
        "SUSPICIOUS_SCHEDULED_TASK",
        "SUSPICIOUS_REGISTRY_RUN",
        "SUSPICIOUS_SERVICE_FOUND",
        "WMI_PERSISTENCE_DETECTED",
        "CRONTAB_RECENTLY_MODIFIED",
        "RC_LOCAL_HAS_COMMANDS",
        "SSH_AUTHORIZED_KEYS_RECENTLY_MODIFIED",
    ],
    "Defense Evasion": [
        "STARTUP_FOLDER_MODIFIED",
        "NEW_SUID_BINARY",
        "SUSPICIOUS_SERVICE_RUNNING",
    ],
    "Exfiltration": [
        "LARGE_DATA_TRANSFER_DETECTED",
        "SUSPICIOUS_DNS_LOOKUP",
        "C2_PORT_DETECTED",
    ],
    "Discovery": [
        "PORT_SCAN_DETECTED",
        "HIGH_EXTERNAL_CONNECTION_COUNT",
        "SUSPICIOUS_PORT_ACTIVE",
    ],
    "Execution": [
        "SUSPICIOUS_FILE_FOUND",
        "SUSPICIOUS_EXTENSION",
    ],
    "Impact": [
        "SUSPICIOUS_ACCOUNT_FOUND",
        "SENSITIVE_FILE_ACCESS",
        "SENSITIVE_FILE_RECENTLY_MODIFIED",
    ],
}

# Additional risk scores for post-boot attack indicators
POST_BOOT_WEIGHTS = {
    "CREDENTIAL_TOOL_RUNNING":           50,
    "LSASS_ACCESS_DETECTED":             50,
    "SAM_DATABASE_ACCESS_DETECTED":      45,
    "CREDENTIAL_REGISTRY_ACCESS":        40,
    "SHADOW_FILE_RECENTLY_ACCESSED":     40,
    "WMI_PERSISTENCE_DETECTED":          40,
    "SUSPICIOUS_REGISTRY_RUN":           35,
    "SUSPICIOUS_SCHEDULED_TASK":         35,
    "LARGE_DATA_TRANSFER_DETECTED":      40,
    "C2_PORT_DETECTED":                  45,
    "PORT_SCAN_DETECTED":                30,
    "SUSPICIOUS_FILE_FOUND":             35,
    "SENSITIVE_FILE_ACCESS":             40,
    "SUSPICIOUS_ACCOUNT_FOUND":          45,
    "SSH_AUTHORIZED_KEYS_RECENTLY_MODIFIED": 35,
    "SUSPICIOUS_SERVICE_FOUND":          35,
    "NEW_SUID_BINARY":                   30,
    "STARTUP_FOLDER_MODIFIED":           30,
    "SUSPICIOUS_PORT_ACTIVE":            25,
    "SUSPICIOUS_DNS_LOOKUP":             25,
    "HIGH_EXTERNAL_CONNECTION_COUNT":    20,
    "CRONTAB_RECENTLY_MODIFIED":         25,
    "SENSITIVE_FILE_RECENTLY_MODIFIED":  30,
    "SUSPICIOUS_EXTENSION":              20,
    "CREDENTIAL_TOOL_IN_HISTORY":        30,
}


def _identify_attack_techniques(indicators: list) -> dict:
    """Map indicators to MITRE ATT&CK-style technique categories."""
    identified = {}
    for indicator in indicators:
        prefix = indicator.split(":")[0]
        for technique, prefixes in ATTACK_TECHNIQUES.items():
            if prefix in prefixes:
                if technique not in identified:
                    identified[technique] = []
                identified[technique].append(indicator)
    return identified


def _compute_post_boot_score(indicators: list) -> int:
    """Compute additional risk score from post-boot indicators."""
    score = 0
    seen_prefixes = set()
    for ind in indicators:
        prefix = ind.split(":")[0]
        if prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            score += POST_BOOT_WEIGHTS.get(prefix, 10)
    return min(score, 200)


def run_post_boot_analysis() -> dict:
    """
    Run all post-boot attack detection modules and return
    a comprehensive forensic analysis.

    Returns:
        dict with:
            - indicators: all post-boot indicators
            - attack_techniques: MITRE-mapped technique categories
            - post_boot_score: additional risk score
            - timeline: ordered list of detected events
            - details: per-module results
            - summary: human-readable attack summary
    """
    all_indicators = []
    details = {}
    timeline = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # Run all post-boot modules
    modules = [
        ("file_integrity",   analyze_file_integrity),
        ("credential_access", detect_credential_access),
        ("network_anomaly",  detect_network_anomalies),
        ("persistence",      detect_persistence),
    ]

    for module_name, module_fn in modules:
        try:
            result = module_fn()
            module_indicators = result.get("indicators", [])
            details[module_name] = result
            all_indicators.extend(module_indicators)

            # Add to timeline
            for ind in module_indicators:
                timeline.append({
                    "timestamp": timestamp,
                    "module": module_name,
                    "indicator": ind,
                })
            logger.debug("Module %s: %d indicators", module_name, len(module_indicators))
        except Exception as e:
            logger.error("Post-boot module %s failed: %s", module_name, str(e)[:200])

    # Deduplicate
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    # Map to attack techniques
    attack_techniques = _identify_attack_techniques(unique_indicators)

    # Compute additional score
    post_boot_score = _compute_post_boot_score(unique_indicators)

    # Build human-readable summary
    summary_parts = []
    if attack_techniques:
        summary_parts.append(f"Detected {len(attack_techniques)} attack technique(s):")
        for technique, inds in attack_techniques.items():
            summary_parts.append(f"  [{technique}] — {len(inds)} indicator(s)")
    else:
        summary_parts.append("No post-boot attack indicators detected.")

    return {
        "indicators": unique_indicators,
        "attack_techniques": attack_techniques,
        "post_boot_score": post_boot_score,
        "timeline": timeline,
        "details": details,
        "summary": "\n".join(summary_parts),
        "techniques_count": len(attack_techniques),
    }
