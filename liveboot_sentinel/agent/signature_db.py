"""
signature_db.py - OS fingerprint database and matching logic.
Maintains known live OS signatures for identification.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─── OS Fingerprint Database ─────────────────────────────────────────────────
# Structure: { keyword: { label, category, threat_level } }
# threat_level: 1-5 (5 = most concerning)

OS_SIGNATURE_DB: dict[str, dict] = {
    # Penetration Testing
    "kali": {
        "label": "Kali Linux",
        "description": "Penetration Testing OS",
        "category": "penetration_testing",
        "threat_level": 5,
    },
    "parrot": {
        "label": "Parrot OS",
        "description": "Security Testing OS",
        "category": "penetration_testing",
        "threat_level": 4,
    },
    "backtrack": {
        "label": "BackTrack Linux",
        "description": "Legacy Penetration Testing OS",
        "category": "penetration_testing",
        "threat_level": 5,
    },
    "blackarch": {
        "label": "BlackArch Linux",
        "description": "Advanced Security Research OS",
        "category": "penetration_testing",
        "threat_level": 5,
    },
    "pentoo": {
        "label": "Pentoo",
        "description": "Gentoo-based Security OS",
        "category": "penetration_testing",
        "threat_level": 4,
    },
    # Privacy / Anonymity
    "tails": {
        "label": "Tails OS",
        "description": "Anonymous/Privacy OS",
        "category": "anonymity",
        "threat_level": 4,
    },
    "whonix": {
        "label": "Whonix",
        "description": "Anonymization OS",
        "category": "anonymity",
        "threat_level": 3,
    },
    # Forensics
    "deft": {
        "label": "DEFT Linux",
        "description": "Digital Evidence & Forensics Toolkit",
        "category": "forensics",
        "threat_level": 3,
    },
    "remnux": {
        "label": "REMnux",
        "description": "Malware Analysis OS",
        "category": "forensics",
        "threat_level": 3,
    },
    "caine": {
        "label": "CAINE",
        "description": "Computer Aided Investigation Environment",
        "category": "forensics",
        "threat_level": 3,
    },
    # Generic Live Environments
    "ubuntu": {
        "label": "Ubuntu Live",
        "description": "Ubuntu Live Environment",
        "category": "live_environment",
        "threat_level": 2,
    },
    "debian": {
        "label": "Debian Live",
        "description": "Debian Live Environment",
        "category": "live_environment",
        "threat_level": 2,
    },
    "fedora": {
        "label": "Fedora Live",
        "description": "Fedora Live Environment",
        "category": "live_environment",
        "threat_level": 2,
    },
    "manjaro": {
        "label": "Manjaro Live",
        "description": "Manjaro Live Environment",
        "category": "live_environment",
        "threat_level": 2,
    },
    # Indicators (not full OS names but strong signals)
    "casper": {
        "label": "Casper Live Boot",
        "description": "Ubuntu/Debian Casper Live Boot System",
        "category": "live_environment",
        "threat_level": 2,
    },
    "live": {
        "label": "Generic Live OS",
        "description": "Generic Live Boot Environment",
        "category": "live_environment",
        "threat_level": 2,
    },
    "persistence": {
        "label": "Persistent Live OS",
        "description": "Live OS with Persistence Layer",
        "category": "live_environment",
        "threat_level": 3,
    },
}


def lookup_os(name: str) -> Optional[dict]:
    """
    Look up an OS name in the signature database.

    Args:
        name: OS name or keyword string (case-insensitive)

    Returns:
        Signature dict or None if not found.
    """
    if not name or not isinstance(name, str):
        return None

    # Sanitize: lowercase, strip, limit length
    name_clean = name.lower().strip()[:64]

    # Remove non-alphanumeric except hyphens/spaces for safe lookup
    name_safe = re.sub(r"[^a-z0-9\-\s]", "", name_clean)

    return OS_SIGNATURE_DB.get(name_safe)


def match_os_from_text(text: str) -> Optional[dict]:
    """
    Scan a text string for any known OS signature keyword.

    Returns:
        Best-matching signature dict or None.
        Prioritizes highest threat_level match.
    """
    if not text or not isinstance(text, str):
        return None

    text_clean = text.lower()[:1024]
    best_match = None
    best_threat = -1

    for keyword, signature in OS_SIGNATURE_DB.items():
        if keyword in text_clean:
            threat = signature.get("threat_level", 0)
            if threat > best_threat:
                best_threat = threat
                best_match = {**signature, "matched_keyword": keyword}

    return best_match


def get_all_signatures() -> dict:
    """Return a copy of the full signature database."""
    return dict(OS_SIGNATURE_DB)


def get_threat_level(os_name: str) -> int:
    """
    Get threat level (1-5) for an OS name.
    Returns 0 if not found.
    """
    sig = lookup_os(os_name) or match_os_from_text(os_name)
    if sig:
        return sig.get("threat_level", 0)
    return 0
