"""
alert_deduplicator.py - Prevent sending duplicate alerts.
Only sends a new alert if the indicators have meaningfully changed
since the last alert was sent.
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

if os.name == "nt":
    STATE_PATH = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "liveboot_sentinel" / "alert_state.json"
else:
    STATE_PATH = Path("/var/lib/liveboot_sentinel/alert_state.json")

# Minimum time between identical alerts (seconds)
MIN_ALERT_INTERVAL = 300  # 5 minutes
# Minimum time between ANY alerts regardless of content (seconds)
MIN_ANY_ALERT_INTERVAL = 60  # 1 minute


def _load_state() -> dict:
    try:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
    except Exception:
        pass
    return {
        "last_alert_hash": "",
        "last_alert_time": 0,
        "last_indicators": [],
    }


def _save_state(state: dict) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state))
    except Exception as e:
        logger.warning("Cannot save alert state: %s", str(e)[:100])


def _hash_indicators(indicators: list) -> str:
    """Create a hash of the current indicator set."""
    sorted_inds = sorted(set(indicators))
    return hashlib.sha256(json.dumps(sorted_inds).encode()).hexdigest()[:16]


def should_send_alert(indicators: list, risk_score: int) -> bool:
    """
    Determine if an alert should be sent based on deduplication rules.

    Returns True if alert should be sent, False if it's a duplicate.
    """
    state = _load_state()
    now = time.time()

    current_hash = _hash_indicators(indicators)
    time_since_last = now - state.get("last_alert_time", 0)

    # Always send if score is 200 and no alert sent in last minute
    if risk_score >= 200 and time_since_last < MIN_ANY_ALERT_INTERVAL:
        logger.debug("Suppressing duplicate alert — sent %ds ago", int(time_since_last))
        return False

    # Check if indicators are the same as last alert
    if current_hash == state.get("last_alert_hash", ""):
        if time_since_last < MIN_ALERT_INTERVAL:
            logger.debug(
                "Suppressing identical alert — same indicators, sent %ds ago",
                int(time_since_last)
            )
            return False

    # Check for NEW indicators not in previous alert
    prev_indicators = set(state.get("last_indicators", []))
    current_indicators = set(indicators)
    new_indicators = current_indicators - prev_indicators

    if not new_indicators and time_since_last < MIN_ALERT_INTERVAL:
        logger.debug("No new indicators since last alert — suppressing")
        return False

    return True


def record_alert_sent(indicators: list) -> None:
    """Record that an alert was sent with these indicators."""
    state = {
        "last_alert_hash": _hash_indicators(indicators),
        "last_alert_time": time.time(),
        "last_indicators": list(indicators),
    }
    _save_state(state)


def get_new_indicators(indicators: list) -> list:
    """Return only indicators that are new since the last alert."""
    state = _load_state()
    prev = set(state.get("last_indicators", []))
    return [i for i in indicators if i not in prev]
