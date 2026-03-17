"""
tamper_evident_logger.py - Append-only, tamper-evident log system.
Each log entry is SHA256 hash-chained to the previous entry.
Windows and Linux compatible.
"""

import hashlib
import json
import logging
import os
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Log path — Windows uses user home, Linux uses /var/log
if platform.system() == "Windows":
    LOG_PATH = Path(os.environ.get("USERPROFILE", "C:\\Users\\Public")) / "liveboot_sentinel" / "liveboot_sentinel.log"
else:
    LOG_PATH = Path("/var/log/liveboot_sentinel.log")

MAX_LOG_SIZE_BYTES = 50 * 1024 * 1024
GENESIS_HASH = "0" * 64


def _sanitize_event(event: str) -> str:
    if not isinstance(event, str):
        event = str(event)
    event = re.sub(r"[\x00-\x1f\x7f]", " ", event)
    return event[:500]


def _compute_hash(previous_hash: str, log_entry_json: str) -> str:
    data = (previous_hash + log_entry_json).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _get_last_hash() -> str:
    if not LOG_PATH.exists():
        return GENESIS_HASH
    last_hash = GENESIS_HASH
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    h = entry.get("current_hash", "")
                    if re.match(r"^[0-9a-f]{64}$", h):
                        last_hash = h
                except Exception:
                    continue
    except OSError:
        pass
    return last_hash


def _ensure_log_dir() -> bool:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        return True
    except OSError as e:
        logger.error("Cannot create log directory: %s", str(e)[:100])
        return False


def log_event(event: str, risk_score: int = 0) -> Optional[dict]:
    if not _ensure_log_dir():
        return None

    event_clean = _sanitize_event(event)
    risk_score = max(0, min(int(risk_score) if isinstance(risk_score, (int, float)) else 0, 200))

    previous_hash = _get_last_hash()
    timestamp = datetime.now(timezone.utc).isoformat()

    entry_without_hash = {
        "timestamp": timestamp,
        "event": event_clean,
        "risk_score": risk_score,
        "previous_hash": previous_hash,
    }

    entry_json_for_hash = json.dumps(entry_without_hash, separators=(",", ":"), sort_keys=True)
    current_hash = _compute_hash(previous_hash, entry_json_for_hash)
    final_entry = {**entry_without_hash, "current_hash": current_hash}

    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(final_entry, separators=(",", ":")) + "\n")
        return final_entry
    except OSError as e:
        logger.error("Cannot write to log: %s", str(e)[:100])
        return None


def verify_log_integrity() -> dict:
    result = {"valid": True, "total_entries": 0, "tampered_entries": [], "indicators": []}

    if not LOG_PATH.exists():
        return result

    expected_previous_hash = GENESIS_HASH
    line_num = 0
    tampered = []

    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                line_num += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    tampered.append((line_num, "INVALID_JSON"))
                    continue

                required = {"timestamp", "event", "risk_score", "previous_hash", "current_hash"}
                if not required.issubset(entry.keys()):
                    tampered.append((line_num, "MISSING_FIELDS"))
                    continue

                if entry["previous_hash"] != expected_previous_hash:
                    tampered.append((line_num, "CHAIN_BREAK"))

                entry_for_hash = {k: entry[k] for k in ["timestamp", "event", "risk_score", "previous_hash"]}
                entry_json = json.dumps(entry_for_hash, separators=(",", ":"), sort_keys=True)
                recomputed = _compute_hash(entry["previous_hash"], entry_json)

                if recomputed != entry["current_hash"]:
                    tampered.append((line_num, "HASH_MISMATCH"))

                expected_previous_hash = entry["current_hash"]

    except OSError:
        result["valid"] = False
        result["indicators"] = ["LOG_TAMPERING_DETECTED"]
        return result

    result["total_entries"] = line_num
    result["tampered_entries"] = tampered[:50]

    if tampered:
        result["valid"] = False
        result["indicators"].append("LOG_TAMPERING_DETECTED")
        logger.critical("LOG INTEGRITY FAILURE: %d tampered entries detected", len(tampered))

    return result
