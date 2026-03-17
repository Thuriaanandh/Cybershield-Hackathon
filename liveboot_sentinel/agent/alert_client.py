"""
alert_client.py - Securely send alerts to the LiveBoot Sentinel API server.
Uses HTTPS with API key authentication. Supports RAM analysis payload.
"""

import json
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

ALERT_SERVER_URL = os.environ.get("LIVEBOOT_ALERT_URL", "https://localhost:8443/alert")
API_KEY = os.environ.get("LIVEBOOT_API_KEY", "")

REQUEST_TIMEOUT    = 15
MAX_RETRIES        = 3
RETRY_DELAY        = 2

MAX_HOSTNAME_LEN   = 253
MAX_INDICATORS_COUNT = 100
MAX_INDICATOR_LEN  = 200
MAX_KERNEL_LEN     = 256
MAX_OS_LEN         = 100
MAX_BOOT_SOURCE_LEN = 50


def _get_hostname() -> str:
    try:
        hostname = socket.gethostname()
        hostname = re.sub(r"[^a-zA-Z0-9.\-]", "", hostname)
        return hostname[:MAX_HOSTNAME_LEN] or "unknown-host"
    except Exception:
        return "unknown-host"


def _sanitize_string(value: str, max_len: int, allow_re: str = r"^[\w\s.\-:,/\(\)]+$") -> str:
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()[:max_len]
    if not re.match(allow_re, value or "x"):
        value = re.sub(r"[^\w\s.\-:,/()]", "", value)[:max_len]
    return value


def _build_alert_payload(
    boot_source: str,
    kernel: str,
    detected_os: Optional[str],
    risk_score: int,
    indicators: list,
    risk_level: str,
) -> dict:
    hostname  = _get_hostname()
    timestamp = datetime.now(timezone.utc).isoformat()

    boot_source_clean = _sanitize_string(boot_source, MAX_BOOT_SOURCE_LEN)
    kernel_clean      = _sanitize_string(kernel, MAX_KERNEL_LEN, r"^[\w\s.\-+#()@:,/]+$")
    detected_os_clean = _sanitize_string(detected_os or "unknown", MAX_OS_LEN)

    if not isinstance(risk_score, (int, float)):
        risk_score = 0
    risk_score = max(0, min(int(risk_score), 200))

    if not isinstance(indicators, list):
        indicators = []

    clean_indicators = []
    for ind in indicators[:MAX_INDICATORS_COUNT]:
        if isinstance(ind, str):
            ind_clean = re.sub(r"[^\w:.\-]", "", ind)[:MAX_INDICATOR_LEN]
            if ind_clean:
                clean_indicators.append(ind_clean)

    valid_levels = {"NORMAL", "WARNING", "CRITICAL"}
    if risk_level not in valid_levels:
        risk_level = "UNKNOWN"

    return {
        "hostname":          hostname,
        "timestamp":         timestamp,
        "boot_source":       boot_source_clean,
        "kernel":            kernel_clean,
        "detected_os":       detected_os_clean,
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "indicators":        clean_indicators,
        "attack_techniques": {},
        "attack_summary":    "",
        "ram_analysis":      {},
        "ram_dump_file":     "",
    }


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ca_bundle = os.environ.get("LIVEBOOT_CA_BUNDLE", "")
    if ca_bundle and os.path.isfile(ca_bundle):
        ctx.load_verify_locations(ca_bundle)
    if os.environ.get("LIVEBOOT_VERIFY_SSL", "true").lower() == "false":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning("SSL verification disabled — development mode only")
    return ctx


def send_alert(
    boot_source: str,
    kernel: str,
    detected_os: Optional[str],
    risk_score: int,
    indicators: list,
    risk_level: str = "NORMAL",
    ram_analysis: Optional[dict] = None,
) -> bool:
    """
    Send an alert to the API server via HTTPS POST.
    Optionally includes RAM dump analysis results.
    """
    if not API_KEY:
        logger.error("LIVEBOOT_API_KEY not set — cannot send alert")
        return False

    if not ALERT_SERVER_URL.startswith("https://"):
        logger.error("Alert URL must use HTTPS")
        return False

    payload = _build_alert_payload(
        boot_source=boot_source,
        kernel=kernel,
        detected_os=detected_os,
        risk_score=risk_score,
        indicators=indicators,
        risk_level=risk_level,
    )

    # Add RAM analysis — sanitize sensitive fields
    if ram_analysis and isinstance(ram_analysis, dict):
        safe_ram = dict(ram_analysis)

        # SECURITY: Strip actual hash values — only send username + flag
        if "credentials_found" in safe_ram:
            safe_ram["credentials_found"] = [
                {"username": c.get("username", ""), "hash_present": True}
                for c in safe_ram.get("credentials_found", [])[:20]
            ]

        # Cap process list for network efficiency
        if "processes" in safe_ram:
            safe_ram["processes"] = safe_ram["processes"][:100]

        # Cap commands
        if "commands_detected" in safe_ram:
            safe_ram["commands_detected"] = safe_ram["commands_detected"][:50]

        payload["ram_analysis"]  = safe_ram
        payload["ram_dump_file"] = _sanitize_string(
            safe_ram.get("ram_dump_file", "") or "", 200
        )

    payload_bytes = json.dumps(payload).encode("utf-8")
    ssl_context   = _create_ssl_context()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = Request(
                ALERT_SERVER_URL,
                data=payload_bytes,
                method="POST",
                headers={
                    "Content-Type":   "application/json",
                    "X-API-Key":      API_KEY,
                    "User-Agent":     "LiveBootSentinel-Agent/1.0",
                    "Content-Length": str(len(payload_bytes)),
                },
            )

            with urlopen(req, context=ssl_context, timeout=REQUEST_TIMEOUT) as response:
                status = response.status
                if 200 <= status < 300:
                    logger.info(
                        "Alert sent: host=%s score=%d level=%s ram=%s",
                        payload["hostname"], risk_score, risk_level,
                        "yes" if ram_analysis else "no",
                    )
                    return True
                else:
                    logger.warning("Server returned %d (attempt %d)", status, attempt)

        except HTTPError as e:
            logger.warning("HTTP error: %d (attempt %d)", e.code, attempt)
        except URLError as e:
            logger.warning("URL error (attempt %d): %s", attempt, str(e.reason)[:100])
        except ssl.SSLError as e:
            logger.error("SSL error: %s", str(e)[:100])
            return False
        except Exception as e:
            logger.error("Unexpected error (attempt %d): %s", attempt, str(e)[:200])

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * attempt)

    logger.error("Failed to send alert after %d attempts", MAX_RETRIES)
    return False
