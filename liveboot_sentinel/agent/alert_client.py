"""
alert_client.py - Securely send alerts to the LiveBoot Sentinel API server.
Uses HTTPS with API key authentication and input validation.
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

# Environment-based configuration (never hardcode secrets)
ALERT_SERVER_URL = os.environ.get("LIVEBOOT_ALERT_URL", "https://localhost:8443/alert")
API_KEY = os.environ.get("LIVEBOOT_API_KEY", "")

# Request settings
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# Validation limits
MAX_HOSTNAME_LEN = 253
MAX_INDICATORS_COUNT = 100
MAX_INDICATOR_LEN = 200
MAX_KERNEL_LEN = 256
MAX_OS_LEN = 100
MAX_BOOT_SOURCE_LEN = 50


def _get_hostname() -> str:
    """
    Get the system hostname safely.
    Returns sanitized hostname string.
    """
    try:
        hostname = socket.gethostname()
        # Sanitize: only allow valid hostname characters
        hostname = re.sub(r"[^a-zA-Z0-9.\-]", "", hostname)
        return hostname[:MAX_HOSTNAME_LEN] or "unknown-host"
    except Exception:
        return "unknown-host"


def _sanitize_string(value: str, max_len: int, allow_re: str = r"^[\w\s.\-:,/\(\)]+$") -> str:
    """
    Sanitize a string field: strip, limit length, validate characters.
    """
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()[:max_len]
    if not re.match(allow_re, value or "x"):
        # Strip unsafe characters
        value = re.sub(r"[^\w\s.\-:,/()]", "", value)[:max_len]
    return value


def _build_alert_payload(
    boot_source: str,
    kernel: str,
    detected_os: Optional[str],
    risk_score: int,
    indicators: list[str],
    risk_level: str,
) -> dict:
    """
    Build and validate alert payload before sending.
    All fields are sanitized and validated.
    """
    hostname = _get_hostname()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Validate and sanitize each field
    boot_source_clean = _sanitize_string(boot_source, MAX_BOOT_SOURCE_LEN)
    kernel_clean = _sanitize_string(kernel, MAX_KERNEL_LEN, r"^[\w\s.\-+#()@:,/]+$")
    detected_os_clean = _sanitize_string(detected_os or "unknown", MAX_OS_LEN)

    # Validate risk score is numeric and in range
    if not isinstance(risk_score, (int, float)):
        risk_score = 0
    risk_score = max(0, min(int(risk_score), 200))

    # Sanitize indicators list
    if not isinstance(indicators, list):
        indicators = []

    clean_indicators = []
    for ind in indicators[:MAX_INDICATORS_COUNT]:
        if isinstance(ind, str):
            ind_clean = re.sub(r"[^\w:.\-]", "", ind)[:MAX_INDICATOR_LEN]
            if ind_clean:
                clean_indicators.append(ind_clean)

    # Validate risk level
    valid_levels = {"NORMAL", "WARNING", "CRITICAL"}
    if risk_level not in valid_levels:
        risk_level = "UNKNOWN"

    return {
        "hostname": hostname,
        "timestamp": timestamp,
        "boot_source": boot_source_clean,
        "kernel": kernel_clean,
        "detected_os": detected_os_clean,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": clean_indicators,
    }


def _create_ssl_context() -> ssl.SSLContext:
    """
    Create a hardened SSL context for HTTPS connections.
    """
    ctx = ssl.create_default_context()
    # Enforce minimum TLS 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Verify certificates (set LIVEBOOT_CA_BUNDLE env var for custom CA)
    ca_bundle = os.environ.get("LIVEBOOT_CA_BUNDLE", "")
    if ca_bundle and os.path.isfile(ca_bundle):
        ctx.load_verify_locations(ca_bundle)
    # Allow self-signed in dev mode (controlled by env, not hardcoded)
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
    indicators: list[str],
    risk_level: str = "NORMAL",
) -> bool:
    """
    Send an alert to the API server via HTTPS POST.

    Args:
        boot_source: Boot source string ('usb', 'disk', 'unknown')
        kernel: Kernel version string
        detected_os: Detected OS name or None
        risk_score: Computed risk score
        indicators: List of indicator strings
        risk_level: Risk level string (NORMAL/WARNING/CRITICAL)

    Returns:
        True if alert was successfully delivered, False otherwise.
    """
    if not API_KEY:
        logger.error("LIVEBOOT_API_KEY environment variable not set — cannot send alert")
        return False

    if not ALERT_SERVER_URL.startswith("https://"):
        logger.error("Alert URL must use HTTPS — refusing to send over plain HTTP")
        return False

    payload = _build_alert_payload(
        boot_source=boot_source,
        kernel=kernel,
        detected_os=detected_os,
        risk_score=risk_score,
        indicators=indicators,
        risk_level=risk_level,
    )

    payload_bytes = json.dumps(payload).encode("utf-8")

    ssl_context = _create_ssl_context()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = Request(
                ALERT_SERVER_URL,
                data=payload_bytes,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": API_KEY,
                    "User-Agent": "LiveBootSentinel-Agent/1.0",
                    "Content-Length": str(len(payload_bytes)),
                },
            )

            with urlopen(req, context=ssl_context, timeout=REQUEST_TIMEOUT) as response:
                status = response.status
                if 200 <= status < 300:
                    logger.info(
                        "Alert sent successfully: host=%s score=%d level=%s",
                        payload["hostname"], risk_score, risk_level
                    )
                    return True
                else:
                    logger.warning("Alert server returned status %d (attempt %d)", status, attempt)

        except HTTPError as e:
            # SECURITY: Do not log response body (may contain sensitive server info)
            logger.warning("HTTP error sending alert: status=%d (attempt %d)", e.code, attempt)
        except URLError as e:
            logger.warning("URL error sending alert (attempt %d): %s", attempt, str(e.reason)[:100])
        except ssl.SSLError as e:
            logger.error("SSL error sending alert: %s", str(e)[:100])
            return False  # Don't retry SSL failures
        except Exception as e:
            logger.error("Unexpected error sending alert (attempt %d): %s", attempt, str(e)[:200])

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY * attempt)  # Exponential backoff

    logger.error("Failed to send alert after %d attempts", MAX_RETRIES)
    return False
