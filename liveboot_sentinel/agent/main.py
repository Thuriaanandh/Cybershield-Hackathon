"""
main.py - LiveBoot Sentinel endpoint agent main loop.
Runs all detection modules every 10 seconds and triggers alerts on high risk.
"""

import logging
import signal
import sys
import time
from pathlib import Path

# Allow running from agent directory
sys.path.insert(0, str(Path(__file__).parent))

from boot_detector import detect_boot_source
from kernel_fingerprint import get_kernel_fingerprint
from disk_monitor import analyze_mounts
from boot_fingerprint import analyze_boot_fingerprint
from uefi_monitor import analyze_uefi
from risk_engine import compute_risk_score
from alert_client import send_alert
from tamper_evident_logger import log_event, verify_log_integrity

# ─── Logging Configuration ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("liveboot_sentinel.main")

# ─── Configuration ────────────────────────────────────────────────────────────
SCAN_INTERVAL_SECONDS = 10
ALERT_RISK_THRESHOLD = 50       # Trigger alert if score > this
WARN_RISK_THRESHOLD = 30        # Log warning if score > this

# ─── Graceful Shutdown ────────────────────────────────────────────────────────
_shutdown_requested = False


def _handle_signal(signum, frame):
    global _shutdown_requested
    logger.info("Shutdown signal received (%d) — stopping agent", signum)
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# ─── Main Detection Cycle ─────────────────────────────────────────────────────

def run_detection_cycle() -> dict:
    """
    Run a single full detection cycle across all modules.

    Returns:
        dict with aggregated results.
    """
    all_indicators = []
    detected_os = None
    module_results = {}

    # ── Module 1: Boot Source Detection
    try:
        boot_result = detect_boot_source()
        module_results["boot_detector"] = boot_result
        all_indicators.extend(boot_result.get("indicators", []))
        logger.debug("Boot detector: %s", boot_result.get("boot_source"))
    except Exception as e:
        logger.error("Boot detector failed: %s", str(e)[:200])
        all_indicators.append("MODULE_FAILURE:BOOT_DETECTOR")

    # ── Module 2: Kernel Fingerprint
    try:
        kernel_result = get_kernel_fingerprint()
        module_results["kernel_fingerprint"] = kernel_result
        all_indicators.extend(kernel_result.get("indicators", []))
        if kernel_result.get("detected_os") and not detected_os:
            detected_os = kernel_result["detected_os"]
        logger.debug("Kernel fingerprint: %s", kernel_result.get("kernel_version", "?")[:50])
    except Exception as e:
        logger.error("Kernel fingerprint failed: %s", str(e)[:200])
        all_indicators.append("MODULE_FAILURE:KERNEL_FINGERPRINT")

    # ── Module 3: Disk Monitor
    try:
        disk_result = analyze_mounts()
        module_results["disk_monitor"] = disk_result
        all_indicators.extend(disk_result.get("indicators", []))
    except Exception as e:
        logger.error("Disk monitor failed: %s", str(e)[:200])
        all_indicators.append("MODULE_FAILURE:DISK_MONITOR")

    # ── Module 4: Boot Fingerprint
    try:
        fp_result = analyze_boot_fingerprint()
        module_results["boot_fingerprint"] = fp_result
        all_indicators.extend(fp_result.get("indicators", []))
    except Exception as e:
        logger.error("Boot fingerprint failed: %s", str(e)[:200])
        all_indicators.append("MODULE_FAILURE:BOOT_FINGERPRINT")

    # ── Module 5: UEFI Monitor
    try:
        uefi_result = analyze_uefi()
        module_results["uefi_monitor"] = uefi_result
        all_indicators.extend(uefi_result.get("indicators", []))
    except Exception as e:
        logger.error("UEFI monitor failed: %s", str(e)[:200])
        all_indicators.append("MODULE_FAILURE:UEFI_MONITOR")

    # ── Log Integrity Check
    try:
        log_integrity = verify_log_integrity()
        module_results["log_integrity"] = log_integrity
        if not log_integrity.get("valid", True):
            all_indicators.extend(log_integrity.get("indicators", []))
            logger.critical("LOG INTEGRITY CHECK FAILED — potential tampering detected")
    except Exception as e:
        logger.error("Log integrity check failed: %s", str(e)[:200])

    # ── Deduplicate indicators (preserve order)
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    # ── Risk Scoring
    risk = compute_risk_score(unique_indicators, detected_os=detected_os)

    return {
        "risk": risk,
        "indicators": unique_indicators,
        "detected_os": detected_os,
        "boot_source": module_results.get("boot_detector", {}).get("boot_source", "unknown"),
        "kernel_version": module_results.get("kernel_fingerprint", {}).get("kernel_version", "unknown"),
        "secure_boot": module_results.get("boot_fingerprint", {}).get("secure_boot", "unknown"),
        "module_results": module_results,
    }


def main():
    """
    Main agent loop — runs detection every SCAN_INTERVAL_SECONDS seconds.
    """
    logger.info("=" * 60)
    logger.info("LiveBoot Sentinel Agent starting")
    logger.info("Scan interval: %ds | Alert threshold: %d", SCAN_INTERVAL_SECONDS, ALERT_RISK_THRESHOLD)
    logger.info("=" * 60)

    # Log startup event
    log_event("Agent started", risk_score=0)

    cycle = 0

    while not _shutdown_requested:
        cycle += 1
        logger.info("[Cycle %d] Starting detection run...", cycle)

        try:
            result = run_detection_cycle()
            risk = result["risk"]
            score = risk.score
            level = risk.level
            indicators = result["indicators"]
            boot_source = result["boot_source"]
            kernel = result["kernel_version"]
            detected_os = result["detected_os"]

            logger.info(
                "[Cycle %d] Score=%d Level=%s Indicators=%d BootSource=%s",
                cycle, score, level, len(indicators), boot_source
            )

            # Log to tamper-evident log
            log_event(
                event=f"Detection cycle {cycle}: level={level} score={score} boot={boot_source}",
                risk_score=score,
            )

            # Send alert if threshold exceeded
            if score > ALERT_RISK_THRESHOLD:
                logger.warning(
                    "[ALERT] Risk score %d exceeds threshold %d — sending alert",
                    score, ALERT_RISK_THRESHOLD
                )
                sent = send_alert(
                    boot_source=boot_source,
                    kernel=kernel,
                    detected_os=detected_os,
                    risk_score=score,
                    indicators=indicators,
                    risk_level=level,
                )
                if sent:
                    log_event(f"Alert sent: score={score} level={level}", risk_score=score)
                else:
                    log_event(f"Alert FAILED to send: score={score}", risk_score=score)
                    logger.error("Alert transmission failed — check network and API key")

            elif score > WARN_RISK_THRESHOLD:
                logger.warning(
                    "[WARNING] Score=%d level=%s — indicators: %s",
                    score, level, ", ".join(indicators[:5])
                )

        except Exception as e:
            logger.error("[Cycle %d] Unexpected error: %s", cycle, str(e)[:200])
            log_event(f"Agent error in cycle {cycle}: {str(e)[:100]}", risk_score=0)

        # Sleep with shutdown check
        for _ in range(SCAN_INTERVAL_SECONDS * 2):  # Check every 0.5s
            if _shutdown_requested:
                break
            time.sleep(0.5)

    logger.info("LiveBoot Sentinel Agent shutting down gracefully")
    log_event("Agent stopped", risk_score=0)


if __name__ == "__main__":
    main()
