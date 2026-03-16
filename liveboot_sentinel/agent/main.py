"""
main.py - LiveBoot Sentinel endpoint agent main loop.
Runs all detection modules every 10 seconds and triggers alerts on high risk.
Includes post-boot attack detection for forensic analysis.
"""

import logging
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from boot_detector import detect_boot_source
from kernel_fingerprint import get_kernel_fingerprint
from disk_monitor import analyze_mounts
from boot_fingerprint import analyze_boot_fingerprint
from uefi_monitor import analyze_uefi
from risk_engine import compute_risk_score
from alert_client import send_alert
from tamper_evident_logger import log_event, verify_log_integrity
from post_boot_analyzer import run_post_boot_analysis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("liveboot_sentinel.main")

SCAN_INTERVAL_SECONDS = 10
ALERT_RISK_THRESHOLD  = 50
WARN_RISK_THRESHOLD   = 30

_shutdown_requested = False


def _handle_signal(signum, frame):
    global _shutdown_requested
    logger.info("Shutdown signal received (%d) — stopping agent", signum)
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)


def run_detection_cycle() -> dict:
    all_indicators = []
    detected_os    = None
    module_results = {}

    # ── Boot detection modules ─────────────────────────────────────────────
    for name, fn in [
        ("boot_detector",     detect_boot_source),
        ("kernel_fingerprint", get_kernel_fingerprint),
        ("disk_monitor",      analyze_mounts),
        ("boot_fingerprint",  analyze_boot_fingerprint),
        ("uefi_monitor",      analyze_uefi),
    ]:
        try:
            result = fn()
            module_results[name] = result
            all_indicators.extend(result.get("indicators", []))
            if name == "kernel_fingerprint" and result.get("detected_os"):
                detected_os = result["detected_os"]
        except Exception as e:
            logger.error("%s failed: %s", name, str(e)[:200])
            all_indicators.append(f"MODULE_FAILURE:{name.upper()}")

    # ── Post-boot attack detection ─────────────────────────────────────────
    try:
        post_boot = run_post_boot_analysis()
        module_results["post_boot_analysis"] = post_boot
        all_indicators.extend(post_boot.get("indicators", []))

        if post_boot.get("techniques_count", 0) > 0:
            logger.warning(
                "POST-BOOT ATTACK DETECTED: %d technique(s) — %s",
                post_boot["techniques_count"],
                ", ".join(post_boot.get("attack_techniques", {}).keys())
            )
    except Exception as e:
        logger.error("Post-boot analysis failed: %s", str(e)[:200])

    # ── Log integrity check ────────────────────────────────────────────────
    try:
        log_integrity = verify_log_integrity()
        module_results["log_integrity"] = log_integrity
        if not log_integrity.get("valid", True):
            all_indicators.extend(log_integrity.get("indicators", []))
            logger.critical("LOG INTEGRITY CHECK FAILED")
    except Exception as e:
        logger.error("Log integrity check failed: %s", str(e)[:200])

    # Deduplicate
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    # Risk scoring
    risk = compute_risk_score(unique_indicators, detected_os=detected_os)

    # Add post-boot score on top
    post_boot_score = module_results.get("post_boot_analysis", {}).get("post_boot_score", 0)
    total_score = min(risk.score + post_boot_score, 200)
    risk.score = total_score
    if total_score >= 50:
        risk.level = "CRITICAL"
    elif total_score >= 30:
        risk.level = "WARNING"

    return {
        "risk":           risk,
        "indicators":     unique_indicators,
        "detected_os":    detected_os,
        "boot_source":    module_results.get("boot_detector", {}).get("boot_source", "unknown"),
        "kernel_version": module_results.get("kernel_fingerprint", {}).get("kernel_version", "unknown"),
        "secure_boot":    module_results.get("boot_fingerprint", {}).get("secure_boot", "unknown"),
        "module_results": module_results,
        "attack_techniques": module_results.get("post_boot_analysis", {}).get("attack_techniques", {}),
        "attack_summary":    module_results.get("post_boot_analysis", {}).get("summary", ""),
    }


def main():
    logger.info("=" * 60)
    logger.info("LiveBoot Sentinel Agent starting")
    logger.info("Scan interval: %ds | Alert threshold: %d", SCAN_INTERVAL_SECONDS, ALERT_RISK_THRESHOLD)
    logger.info("Post-boot attack detection: ENABLED")
    logger.info("=" * 60)

    log_event("Agent started", risk_score=0)
    cycle = 0

    while not _shutdown_requested:
        cycle += 1
        logger.info("[Cycle %d] Starting detection run...", cycle)

        try:
            result          = run_detection_cycle()
            risk            = result["risk"]
            score           = risk.score
            level           = risk.level
            indicators      = result["indicators"]
            boot_source     = result["boot_source"]
            kernel          = result["kernel_version"]
            detected_os     = result["detected_os"]
            attack_tech     = result["attack_techniques"]
            attack_summary  = result["attack_summary"]

            logger.info(
                "[Cycle %d] Score=%d Level=%s Indicators=%d BootSource=%s AttackTechniques=%d",
                cycle, score, level, len(indicators), boot_source, len(attack_tech)
            )

            if attack_tech:
                logger.warning("[Cycle %d] ATTACK TECHNIQUES: %s", cycle, ", ".join(attack_tech.keys()))

            log_event(
                event=f"Cycle {cycle}: level={level} score={score} boot={boot_source} techniques={len(attack_tech)}",
                risk_score=score,
            )

            if score > ALERT_RISK_THRESHOLD:
                logger.warning("[ALERT] Score %d > threshold %d — sending alert", score, ALERT_RISK_THRESHOLD)
                sent = send_alert(
                    boot_source=boot_source,
                    kernel=kernel,
                    detected_os=detected_os,
                    risk_score=score,
                    indicators=indicators,
                    risk_level=level,
                )
                if sent:
                    log_event(f"Alert sent: score={score} level={level} techniques={len(attack_tech)}", risk_score=score)
                else:
                    log_event(f"Alert FAILED: score={score}", risk_score=score)
                    logger.error("Alert transmission failed — check network and API key")

            elif score > WARN_RISK_THRESHOLD:
                logger.warning("[WARNING] Score=%d level=%s — %s", score, level, ", ".join(indicators[:5]))

        except Exception as e:
            logger.error("[Cycle %d] Unexpected error: %s", cycle, str(e)[:200])
            log_event(f"Agent error cycle {cycle}: {str(e)[:100]}", risk_score=0)

        for _ in range(SCAN_INTERVAL_SECONDS * 2):
            if _shutdown_requested:
                break
            time.sleep(0.5)

    logger.info("LiveBoot Sentinel Agent shutting down")
    log_event("Agent stopped", risk_score=0)


if __name__ == "__main__":
    main()
