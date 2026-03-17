"""
main.py - LiveBoot Sentinel endpoint agent main loop.
Includes: boot detection, post-boot attack detection,
          forensic evidence collection, live OS command tracking,
          RAM dump analysis, alert deduplication.
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
from forensic_evidence_collector import collect_forensic_evidence
from boot_sequence_monitor import record_and_analyze_boot
from live_os_command_tracker import track_live_os_commands
from ram_dump_analyzer import analyze_ram_dump, check_volatility_installed
from alert_deduplicator import should_send_alert, record_alert_sent

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
    logger.info("Shutdown signal received — stopping agent")
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)


def run_startup_forensics() -> dict:
    """
    Run on every Windows startup:
    1. Boot sequence analysis
    2. Forensic evidence collection
    3. Live OS command tracking
    4. RAM dump analysis (if dump exists)
    """
    logger.info("=" * 60)
    logger.info("POST-INCIDENT FORENSIC ANALYSIS STARTING")
    logger.info("Looking back 48 hours for attack evidence...")
    logger.info("=" * 60)

    all_indicators  = []
    forensic_score  = 0
    attack_techniques = {}
    ram_report      = {}

    # 1. Boot sequence analysis
    try:
        boot_result = record_and_analyze_boot()
        all_indicators.extend(boot_result.get("indicators", []))
    except Exception as e:
        logger.error("Boot sequence monitor failed: %s", str(e)[:100])

    # 2. Forensic evidence collection
    try:
        forensic = collect_forensic_evidence()
        all_indicators.extend(forensic.get("indicators", []))
        forensic_score = forensic.get("forensic_score", 0)
    except Exception as e:
        logger.error("Forensic collection failed: %s", str(e)[:100])

    # 3. Live OS command tracking
    try:
        cmd_result = track_live_os_commands()
        cmd_indicators = cmd_result.get("indicators", [])
        all_indicators.extend(cmd_indicators)
        if cmd_indicators:
            attack_techniques["Command Execution"] = cmd_indicators
            logger.warning("COMMANDS DETECTED during live OS session:")
            for ind in cmd_indicators:
                logger.warning("  %s", ind)
    except Exception as e:
        logger.error("Command tracking failed: %s", str(e)[:100])

    # 4. RAM dump analysis
    try:
        vol_status = check_volatility_installed()
        if not vol_status["installed"]:
            logger.info("Volatility3: %s", vol_status["message"])

        ram_report = analyze_ram_dump()
        ram_indicators = ram_report.get("indicators", [])
        all_indicators.extend(ram_indicators)
        ram_risk = ram_report.get("risk_score_increment", 0)
        forensic_score += ram_risk

        if ram_report.get("analysis_complete"):
            logger.info("RAM ANALYSIS COMPLETE:")
            logger.info("  Processes analyzed:    %d", len(ram_report.get("processes", [])))
            logger.info("  Suspicious tools:      %d", len(ram_report.get("suspicious_tools", [])))
            logger.info("  Network connections:   %d", len(ram_report.get("network_connections", [])))
            logger.info("  Commands detected:     %d", len(ram_report.get("commands_detected", [])))
            logger.info("  Risk increment:        +%d", ram_risk)

            if ram_report.get("suspicious_tools"):
                attack_techniques["RAM: Suspicious Tools"] = [
                    t["tool"] for t in ram_report["suspicious_tools"]
                ]
                logger.warning("SUSPICIOUS TOOLS IN RAM:")
                for tool in ram_report["suspicious_tools"]:
                    logger.warning(
                        "  [PID %d] %s — %s",
                        tool.get("pid", 0),
                        tool.get("tool", "?")[:30],
                        tool.get("technique", "?"),
                    )

            if ram_report.get("credentials_found"):
                attack_techniques["RAM: Credentials"] = [
                    f"{c['username']} (hash found)"
                    for c in ram_report["credentials_found"]
                ]

        elif ram_indicators and "NO_RAM_DUMP_FOUND" not in ram_indicators:
            logger.info("RAM analysis: %s", ram_indicators)

    except Exception as e:
        logger.error("RAM dump analysis failed: %s", str(e)[:200])

    # Deduplicate indicators
    seen = set()
    unique = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    log_event(
        f"Startup forensic scan: {len(unique)} indicators, score={forensic_score}",
        risk_score=forensic_score
    )

    if unique and "NO_RAM_DUMP_FOUND" not in unique:
        logger.warning("FORENSIC EVIDENCE FOUND: %d indicators", len(unique))
        for ind in unique:
            logger.warning("  [FORENSIC] %s", ind)

        total_score = min(forensic_score + len(unique) * 5, 200)

        # Build summary
        summary_lines = [
            "POST-INCIDENT FORENSIC ANALYSIS",
            "=" * 32,
            f"Total indicators: {len(unique)}",
            f"Forensic score:   {total_score}",
        ]

        categories = {
            "Live OS Evidence":  ["LIVE_OS_USB_IN_REGISTRY"],
            "RAM Analysis":      ["RAM_SUSPICIOUS_TOOL", "RAM_CREDENTIALS", "RAM_C2", "RAM_REVERSE"],
            "Commands Executed": ["COMMAND_DETECTED", "PREFETCH"],
            "Persistence":       ["MALICIOUS_REGISTRY", "ENCODED_REGISTRY", "WMI_PERSISTENCE"],
            "Anti-Forensics":    ["AUDIT_LOG_CLEARED", "SHADOW_COPIES_DELETED"],
            "Privilege Abuse":   ["NEW_LOCAL_USER", "USER_ADDED_TO_ADMINS"],
        }

        for category, prefixes in categories.items():
            matched = [i for i in unique if any(i.startswith(p) for p in prefixes)]
            if matched:
                attack_techniques[category] = matched
                summary_lines.append(f"  [{category}] — {len(matched)} indicator(s)")

        if total_score > ALERT_RISK_THRESHOLD or unique:
            logger.warning(
                "FORENSIC ALERT: score=%d — sending to server", total_score
            )
            send_alert(
                boot_source="post_incident_forensics",
                kernel="startup_forensic_scan",
                detected_os="Post-Incident Analysis",
                risk_score=total_score,
                indicators=unique,
                risk_level="CRITICAL" if total_score > 50 else "WARNING",
                ram_analysis=ram_report,
            )
            record_alert_sent(unique)
    else:
        logger.info("No forensic evidence found — system appears clean")

    return {"indicators": unique, "forensic_score": forensic_score}


def run_detection_cycle() -> dict:
    all_indicators = []
    detected_os    = None
    module_results = {}

    for name, fn in [
        ("boot_detector",      detect_boot_source),
        ("kernel_fingerprint", get_kernel_fingerprint),
        ("disk_monitor",       analyze_mounts),
        ("boot_fingerprint",   analyze_boot_fingerprint),
        ("uefi_monitor",       analyze_uefi),
    ]:
        try:
            result = fn()
            module_results[name] = result
            all_indicators.extend(result.get("indicators", []))
            if name == "kernel_fingerprint" and result.get("detected_os"):
                detected_os = result["detected_os"]
        except Exception as e:
            logger.error("%s failed: %s", name, str(e)[:100])
            all_indicators.append(f"MODULE_FAILURE:{name.upper()}")

    try:
        post_boot = run_post_boot_analysis()
        module_results["post_boot"] = post_boot
        all_indicators.extend(post_boot.get("indicators", []))
        if post_boot.get("techniques_count", 0) > 0:
            logger.warning(
                "ACTIVE ATTACK TECHNIQUES: %s",
                ", ".join(post_boot.get("attack_techniques", {}).keys())
            )
    except Exception as e:
        logger.error("Post-boot analysis failed: %s", str(e)[:100])

    try:
        log_integrity = verify_log_integrity()
        if not log_integrity.get("valid", True):
            all_indicators.extend(log_integrity.get("indicators", []))
    except Exception as e:
        logger.error("Log integrity check failed: %s", str(e)[:100])

    seen = set()
    unique = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    risk = compute_risk_score(unique, detected_os=detected_os)
    post_score = module_results.get("post_boot", {}).get("post_boot_score", 0)
    total = min(risk.score + post_score, 200)
    risk.score = total
    risk.level = "CRITICAL" if total >= 50 else "WARNING" if total >= 30 else "NORMAL"

    return {
        "risk":              risk,
        "indicators":        unique,
        "detected_os":       detected_os,
        "boot_source":       module_results.get("boot_detector", {}).get("boot_source", "unknown"),
        "kernel_version":    module_results.get("kernel_fingerprint", {}).get("kernel_version", "unknown"),
        "attack_techniques": module_results.get("post_boot", {}).get("attack_techniques", {}),
        "attack_summary":    module_results.get("post_boot", {}).get("summary", ""),
    }


def main():
    logger.info("=" * 60)
    logger.info("LiveBoot Sentinel Agent starting")
    logger.info("Scan interval:   %ds", SCAN_INTERVAL_SECONDS)
    logger.info("Alert threshold: %d", ALERT_RISK_THRESHOLD)
    logger.info("=" * 60)

    log_event("Agent started", risk_score=0)
    run_startup_forensics()

    cycle = 0
    while not _shutdown_requested:
        cycle += 1
        logger.info("[Cycle %d] Starting detection run...", cycle)

        try:
            result      = run_detection_cycle()
            risk        = result["risk"]
            score       = risk.score
            level       = risk.level
            indicators  = result["indicators"]
            boot_source = result["boot_source"]
            kernel      = result["kernel_version"]
            detected_os = result["detected_os"]
            attack_tech = result["attack_techniques"]
            attack_sum  = result["attack_summary"]

            if attack_tech:
                logger.warning(
                    "ACTIVE ATTACK TECHNIQUES: %s",
                    ", ".join(attack_tech.keys())
                )

            logger.info(
                "[Cycle %d] Score=%d Level=%s Indicators=%d "
                "BootSource=%s Techniques=%d",
                cycle, score, level, len(indicators),
                boot_source, len(attack_tech)
            )

            log_event(
                f"Cycle {cycle}: level={level} score={score} boot={boot_source}",
                risk_score=score,
            )

            if score > ALERT_RISK_THRESHOLD:
                if should_send_alert(indicators, score):
                    logger.warning("[ALERT] Score %d — sending alert", score)
                    sent = send_alert(
                        boot_source=boot_source,
                        kernel=kernel,
                        detected_os=detected_os,
                        risk_score=score,
                        indicators=indicators,
                        risk_level=level,
                    )
                    if sent:
                        record_alert_sent(indicators)
                        log_event(
                            f"Alert sent: score={score} level={level}",
                            risk_score=score
                        )
                    else:
                        logger.error("Alert transmission failed")
                else:
                    logger.info(
                        "[Cycle %d] Alert suppressed — no new indicators",
                        cycle
                    )
            elif score > WARN_RISK_THRESHOLD:
                logger.warning(
                    "[WARNING] Score=%d — %s",
                    score, ", ".join(indicators[:5])
                )

        except Exception as e:
            logger.error("[Cycle %d] Error: %s", cycle, str(e)[:200])

        for _ in range(SCAN_INTERVAL_SECONDS * 2):
            if _shutdown_requested:
                break
            time.sleep(0.5)

    logger.info("LiveBoot Sentinel Agent shutting down")
    log_event("Agent stopped", risk_score=0)


if __name__ == "__main__":
    main()
