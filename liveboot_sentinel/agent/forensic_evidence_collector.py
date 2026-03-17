"""
forensic_evidence_collector.py - Post-incident forensic evidence collection.
Fixed to eliminate false positives by using proper baselines and thresholds.
Only flags things that are GENUINELY suspicious, not normal Windows state.
"""

import json
import logging
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

EVIDENCE_WINDOW_HOURS = 72

# Known attacker tool names — very specific, not generic Windows tools
ATTACKER_TOOL_NAMES = [
    "mimikatz", "meterpreter", "empire", "cobalt",
    "pwdump", "wce.exe", "fgdump", "gsecdump",
    "procdump64", "sharphound", "rubeus", "bloodhound",
]

# Suspicious file extensions in TEMP locations only
SUSPICIOUS_EXTENSIONS = {".ps1", ".vbs", ".hta", ".scr", ".pif", ".jse"}

# Registry run key values that are genuinely suspicious
# Only flag if value points to temp/suspicious locations
SUSPICIOUS_RUN_PATHS = [
    "\\temp\\", "\\tmp\\", "\\public\\",
    "%temp%", "%tmp%",
    "\\appdata\\local\\temp\\",
]

# Known legitimate PowerShell autorun entries to whitelist
LEGIT_POWERSHELL_ENTRIES = [
    "onedrive", "teams", "skype", "office",
    "windowsdefender", "securityhealth",
    "backgroundtaskhost", "shellexperiencehost",
]


def _run_safe(args: list, timeout: int = 15) -> Optional[str]:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, shell=False
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _check_attacker_files_in_temp() -> dict:
    """
    Only scan TEMP and PUBLIC directories for attacker tool names.
    Do NOT scan the entire filesystem — too many false positives.
    """
    indicators = []
    found_files = []

    scan_paths = [
        Path(os.environ.get("TEMP", "C:\\Temp")),
        Path(os.environ.get("TMP", "C:\\Temp")),
        Path("C:\\Users\\Public"),
        Path("C:\\Windows\\Temp"),
    ]

    for base_path in scan_paths:
        if not base_path.exists():
            continue
        try:
            for f in base_path.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    stat = f.stat()
                    age_hours = (time.time() - stat.st_mtime) / 3600
                    if age_hours > EVIDENCE_WINDOW_HOURS:
                        continue

                    name_lower = f.name.lower()

                    # Check for exact attacker tool names
                    for tool in ATTACKER_TOOL_NAMES:
                        if tool in name_lower:
                            indicators.append(f"ATTACKER_TOOL_FOUND:{tool.upper()}")
                            found_files.append({
                                "path": str(f)[:200],
                                "tool": tool,
                                "modified": datetime.fromtimestamp(
                                    stat.st_mtime, tz=timezone.utc
                                ).isoformat(),
                            })
                            break

                    # Only flag .ps1 files in temp if they have suspicious content
                    if f.suffix.lower() == ".ps1" and stat.st_size < 1024 * 1024:
                        try:
                            content = f.read_text(errors="ignore").lower()
                            suspicious_ps1 = [
                                "invoke-mimikatz", "invoke-expression",
                                "downloadstring", "bypass", "encodedcommand",
                                "iex(", "iex (", "-nop ", "-windowstyle hidden",
                            ]
                            if any(s in content for s in suspicious_ps1):
                                indicators.append("SUSPICIOUS_PS1_IN_TEMP")
                                found_files.append({
                                    "path": str(f)[:200],
                                    "reason": "suspicious_powershell_content",
                                })
                        except OSError:
                            pass

                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue

    return {"indicators": indicators, "found_files": found_files[:20]}


def _check_registry_run_keys() -> dict:
    """
    Check registry run keys for GENUINELY suspicious entries.
    Only flag entries that point to temp directories or use obfuscation.
    Do NOT flag all PowerShell entries — most are legitimate.
    """
    indicators = []
    findings = []

    run_keys = [
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    for key in run_keys:
        ps_cmd = (
            f"Get-ItemProperty '{key}' "
            f"-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 1"
        )
        output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
        if not output or output.strip() in ["null", ""]:
            continue

        try:
            entries = json.loads(output)
            if not isinstance(entries, dict):
                continue

            for name, value in entries.items():
                # Skip PS properties
                if name.startswith("PS"):
                    continue

                value_str = str(value).lower()

                # Skip known legitimate entries
                if any(legit in value_str for legit in LEGIT_POWERSHELL_ENTRIES):
                    continue

                # Only flag if pointing to temp/suspicious locations
                if any(sus in value_str for sus in SUSPICIOUS_RUN_PATHS):
                    safe_name = re.sub(r"[^\w]", "", name)[:30]
                    indicators.append(f"MALICIOUS_REGISTRY_RUN_KEY:{safe_name.upper()}")
                    findings.append({
                        "key": key,
                        "name": name[:50],
                        "reason": "points_to_temp_location",
                    })

                # Flag if using encoding/obfuscation
                elif "-encodedcommand" in value_str or "-enc " in value_str:
                    safe_name = re.sub(r"[^\w]", "", name)[:30]
                    indicators.append(f"ENCODED_REGISTRY_RUN_KEY:{safe_name.upper()}")
                    findings.append({
                        "key": key,
                        "name": name[:50],
                        "reason": "uses_encoded_command",
                    })

        except (json.JSONDecodeError, TypeError):
            pass

    return {"indicators": indicators, "findings": findings}


def _check_event_log_for_attacks() -> dict:
    """
    Check Windows event log for specific attack indicators.
    Uses narrow event ID filters to avoid false positives.
    """
    indicators = []
    events = []

    # Only check for HIGH confidence attack events
    attack_events = [
        # Audit log cleared — very suspicious, almost always attacker
        (
            "1102", "AUDIT_LOG_CLEARED",
            "Get-WinEvent -LogName Security -MaxEvents 50 "
            "-ErrorAction SilentlyContinue "
            "| Where-Object {$_.Id -eq 1102} "
            "| Measure-Object | Select-Object -ExpandProperty Count"
        ),
        # New local user account created
        (
            "4720", "NEW_LOCAL_USER_CREATED",
            "Get-WinEvent -LogName Security -MaxEvents 200 "
            "-ErrorAction SilentlyContinue "
            "| Where-Object {$_.Id -eq 4720 -and "
            "$_.TimeCreated -gt (Get-Date).AddHours(-72)} "
            "| Measure-Object | Select-Object -ExpandProperty Count"
        ),
        # User added to Administrators group
        (
            "4732", "USER_ADDED_TO_ADMINS",
            "Get-WinEvent -LogName Security -MaxEvents 200 "
            "-ErrorAction SilentlyContinue "
            "| Where-Object {$_.Id -eq 4732 -and "
            "$_.TimeCreated -gt (Get-Date).AddHours(-72)} "
            "| Measure-Object | Select-Object -ExpandProperty Count"
        ),
    ]

    for event_id, indicator_name, ps_cmd in attack_events:
        output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
        if output and output.strip() not in ["0", "", "null"]:
            try:
                count = int(output.strip())
                if count > 0:
                    indicators.append(f"EVENT_LOG:{indicator_name}:{count}")
                    events.append({"event_id": event_id, "count": count})
            except ValueError:
                pass

    return {"indicators": indicators, "events": events}


def _check_shadow_copies() -> dict:
    """
    Check shadow copies. Only flag if they were recently deleted
    (not just absent — many systems have no shadow copies normally).
    """
    indicators = []
    details = {}

    # Check if vssadmin delete was recently run via event log
    ps_cmd = (
        "Get-WinEvent -LogName System -MaxEvents 500 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {"
        "$_.TimeCreated -gt (Get-Date).AddHours(-72) -and "
        "($_.Message -like '*vssadmin*delete*' -or "
        "$_.Message -like '*shadowcopy*delete*' -or "
        "$_.Message -like '*wmic*shadowcopy*')} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if output and output.strip() not in ["0", "", "null"]:
        try:
            count = int(output.strip())
            if count > 0:
                indicators.append("SHADOW_COPIES_DELETED")
                details["deletion_events"] = count
        except ValueError:
            pass

    return {"indicators": indicators, "details": details}


def _check_usb_registry_for_live_os() -> dict:
    """
    Check USB device registry for known live OS USB drive labels.
    This is high confidence — if a Kali USB was plugged in, it leaves a trace.
    """
    indicators = []
    details = {}

    ps_cmd = (
        "Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' "
        "-ErrorAction SilentlyContinue "
        "| Select-Object FriendlyName, DeviceDesc "
        "| ConvertTo-Json -Depth 1"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=10)

    if output and output.strip() not in ["null", "[]", ""]:
        output_lower = output.lower()
        live_os_keywords = {
            "kali": "Kali Linux",
            "tails": "Tails OS",
            "parrot": "Parrot OS",
            "blackarch": "BlackArch",
            "live": "Live OS",
            "persistence": "Persistent Live OS",
        }
        for keyword, label in live_os_keywords.items():
            if keyword in output_lower:
                indicators.append(f"LIVE_OS_USB_IN_REGISTRY:{label.upper().replace(' ', '_')}")
                details["detected_os"] = label
                break

        # Also record the USB brand for evidence
        usb_brands = ["sandisk", "kingston", "verbatim", "samsung", "generic"]
        for brand in usb_brands:
            if brand in output_lower:
                details["usb_brand"] = brand.title()
                # Only add brand indicator if we already found a live OS
                if indicators:
                    indicators[0] = indicators[0] + f"_ON_{brand.upper()}"
                break

    return {"indicators": indicators, "details": details}


def _check_prefetch_for_tools() -> dict:
    """
    Check Prefetch for evidence of specific attacker tools being run.
    Very high confidence — prefetch proves execution.
    """
    indicators = []
    executed = []

    prefetch_path = Path("C:/Windows/Prefetch")
    if not prefetch_path.exists():
        return {"indicators": [], "executed": []}

    # Very specific tool names only
    attacker_prefetch_names = [
        "MIMIKATZ", "METERPRETER", "PROCDUMP",
        "WCESERVICE", "FGDUMP", "PWDUMP",
        "BLOODHOUND", "SHARPHOUND", "RUBEUS",
    ]

    try:
        for pf_file in prefetch_path.glob("*.pf"):
            name = pf_file.stem.upper()
            for tool in attacker_prefetch_names:
                if tool in name:
                    stat = pf_file.stat()
                    age_hours = (time.time() - stat.st_mtime) / 3600
                    if age_hours <= EVIDENCE_WINDOW_HOURS:
                        indicators.append(f"PREFETCH_TOOL_EXECUTED:{tool}")
                        executed.append({
                            "tool": tool,
                            "last_run": datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc
                            ).isoformat(),
                        })
    except (OSError, PermissionError):
        pass

    return {"indicators": indicators, "executed": executed}


def _check_hosts_file() -> dict:
    """Check if hosts file was modified to redirect traffic."""
    indicators = []

    hosts_path = Path("C:/Windows/System32/drivers/etc/hosts")
    if not hosts_path.exists():
        return {"indicators": []}

    try:
        stat = hosts_path.stat()
        age_hours = (time.time() - stat.st_mtime) / 3600
        if age_hours <= EVIDENCE_WINDOW_HOURS:
            content = hosts_path.read_text(errors="ignore")
            real_lines = [
                l.strip() for l in content.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            # Default Windows hosts has 0-1 real lines
            # More than 3 is suspicious
            if len(real_lines) > 3:
                indicators.append(f"HOSTS_FILE_MODIFIED:{len(real_lines)}_ENTRIES")
    except (OSError, PermissionError):
        pass

    return {"indicators": indicators}


def collect_forensic_evidence() -> dict:
    """
    Run all forensic evidence collection.
    Returns only HIGH CONFIDENCE indicators — no false positives.
    """
    all_indicators = []
    evidence = {}
    timestamp = datetime.now(timezone.utc).isoformat()

    if platform.system() != "Windows":
        return {
            "indicators": [],
            "evidence": {},
            "forensic_score": 0,
            "summary": "No forensic evidence found.",
        }

    modules = [
        ("usb_registry",    _check_usb_registry_for_live_os),
        ("attacker_files",  _check_attacker_files_in_temp),
        ("registry_run",    _check_registry_run_keys),
        ("event_logs",      _check_event_log_for_attacks),
        ("shadow_copies",   _check_shadow_copies),
        ("prefetch",        _check_prefetch_for_tools),
        ("hosts_file",      _check_hosts_file),
    ]

    for module_name, module_fn in modules:
        try:
            result = module_fn()
            module_indicators = result.get("indicators", [])
            evidence[module_name] = result
            all_indicators.extend(module_indicators)
            if module_indicators:
                logger.debug("Forensic [%s]: %s", module_name, module_indicators)
        except Exception as e:
            logger.error("Forensic module %s failed: %s", module_name, str(e)[:100])

    # Deduplicate
    seen = set()
    unique = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    forensic_score = _compute_score(unique)
    summary = _build_summary(unique)

    return {
        "indicators":     unique,
        "evidence":       evidence,
        "forensic_score": forensic_score,
        "summary":        summary,
    }


FORENSIC_WEIGHTS = {
    "AUDIT_LOG_CLEARED":        60,
    "SHADOW_COPIES_DELETED":    55,
    "PREFETCH_TOOL_EXECUTED":   50,
    "ATTACKER_TOOL_FOUND":      50,
    "NEW_LOCAL_USER_CREATED":   45,
    "USER_ADDED_TO_ADMINS":     45,
    "MALICIOUS_REGISTRY_RUN_KEY": 40,
    "ENCODED_REGISTRY_RUN_KEY": 40,
    "LIVE_OS_USB_IN_REGISTRY":  35,
    "SUSPICIOUS_PS1_IN_TEMP":   35,
    "HOSTS_FILE_MODIFIED":      30,
    "EVENT_LOG":                20,
}


def _compute_score(indicators: list) -> int:
    score = 0
    seen = set()
    for ind in indicators:
        prefix = ind.split(":")[0]
        if prefix not in seen:
            seen.add(prefix)
            score += FORENSIC_WEIGHTS.get(prefix, 10)
    return min(score, 200)


def _build_summary(indicators: list) -> str:
    if not indicators:
        return "No forensic evidence of attack activity found."

    categories = {
        "Live OS Evidence":  ["LIVE_OS_USB_IN_REGISTRY"],
        "Tool Execution":    ["ATTACKER_TOOL_FOUND", "PREFETCH_TOOL_EXECUTED"],
        "Anti-Forensics":   ["AUDIT_LOG_CLEARED", "SHADOW_COPIES_DELETED"],
        "Persistence":       ["MALICIOUS_REGISTRY_RUN_KEY", "ENCODED_REGISTRY_RUN_KEY"],
        "Privilege Abuse":   ["NEW_LOCAL_USER_CREATED", "USER_ADDED_TO_ADMINS"],
        "Network Tampering": ["HOSTS_FILE_MODIFIED"],
    }

    lines = [f"FORENSIC EVIDENCE FOUND — {len(indicators)} indicator(s):"]
    for category, prefixes in categories.items():
        matched = [i for i in indicators if any(i.startswith(p) for p in prefixes)]
        if matched:
            lines.append(f"  [{category}] — {len(matched)} indicator(s)")

    return "\n".join(lines)
