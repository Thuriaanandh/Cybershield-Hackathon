"""
live_os_command_tracker.py - Identify commands executed during a live OS session.
After Windows boots back, scans for bash/shell history files left behind
by the attacker on the Windows partition.
Also checks Windows artifacts for evidence of what was run.
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

# High-risk commands that indicate specific attack techniques
HIGH_RISK_COMMANDS = {
    # Credential dumping
    "mimikatz":          "Credential Dumping",
    "sekurlsa":          "Credential Dumping",
    "hashdump":          "Credential Dumping",
    "lsadump":           "Credential Dumping",
    "procdump":          "Credential Dumping",
    "wce ":              "Credential Dumping",
    "fgdump":            "Credential Dumping",
    "pwdump":            "Credential Dumping",

    # Persistence
    "schtasks /create":  "Scheduled Task Persistence",
    "reg add.*run":      "Registry Run Key Persistence",
    "sc create":         "Service Persistence",
    "netsh advfirewall": "Firewall Modification",
    "net user /add":     "New User Account",
    "net localgroup administrators /add": "Admin Privilege Escalation",

    # Discovery
    "net view":          "Network Discovery",
    "nmap":              "Port Scanning",
    "arp -a":            "ARP Discovery",
    "ipconfig /all":     "Network Enumeration",
    "whoami /all":       "Privilege Enumeration",
    "net user":          "User Enumeration",
    "net group":         "Group Enumeration",
    "systeminfo":        "System Enumeration",

    # Exfiltration
    "xcopy":             "File Exfiltration",
    "robocopy":          "File Exfiltration",
    "compress-archive":  "File Archiving",
    "tar -c":            "File Archiving",
    "curl.*upload":      "Data Upload",
    "wget.*post":        "Data Upload",

    # Anti-forensics
    "vssadmin delete":   "Shadow Copy Deletion",
    "wevtutil cl":       "Event Log Clearing",
    "del /f /s /q":      "File Deletion",
    "cipher /w":         "Secure File Wipe",
    "bcdedit":           "Boot Configuration Modification",
    "format ":           "Drive Formatting",

    # Lateral movement
    "psexec":            "Lateral Movement",
    "wmiexec":           "Lateral Movement",
    "smbexec":           "Lateral Movement",
    "winrm":             "Remote Management",

    # Kali-specific tools
    "msfconsole":        "Metasploit Framework",
    "msfvenom":          "Payload Generation",
    "hydra":             "Password Brute Force",
    "john":              "Password Cracking",
    "hashcat":           "Password Cracking",
    "aircrack":          "Wireless Attack",
    "sqlmap":            "SQL Injection",
    "nikto":             "Web Vulnerability Scan",
    "burpsuite":         "Web Proxy Attack",
    "netcat":            "Network Backdoor",
    "nc -l":             "Reverse Shell Listener",
    "nc -e":             "Reverse Shell",
    "bash -i":           "Interactive Reverse Shell",
    "/bin/bash -i":      "Interactive Reverse Shell",
}

# Locations where live OS bash history might be left on Windows partition
HISTORY_SEARCH_PATHS_WINDOWS = [
    "C:\\",
    "C:\\Users",
    "C:\\Windows\\Temp",
    "C:\\Temp",
]

# Common bash history filenames
HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".history",
    "bash_history.txt",
]


def _run_safe(args: list, timeout: int = 10) -> Optional[str]:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, shell=False
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def _scan_for_bash_history_windows() -> dict:
    """
    Scan Windows filesystem for bash history files left by attacker.
    Kali attackers sometimes leave .bash_history in their working directory.
    """
    indicators = []
    commands_found = []
    history_files_found = []

    # Search common locations
    for base in HISTORY_SEARCH_PATHS_WINDOWS:
        base_path = Path(base)
        if not base_path.exists():
            continue
        try:
            for history_file in HISTORY_FILES:
                # Direct check in base
                candidate = base_path / history_file
                if candidate.exists():
                    try:
                        stat = candidate.stat()
                        age_hours = (time.time() - stat.st_mtime) / 3600
                        if age_hours <= 72:
                            content = candidate.read_text(errors="ignore")
                            parsed = _parse_history_content(content)
                            if parsed["commands"]:
                                history_files_found.append(str(candidate))
                                commands_found.extend(parsed["commands"])
                                indicators.extend(parsed["indicators"])
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            continue

    return {
        "indicators": indicators,
        "commands": commands_found[:100],
        "history_files": history_files_found,
    }


def _check_powershell_history() -> dict:
    """
    Check PowerShell command history — attackers using PowerShell
    leave traces in PSReadLine history.
    """
    indicators = []
    commands_found = []

    ps_history_paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
        Path(os.environ.get("USERPROFILE", "")) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
    ]

    for history_path in ps_history_paths:
        if not history_path.exists():
            continue
        try:
            stat = history_path.stat()
            age_hours = (time.time() - stat.st_mtime) / 3600
            if age_hours <= 72:
                content = history_path.read_text(errors="ignore")
                parsed = _parse_history_content(content)
                commands_found.extend(parsed["commands"])
                indicators.extend(parsed["indicators"])
        except (OSError, PermissionError):
            pass

    return {
        "indicators": indicators,
        "commands": commands_found[:50],
    }


def _check_prefetch_command_evidence() -> dict:
    """
    Cross-reference Prefetch files with attack command patterns.
    Prefetch proves a program was executed even if history was cleared.
    """
    indicators = []
    evidence = []

    prefetch_path = Path("C:/Windows/Prefetch")
    if not prefetch_path.exists():
        return {"indicators": [], "evidence": []}

    # Map prefetch names to attack techniques
    prefetch_attack_map = {
        "MIMIKATZ":     ("Credential Dumping", "PREFETCH:MIMIKATZ_EXECUTED"),
        "PROCDUMP":     ("Credential Dumping", "PREFETCH:PROCDUMP_EXECUTED"),
        "MSFCONSOLE":   ("Metasploit",          "PREFETCH:METASPLOIT_EXECUTED"),
        "MSFVENOM":     ("Payload Generation",  "PREFETCH:MSFVENOM_EXECUTED"),
        "NMAP":         ("Port Scanning",        "PREFETCH:NMAP_EXECUTED"),
        "HYDRA":        ("Brute Force",          "PREFETCH:HYDRA_EXECUTED"),
        "SQLMAP":       ("SQL Injection",        "PREFETCH:SQLMAP_EXECUTED"),
        "NETCAT":       ("Backdoor",             "PREFETCH:NETCAT_EXECUTED"),
        "NC":           ("Backdoor",             "PREFETCH:NC_EXECUTED"),
        "WCESERVICE":   ("Credential Dumping",  "PREFETCH:WCE_EXECUTED"),
        "PWDUMP":       ("Credential Dumping",  "PREFETCH:PWDUMP_EXECUTED"),
        "BLOODHOUND":   ("AD Reconnaissance",   "PREFETCH:BLOODHOUND_EXECUTED"),
        "SHARPHOUND":   ("AD Reconnaissance",   "PREFETCH:SHARPHOUND_EXECUTED"),
        "RUBEUS":       ("Kerberos Attack",      "PREFETCH:RUBEUS_EXECUTED"),
        "JOHN":         ("Password Cracking",    "PREFETCH:JOHN_EXECUTED"),
        "HASHCAT":      ("Password Cracking",    "PREFETCH:HASHCAT_EXECUTED"),
        "PSEXEC":       ("Lateral Movement",     "PREFETCH:PSEXEC_EXECUTED"),
    }

    try:
        for pf_file in prefetch_path.glob("*.pf"):
            name = pf_file.stem.upper()
            for tool, (technique, indicator) in prefetch_attack_map.items():
                if tool in name:
                    try:
                        stat = pf_file.stat()
                        age_hours = (time.time() - stat.st_mtime) / 3600
                        if age_hours <= 72:
                            indicators.append(indicator)
                            evidence.append({
                                "tool": tool,
                                "technique": technique,
                                "last_executed": datetime.fromtimestamp(
                                    stat.st_mtime, tz=timezone.utc
                                ).isoformat(),
                                "source": "prefetch",
                            })
                    except OSError:
                        pass
    except (OSError, PermissionError):
        pass

    return {"indicators": indicators, "evidence": evidence}


def _check_event_log_commands() -> dict:
    """
    Check Windows event log for PowerShell script block logging
    and process creation events that reveal what was run.
    """
    indicators = []
    commands_found = []

    # PowerShell script block logging (Event ID 4104)
    ps_cmd = (
        "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
        "-MaxEvents 200 -ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 4104 -and "
        "$_.TimeCreated -gt (Get-Date).AddHours(-72)} "
        "| Select-Object -ExpandProperty Message"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if output:
        parsed = _parse_history_content(output)
        commands_found.extend(parsed["commands"])
        indicators.extend(parsed["indicators"])

    # Process creation events (Event ID 4688) — requires audit policy
    ps_cmd2 = (
        "Get-WinEvent -LogName Security -MaxEvents 500 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Id -eq 4688 -and "
        "$_.TimeCreated -gt (Get-Date).AddHours(-72)} "
        "| Select-Object -ExpandProperty Message"
    )
    output2 = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd2], timeout=20)
    if output2:
        parsed2 = _parse_history_content(output2)
        for cmd in parsed2["commands"]:
            if cmd not in commands_found:
                commands_found.append(cmd)
        for ind in parsed2["indicators"]:
            if ind not in indicators:
                indicators.append(ind)

    return {
        "indicators": indicators,
        "commands": commands_found[:50],
    }


def _parse_history_content(content: str) -> dict:
    """
    Parse command history content and identify attack commands.
    Returns matched indicators and sanitized command list.
    """
    indicators = []
    matched_commands = []

    if not content:
        return {"indicators": [], "commands": []}

    content_lower = content.lower()

    for pattern, technique in HIGH_RISK_COMMANDS.items():
        if re.search(re.escape(pattern), content_lower):
            safe_technique = re.sub(r"[^\w\s]", "", technique).upper().replace(" ", "_")
            indicator = f"COMMAND_DETECTED:{safe_technique}"
            if indicator not in indicators:
                indicators.append(indicator)
                matched_commands.append({
                    "technique": technique,
                    "pattern": pattern[:50],
                    "indicator": indicator,
                })

    return {
        "indicators": indicators,
        "commands": matched_commands,
    }


def track_live_os_commands() -> dict:
    """
    Main function — identify commands used during the live OS session.
    Combines multiple evidence sources for comprehensive coverage.
    """
    all_indicators = []
    all_commands = []
    all_evidence = []
    details = {}

    if platform.system() != "Windows":
        return {
            "indicators": [],
            "commands": [],
            "evidence": [],
            "details": {},
            "attack_timeline": [],
        }

    # 1. Scan for bash history files left behind
    bash_result = _scan_for_bash_history_windows()
    all_indicators.extend(bash_result.get("indicators", []))
    all_commands.extend(bash_result.get("commands", []))
    if bash_result.get("history_files"):
        details["bash_history_files_found"] = bash_result["history_files"]

    # 2. Check PowerShell history
    ps_result = _check_powershell_history()
    all_indicators.extend(ps_result.get("indicators", []))
    all_commands.extend(ps_result.get("commands", []))

    # 3. Check Prefetch for tool execution
    prefetch_result = _check_prefetch_command_evidence()
    all_indicators.extend(prefetch_result.get("indicators", []))
    all_evidence.extend(prefetch_result.get("evidence", []))

    # 4. Check event logs for commands
    event_result = _check_event_log_commands()
    all_indicators.extend(event_result.get("indicators", []))
    all_commands.extend(event_result.get("commands", []))

    # Deduplicate indicators
    seen = set()
    unique_indicators = []
    for ind in all_indicators:
        if ind not in seen:
            seen.add(ind)
            unique_indicators.append(ind)

    # Build attack timeline
    attack_timeline = []
    for evidence in all_evidence:
        attack_timeline.append({
            "timestamp": evidence.get("last_executed", "unknown"),
            "tool": evidence.get("tool", "unknown"),
            "technique": evidence.get("technique", "unknown"),
            "source": evidence.get("source", "unknown"),
        })

    # Add command-based entries
    for cmd in all_commands:
        if isinstance(cmd, dict):
            attack_timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": cmd.get("pattern", "unknown")[:30],
                "technique": cmd.get("technique", "unknown"),
                "source": "command_history",
            })

    # Sort by timestamp
    attack_timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    details["total_commands_analyzed"] = len(all_commands)
    details["evidence_sources"] = []
    if bash_result.get("history_files"):
        details["evidence_sources"].append("bash_history")
    if ps_result.get("commands"):
        details["evidence_sources"].append("powershell_history")
    if prefetch_result.get("evidence"):
        details["evidence_sources"].append("prefetch")
    if event_result.get("commands"):
        details["evidence_sources"].append("event_logs")

    if unique_indicators:
        logger.warning(
            "Live OS command tracking: %d attack techniques identified",
            len(unique_indicators)
        )
        for ind in unique_indicators:
            logger.warning("  [COMMAND] %s", ind)

    return {
        "indicators":      unique_indicators,
        "commands":        all_commands[:50],
        "evidence":        all_evidence[:20],
        "details":         details,
        "attack_timeline": attack_timeline[:30],
    }
