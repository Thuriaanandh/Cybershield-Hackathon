"""
persistence_detector.py - Detect attacker persistence mechanisms.
Fixed to avoid false positives from normal Windows state.
Only flags genuinely suspicious entries.
"""

import json
import logging
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Known legitimate scheduled task paths — do not flag these
LEGIT_TASK_PATHS = [
    "\\microsoft\\", "\\windows\\", "\\adobe\\",
    "\\google\\", "\\mozilla\\", "\\office\\",
    "\\onedrive\\", "\\teams\\", "\\skype\\",
    "\\dropbox\\", "\\zoom\\", "\\nvidia\\",
    "\\intel\\", "\\amd\\", "\\hp\\", "\\dell\\",
    "\\lenovo\\", "\\asus\\", "\\mcafee\\",
    "\\symantec\\", "\\avast\\", "\\avg\\",
    "\\kaspersky\\", "\\bitdefender\\",
]

# Paths that ARE suspicious in scheduled tasks
SUSPICIOUS_TASK_PATHS = [
    "\\temp\\", "\\tmp\\", "\\public\\",
    "%temp%", "%tmp%", "%public%",
    "\\appdata\\local\\temp\\",
]

# Known legitimate run key entries
LEGIT_RUN_ENTRIES = [
    "onedrive", "teams", "skype", "office",
    "windowsdefender", "securityhealth", "cortana",
    "chrome", "firefox", "edge", "discord",
    "steam", "epic", "nvidia", "intel",
    "realtek", "logitech", "microsoft",
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


def _check_scheduled_tasks_windows() -> list:
    """
    Check for suspicious scheduled tasks.
    Only flags tasks pointing to temp/suspicious locations.
    Whitelists all known legitimate task paths.
    """
    indicators = []

    ps_cmd = (
        "Get-ScheduledTask -ErrorAction SilentlyContinue "
        "| Where-Object {$_.State -ne 'Disabled'} "
        "| Select-Object TaskName, TaskPath, "
        "@{N='Execute';E={$_.Actions.Execute}}, "
        "@{N='Arguments';E={$_.Actions.Arguments}} "
        "| ConvertTo-Json -Depth 2"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if not output or output.strip() in ["null", "[]"]:
        return []

    try:
        tasks = json.loads(output)
        if isinstance(tasks, dict):
            tasks = [tasks]

        for task in tasks:
            if not isinstance(task, dict):
                continue

            task_path = str(task.get("TaskPath", "")).lower()
            execute = str(task.get("Execute", "") or "").lower()
            arguments = str(task.get("Arguments", "") or "").lower()
            combined = f"{task_path} {execute} {arguments}"

            # Skip all legitimate tasks
            if any(legit in task_path for legit in LEGIT_TASK_PATHS):
                continue

            # Only flag if pointing to suspicious locations
            if any(sus in combined for sus in SUSPICIOUS_TASK_PATHS):
                task_name = re.sub(r"[^\w]", "", str(task.get("TaskName", "unknown")))[:30]
                indicators.append(f"SUSPICIOUS_SCHEDULED_TASK:{task_name.upper()}")

            # Flag encoded commands regardless of path
            elif "-encodedcommand" in combined or "-enc " in combined:
                task_name = re.sub(r"[^\w]", "", str(task.get("TaskName", "unknown")))[:30]
                indicators.append(f"ENCODED_SCHEDULED_TASK:{task_name.upper()}")

    except (json.JSONDecodeError, TypeError):
        pass

    return indicators


def _check_wmi_subscriptions_windows() -> list:
    """
    Check WMI event subscriptions — almost always malicious if present
    as most legitimate software doesn't use WMI subscriptions.
    """
    indicators = []
    ps_cmd = (
        "Get-WMIObject -Namespace root\\subscription "
        "-Class __EventFilter "
        "-ErrorAction SilentlyContinue "
        "| Where-Object {$_.Name -notlike '__*'} "
        "| Measure-Object | Select-Object -ExpandProperty Count"
    )
    output = _run_safe(["powershell", "-NoProfile", "-Command", ps_cmd])
    if output and output.strip() not in ["0", "", "null"]:
        try:
            count = int(output.strip())
            if count > 0:
                indicators.append(f"WMI_PERSISTENCE_DETECTED:{count}_SUBSCRIPTIONS")
        except ValueError:
            pass

    return indicators


def _check_linux_persistence() -> list:
    """Check for persistence on Linux."""
    indicators = []

    for cron_path in ["/etc/crontab", "/var/spool/cron/crontabs", "/etc/cron.d"]:
        p = Path(cron_path)
        if p.exists():
            try:
                import time
                if time.time() - p.stat().st_mtime < 86400:
                    indicators.append(f"CRONTAB_RECENTLY_MODIFIED:{p.name}")
            except OSError:
                pass

    auth_keys = Path("/root/.ssh/authorized_keys")
    if auth_keys.exists():
        try:
            import time
            if time.time() - auth_keys.stat().st_mtime < 86400:
                indicators.append("SSH_AUTHORIZED_KEYS_RECENTLY_MODIFIED")
        except OSError:
            pass

    return indicators


def detect_persistence() -> dict:
    indicators = []

    try:
        if platform.system() == "Windows":
            indicators.extend(_check_scheduled_tasks_windows())
            indicators.extend(_check_wmi_subscriptions_windows())
        else:
            indicators.extend(_check_linux_persistence())
    except Exception as e:
        logger.error("Persistence detection error: %s", str(e)[:200])

    seen = set()
    unique = []
    for ind in indicators:
        key = ind.split(":")[0]
        if key not in seen:
            seen.add(key)
            unique.append(ind)

    return {"indicators": unique, "details": {"platform": platform.system()}}
