"""
ram_dump_analyzer.py - RAM dump forensic analysis module.
Locates memory dump files, runs Volatility3 plugins, reconstructs
attacker activity from a Live OS session.

Security: no shell=True, validated paths, sanitized output,
          credentials never logged, subprocess timeouts enforced.
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

# ── Constants ──────────────────────────────────────────────────────────────────

# Search paths for RAM dump files
DUMP_SEARCH_PATHS_WINDOWS = [
    Path("C:/ProgramData/LiveBootSentinel/memory/dumps"),
    Path("C:/Windows/Temp"),
    Path("C:/Temp"),
    Path(os.environ.get("USERPROFILE", "C:/Users/Public")),
]

SUPPORTED_EXTENSIONS = {".raw", ".mem", ".lime", ".bin", ".dmp", ".vmem"}

# Maximum dump file age to analyze (hours)
MAX_DUMP_AGE_HOURS = 72

# Volatility3 subprocess timeout per plugin (seconds)
PLUGIN_TIMEOUT = 120

# Maximum lines to parse per plugin output (prevent memory exhaustion)
MAX_LINES_PER_PLUGIN = 5000

# Maximum string length for sanitized output fields
MAX_FIELD_LEN = 500

# Known attacker tools and their risk scores
SUSPICIOUS_TOOL_SIGNATURES = {
    "nmap":         ("Port Scanning",        20),
    "hydra":        ("Brute Force",           30),
    "msfconsole":   ("Metasploit",            40),
    "msfvenom":     ("Payload Generation",    40),
    "mimikatz":     ("Credential Dumping",    50),
    "wce":          ("Credential Dumping",    50),
    "procdump":     ("Credential Dumping",    35),
    "pwdump":       ("Credential Dumping",    45),
    "netcat":       ("Reverse Shell",         35),
    "nc.exe":       ("Reverse Shell",         35),
    "ncat":         ("Reverse Shell",         35),
    "socat":        ("Reverse Shell",         30),
    "bloodhound":   ("AD Reconnaissance",     40),
    "sharphound":   ("AD Reconnaissance",     40),
    "rubeus":       ("Kerberos Attack",        45),
    "hashcat":      ("Password Cracking",     35),
    "john":         ("Password Cracking",     30),
    "aircrack":     ("Wireless Attack",       25),
    "sqlmap":       ("SQL Injection",          30),
    "nikto":        ("Web Vulnerability Scan", 20),
    "metasploit":   ("Metasploit",            40),
    "empire":       ("C2 Framework",          45),
    "cobalt":       ("C2 Framework",          50),
    "psexec":       ("Lateral Movement",      35),
    "wmiexec":      ("Lateral Movement",      35),
}

# Risk score weights for RAM analysis findings
RAM_RISK_WEIGHTS = {
    "suspicious_tool":        40,
    "credential_found":       35,
    "reverse_shell_detected": 40,
    "network_c2_connection":  35,
    "injected_process":       45,
    "suspicious_dll":         30,
}


# ── Sanitization Helpers ───────────────────────────────────────────────────────

def _sanitize(value: str, max_len: int = MAX_FIELD_LEN) -> str:
    """Strip control characters and cap length."""
    if not isinstance(value, str):
        value = str(value)
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    return value.strip()[:max_len]


def _sanitize_path(path_str: str) -> Optional[Path]:
    """
    Validate and return a Path only if it's safe (no traversal, exists).
    """
    try:
        p = Path(path_str).resolve()
        # Prevent path traversal
        if ".." in p.parts:
            return None
        return p
    except (ValueError, OSError):
        return None


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


# ── RAM Dump Discovery ─────────────────────────────────────────────────────────

def _get_usb_drive_paths() -> list:
    """Get all removable USB drive paths on Windows."""
    drives = []
    try:
        ps_cmd = (
            "Get-WmiObject Win32_LogicalDisk "
            "| Where-Object {$_.DriveType -eq 2} "
            "| Select-Object -ExpandProperty DeviceID"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10, shell=False
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                drive = line.strip()
                if re.match(r"^[A-Z]:$", drive):
                    drives.append(Path(drive + "\\"))
    except Exception:
        pass
    return drives


def _is_valid_dump_file(path: Path) -> bool:
    """
    Validate a dump file:
    - Must exist and be a regular file
    - Must have a supported extension
    - Must be at least 64MB (real dumps are large)
    - Must not be too old
    """
    try:
        if not path.is_file():
            return False
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return False
        stat = path.stat()
        # Minimum 64MB
        if stat.st_size < 64 * 1024 * 1024:
            logger.debug("Skipping %s — too small (%d bytes)", path.name, stat.st_size)
            return False
        # Check age
        age_hours = (time.time() - stat.st_mtime) / 3600
        if age_hours > MAX_DUMP_AGE_HOURS:
            logger.debug("Skipping %s — too old (%.1f hours)", path.name, age_hours)
            return False
        return True
    except (OSError, PermissionError):
        return False


def find_ram_dump() -> Optional[Path]:
    """
    Search all configured locations for a valid RAM dump file.
    Returns the most recently modified valid dump, or None.
    """
    search_paths = list(DUMP_SEARCH_PATHS_WINDOWS)

    # Add USB drives
    if platform.system() == "Windows":
        search_paths.extend(_get_usb_drive_paths())

    candidates = []

    for base_path in search_paths:
        if not base_path.exists():
            continue
        try:
            for ext in SUPPORTED_EXTENSIONS:
                for dump_file in base_path.glob(f"*{ext}"):
                    safe_path = _sanitize_path(str(dump_file))
                    if safe_path and _is_valid_dump_file(safe_path):
                        candidates.append(safe_path)
            # Also check one level deep
            for subdir in base_path.iterdir():
                if subdir.is_dir():
                    for ext in SUPPORTED_EXTENSIONS:
                        for dump_file in subdir.glob(f"*{ext}"):
                            safe_path = _sanitize_path(str(dump_file))
                            if safe_path and _is_valid_dump_file(safe_path):
                                candidates.append(safe_path)
        except (OSError, PermissionError):
            continue

    if not candidates:
        logger.info("No valid RAM dump files found")
        return None

    # Return most recently modified
    most_recent = max(candidates, key=lambda p: p.stat().st_mtime)
    logger.info(
        "RAM dump found: %s (%.1f MB)",
        most_recent.name,
        most_recent.stat().st_size / (1024 * 1024)
    )
    return most_recent


# ── Volatility3 Runner ─────────────────────────────────────────────────────────

def _find_volatility() -> Optional[str]:
    """
    Find the Volatility3 vol.py script or vol executable.
    Checks common installation paths.
    """
    candidates = [
        "vol",
        "vol.py",
        "volatility3",
        "python vol.py",
    ]

    # Common install paths
    vol_paths = [
        Path("C:/Tools/volatility3/vol.py"),
        Path("C:/volatility3/vol.py"),
        Path("/usr/local/bin/vol"),
        Path("/usr/bin/vol"),
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "volatility3" / "vol.py",
        Path(os.environ.get("USERPROFILE", "C:/Users/Public")) / "volatility3" / "vol.py",
    ]

    for path in vol_paths:
        if path.exists():
            logger.info("Volatility3 found at: %s", path)
            return str(path)

    # Try PATH
    try:
        result = subprocess.run(
            ["vol", "--help"],
            capture_output=True, text=True, timeout=5, shell=False
        )
        if result.returncode in (0, 1):
            return "vol"
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            ["python", "-c", "import volatility3"],
            capture_output=True, text=True, timeout=5, shell=False
        )
        if result.returncode == 0:
            return "python -m volatility3"
    except FileNotFoundError:
        pass

    logger.warning("Volatility3 not found — RAM analysis will be limited")
    return None


def _run_volatility_plugin(
    vol_path: str,
    dump_file: Path,
    plugin: str,
    extra_args: list = None,
) -> Optional[list]:
    """
    Run a single Volatility3 plugin safely.
    Returns parsed lines or None on failure.

    Security: no shell=True, timeout enforced, output capped.
    """
    if extra_args is None:
        extra_args = []

    # Build command as list — never use shell=True
    dump_str = str(dump_file)

    if vol_path.endswith(".py"):
        cmd = ["python", vol_path, "-f", dump_str, "-q"] + extra_args + [plugin]
    elif vol_path == "vol" or vol_path == "volatility3":
        cmd = [vol_path, "-f", dump_str, "-q"] + extra_args + [plugin]
    else:
        cmd = vol_path.split() + ["-f", dump_str, "-q"] + extra_args + [plugin]

    logger.info("Running plugin: %s", plugin)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PLUGIN_TIMEOUT,
            shell=False,  # SECURITY: never shell=True
        )

        if result.returncode not in (0, 1):
            logger.warning(
                "Plugin %s returned code %d: %s",
                plugin, result.returncode,
                result.stderr[:200]
            )
            return None

        lines = result.stdout.strip().splitlines()
        # Cap output to prevent memory exhaustion
        return lines[:MAX_LINES_PER_PLUGIN]

    except subprocess.TimeoutExpired:
        logger.error("Plugin %s timed out after %ds", plugin, PLUGIN_TIMEOUT)
        return None
    except FileNotFoundError:
        logger.error("Volatility3 executable not found: %s", cmd[0])
        return None
    except Exception as e:
        logger.error("Plugin %s failed: %s", plugin, str(e)[:200])
        return None


# ── Plugin Output Parsers ──────────────────────────────────────────────────────

def _parse_pslist(lines: list) -> list:
    """
    Parse windows.pslist output into structured process list.
    Format: PID PPID ImageFileName Offset Threads Handles SessionId Wow64 CreateTime ExitTime
    """
    processes = []
    if not lines:
        return processes

    for line in lines:
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("*") or line.startswith("Volatility"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            proc = {
                "pid":        _safe_int(parts[0]),
                "ppid":       _safe_int(parts[1]),
                "name":       _sanitize(parts[2], 100),
                "threads":    _safe_int(parts[4]) if len(parts) > 4 else 0,
                "create_time": _sanitize(parts[8], 30) if len(parts) > 8 else "",
            }
            processes.append(proc)
        except (IndexError, ValueError):
            continue

    return processes[:500]  # Cap


def _parse_cmdline(lines: list) -> list:
    """
    Parse windows.cmdline output into command line entries.
    Format: PID Process Args
    """
    commands = []
    if not lines:
        return commands

    for line in lines:
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("Volatility"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            cmd = {
                "pid":     _safe_int(parts[0]),
                "process": _sanitize(parts[1], 100),
                "cmdline": _sanitize(parts[2], 500) if len(parts) > 2 else "",
            }
            commands.append(cmd)
        except (IndexError, ValueError):
            continue

    return commands[:200]


def _parse_netstat(lines: list) -> list:
    """
    Parse windows.netstat output into network connection list.
    Format: Offset Proto LocalAddr ForeignAddr State PID Owner Created
    """
    connections = []
    if not lines:
        return connections

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Offset") or line.startswith("Volatility"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            conn = {
                "protocol":    _sanitize(parts[1], 10),
                "local_addr":  _sanitize(parts[2], 50),
                "remote_addr": _sanitize(parts[3], 50),
                "state":       _sanitize(parts[4], 20),
                "pid":         _safe_int(parts[5]) if len(parts) > 5 else 0,
                "process":     _sanitize(parts[6], 100) if len(parts) > 6 else "",
            }
            connections.append(conn)
        except (IndexError, ValueError):
            continue

    return connections[:200]


def _parse_dlllist(lines: list) -> list:
    """
    Parse windows.dlllist output — extract loaded DLL paths.
    Focus on DLLs loaded from suspicious locations.
    """
    modules = []
    suspicious_paths = [
        "\\temp\\", "\\tmp\\", "\\public\\",
        "\\appdata\\local\\temp\\",
        "\\programdata\\",
    ]

    if not lines:
        return modules

    current_pid = 0
    current_process = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Volatility"):
            continue

        # Process header line
        if "pid" in line.lower() and "process" in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                current_pid = _safe_int(parts[0])
                current_process = _sanitize(parts[1], 100) if len(parts) > 1 else ""
            continue

        # DLL path line
        if line.startswith("0x") or "\\" in line:
            path_lower = line.lower()
            if any(sus in path_lower for sus in suspicious_paths):
                modules.append({
                    "pid":     current_pid,
                    "process": current_process,
                    "path":    _sanitize(line, 300),
                    "suspicious": True,
                })

    return modules[:100]


def _parse_hashdump(lines: list) -> list:
    """
    Parse windows.hashdump output.
    SECURITY: Never log actual hash values — only log that hashes were found.
    Return count and usernames only, not actual hashes.
    """
    credentials = []
    if not lines:
        return credentials

    for line in lines:
        line = line.strip()
        if not line or line.startswith("User") or line.startswith("Volatility"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            username = _sanitize(parts[0], 50)
            if username and not username.startswith("*"):
                credentials.append({
                    "username": username,
                    "hash_present": True,
                    # SECURITY: Never store or log actual hash values
                    "note": "Hash found — not logged for security",
                })

    return credentials[:50]


def _parse_hivelist(lines: list) -> list:
    """Parse windows.registry.hivelist output."""
    hives = []
    if not lines:
        return hives

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Offset") or line.startswith("Volatility"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            hives.append({
                "offset": _sanitize(parts[0], 20),
                "path":   _sanitize(parts[-1], 200),
            })

    return hives[:50]


# ── Suspicious Activity Detection ─────────────────────────────────────────────

def _detect_suspicious_processes(
    processes: list,
    commands: list,
) -> tuple:
    """
    Detect suspicious tools and reconstruct attacker commands.
    Returns (suspicious_tools list, reconstructed_commands list, risk_score_increment).
    """
    suspicious_tools = []
    reconstructed_commands = []
    risk_increment = 0
    seen_tools = set()

    # Check process names
    for proc in processes:
        name_lower = proc.get("name", "").lower()
        for tool, (technique, score) in SUSPICIOUS_TOOL_SIGNATURES.items():
            if tool in name_lower and tool not in seen_tools:
                seen_tools.add(tool)
                suspicious_tools.append({
                    "tool":      _sanitize(proc["name"], 50),
                    "technique": technique,
                    "pid":       proc.get("pid", 0),
                    "ppid":      proc.get("ppid", 0),
                    "risk_score": score,
                })
                risk_increment += score
                logger.warning(
                    "SUSPICIOUS PROCESS: %s (PID %d) — %s [+%d risk]",
                    proc["name"][:30], proc.get("pid", 0), technique, score
                )

    # Check command lines
    for cmd in commands:
        cmdline_lower = cmd.get("cmdline", "").lower()
        proc_lower = cmd.get("process", "").lower()
        combined = f"{proc_lower} {cmdline_lower}"

        for tool, (technique, score) in SUSPICIOUS_TOOL_SIGNATURES.items():
            if tool in combined:
                reconstructed_commands.append({
                    "process": _sanitize(cmd.get("process", ""), 50),
                    "command": _sanitize(cmd.get("cmdline", ""), 300),
                    "pid":     cmd.get("pid", 0),
                    "technique": technique,
                })
                if tool not in seen_tools:
                    seen_tools.add(tool)
                    risk_increment += score // 2  # Partial score if only in cmdline

        # Detect reverse shell patterns
        reverse_shell_patterns = [
            r"bash\s+-i",
            r"nc\s+.*-e",
            r"ncat\s+.*-e",
            r"powershell.*iex",
            r"cmd.*\/c.*echo.*\|",
            r"-encodedcommand",
        ]
        for pattern in reverse_shell_patterns:
            if re.search(pattern, cmdline_lower):
                reconstructed_commands.append({
                    "process":   _sanitize(cmd.get("process", ""), 50),
                    "command":   _sanitize(cmd.get("cmdline", ""), 300),
                    "pid":       cmd.get("pid", 0),
                    "technique": "Reverse Shell",
                })
                risk_increment += RAM_RISK_WEIGHTS["reverse_shell_detected"]
                break

    return suspicious_tools, reconstructed_commands, risk_increment


def _detect_suspicious_network(connections: list) -> tuple:
    """
    Flag suspicious network connections from memory.
    Returns (flagged_connections, risk_increment).
    """
    flagged = []
    risk_increment = 0

    # Known C2 ports
    c2_ports = {4444, 4445, 1234, 31337, 8888, 9999, 6666, 1337}

    # Local ranges — skip these
    local_prefixes = ("127.", "10.", "192.168.", "172.")

    for conn in connections:
        remote = conn.get("remote_addr", "")
        if not remote or remote in ("0.0.0.0", "::", "*"):
            continue

        # Skip local connections
        if any(remote.startswith(p) for p in local_prefixes):
            continue

        # Check port
        port_match = re.search(r":(\d+)$", remote)
        if port_match:
            port = int(port_match.group(1))
            if port in c2_ports:
                flagged.append({
                    **conn,
                    "reason": f"C2_PORT_{port}",
                })
                risk_increment += RAM_RISK_WEIGHTS["network_c2_connection"]
                logger.warning(
                    "C2 connection detected: %s → %s (port %d)",
                    conn.get("local_addr", "?")[:30],
                    remote[:30], port
                )

    return flagged, risk_increment


# ── Main Analysis Function ─────────────────────────────────────────────────────

def analyze_ram_dump() -> dict:
    """
    Main RAM forensic analysis function.

    1. Locate RAM dump
    2. Run Volatility3 plugins
    3. Parse and structure results
    4. Detect suspicious activity
    5. Return comprehensive forensic report

    Returns:
        dict with full forensic report ready to send to server.
        Returns empty report dict if no dump found or analysis fails.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # Base report structure
    report = {
        "ram_dump_file":       None,
        "analysis_timestamp":  timestamp,
        "volatility_available": False,
        "processes":           [],
        "network_connections": [],
        "commands_detected":   [],
        "loaded_modules":      [],
        "credentials_found":   [],
        "registry_hives":      [],
        "suspicious_tools":    [],
        "indicators":          [],
        "risk_score_increment": 0,
        "analysis_complete":   False,
        "errors":              [],
    }

    # ── Step 1: Find RAM dump ──────────────────────────────────────────────
    dump_file = find_ram_dump()
    if not dump_file:
        logger.info("RAM dump analysis: no dump file found — skipping")
        report["indicators"].append("NO_RAM_DUMP_FOUND")
        return report

    report["ram_dump_file"] = _sanitize(str(dump_file.name), 100)
    logger.info("Starting RAM analysis on: %s", dump_file.name)

    # ── Step 2: Find Volatility3 ───────────────────────────────────────────
    vol_path = _find_volatility()
    if not vol_path:
        logger.warning("Volatility3 not available — performing limited analysis")
        report["errors"].append("VOLATILITY3_NOT_FOUND")
        # Still return what we found (the dump exists = evidence)
        report["indicators"].append("RAM_DUMP_FOUND_VOLATILITY_UNAVAILABLE")
        report["risk_score_increment"] = 20  # Dump exists = suspicious
        return report

    report["volatility_available"] = True

    # ── Step 3: Run plugins ────────────────────────────────────────────────
    plugin_results = {}
    plugins_to_run = [
        ("windows.pslist",            "Process list"),
        ("windows.cmdline",           "Command lines"),
        ("windows.netstat",           "Network connections"),
        ("windows.dlllist",           "Loaded modules"),
        ("windows.hashdump",          "Credential hashes"),
        ("windows.registry.hivelist", "Registry hives"),
    ]

    for plugin, description in plugins_to_run:
        logger.info("Running Volatility3 plugin: %s (%s)", plugin, description)
        lines = _run_volatility_plugin(vol_path, dump_file, plugin)
        if lines is not None:
            plugin_results[plugin] = lines
            logger.info("Plugin %s: %d lines", plugin, len(lines))
        else:
            report["errors"].append(f"PLUGIN_FAILED:{plugin}")

    # ── Step 4: Parse results ──────────────────────────────────────────────

    # Processes
    if "windows.pslist" in plugin_results:
        report["processes"] = _parse_pslist(plugin_results["windows.pslist"])
        logger.info("Parsed %d processes", len(report["processes"]))

    # Commands
    if "windows.cmdline" in plugin_results:
        report["commands_detected"] = _parse_cmdline(plugin_results["windows.cmdline"])
        logger.info("Parsed %d command lines", len(report["commands_detected"]))

    # Network
    if "windows.netstat" in plugin_results:
        report["network_connections"] = _parse_netstat(plugin_results["windows.netstat"])
        logger.info("Parsed %d network connections", len(report["network_connections"]))

    # Modules
    if "windows.dlllist" in plugin_results:
        report["loaded_modules"] = _parse_dlllist(plugin_results["windows.dlllist"])
        logger.info("Parsed %d suspicious modules", len(report["loaded_modules"]))

    # Credentials — SECURITY: only count, never log values
    if "windows.hashdump" in plugin_results:
        report["credentials_found"] = _parse_hashdump(plugin_results["windows.hashdump"])
        if report["credentials_found"]:
            logger.warning(
                "CREDENTIALS IN MEMORY: %d accounts found (hashes not logged)",
                len(report["credentials_found"])
            )
            report["risk_score_increment"] += (
                RAM_RISK_WEIGHTS["credential_found"] * len(report["credentials_found"])
            )

    # Registry
    if "windows.registry.hivelist" in plugin_results:
        report["registry_hives"] = _parse_hivelist(
            plugin_results["windows.registry.hivelist"]
        )

    # ── Step 5: Detect suspicious activity ────────────────────────────────
    suspicious_tools, reconstructed_cmds, proc_risk = _detect_suspicious_processes(
        report["processes"],
        report["commands_detected"],
    )
    report["suspicious_tools"].extend(suspicious_tools)
    report["commands_detected"].extend(reconstructed_cmds)
    report["risk_score_increment"] += proc_risk

    # Flag suspicious network connections
    flagged_conns, net_risk = _detect_suspicious_network(report["network_connections"])
    if flagged_conns:
        report["network_connections"] = flagged_conns
        report["risk_score_increment"] += net_risk

    # Flag suspicious modules
    if report["loaded_modules"]:
        for mod in report["loaded_modules"]:
            report["risk_score_increment"] += RAM_RISK_WEIGHTS["suspicious_dll"]

    # ── Step 6: Build indicators ───────────────────────────────────────────
    indicators = []

    if report["suspicious_tools"]:
        for tool in report["suspicious_tools"]:
            safe_tool = re.sub(r"[^\w]", "_", tool["tool"].upper())[:30]
            indicators.append(f"RAM_SUSPICIOUS_TOOL:{safe_tool}")

    if report["credentials_found"]:
        indicators.append(
            f"RAM_CREDENTIALS_IN_MEMORY:{len(report['credentials_found'])}_ACCOUNTS"
        )

    if flagged_conns:
        indicators.append(f"RAM_C2_CONNECTIONS:{len(flagged_conns)}")

    if report["loaded_modules"]:
        indicators.append(
            f"RAM_SUSPICIOUS_MODULES:{len(report['loaded_modules'])}"
        )

    for cmd in report["commands_detected"]:
        if cmd.get("technique") == "Reverse Shell":
            indicators.append("RAM_REVERSE_SHELL_DETECTED")
            break

    indicators.append("RAM_DUMP_ANALYZED")
    report["indicators"] = indicators

    # Cap risk increment
    report["risk_score_increment"] = min(report["risk_score_increment"], 100)
    report["analysis_complete"] = True

    # ── Step 7: Summary logging ────────────────────────────────────────────
    logger.info(
        "RAM analysis complete: %d processes, %d suspicious tools, "
        "%d connections, risk_increment=%d",
        len(report["processes"]),
        len(report["suspicious_tools"]),
        len(report["network_connections"]),
        report["risk_score_increment"],
    )

    if report["suspicious_tools"]:
        logger.warning("SUSPICIOUS TOOLS IN MEMORY:")
        for tool in report["suspicious_tools"]:
            logger.warning(
                "  [%s] PID=%d technique=%s risk=+%d",
                tool["tool"][:30], tool["pid"],
                tool["technique"], tool["risk_score"]
            )

    return report


# ── Volatility3 Installation Helper ───────────────────────────────────────────

def check_volatility_installed() -> dict:
    """
    Check if Volatility3 is installed and return status.
    Provides installation instructions if not found.
    """
    vol_path = _find_volatility()
    if vol_path:
        return {
            "installed": True,
            "path": vol_path,
            "message": f"Volatility3 found at: {vol_path}",
        }
    else:
        return {
            "installed": False,
            "path": None,
            "message": (
                "Volatility3 not found. Install with: "
                "pip install volatility3  OR  "
                "git clone https://github.com/volatilityfoundation/volatility3"
            ),
        }
