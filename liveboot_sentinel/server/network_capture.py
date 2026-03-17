"""
network_capture.py - Network-based attack detection for LiveBoot Sentinel.
Fixed to:
1. Push detections to dashboard via WebSocket immediately
2. Store detections as alerts in the database
3. Provide real-time updates via /network-monitor/report
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# ── Attack Signature Thresholds ────────────────────────────────────────────────
PORT_SCAN_THRESHOLD     = 15    # unique ports in window
PORT_SCAN_WINDOW_SECS   = 30
ARP_SCAN_THRESHOLD      = 10    # ARP requests in window
ARP_SCAN_WINDOW_SECS    = 20
AUTH_FAIL_THRESHOLD     = 8     # auth failures in window
AUTH_FAIL_WINDOW_SECS   = 30
EXFIL_THRESHOLD_MB      = 50    # MB sent
LATERAL_IP_THRESHOLD    = 5     # unique IPs contacted

# C2 ports — very specific
C2_PORTS = {4444, 4445, 4446, 1234, 31337, 6666, 9999, 8888, 5555}

# Attack tool destination ports
ATTACK_TOOL_PORTS = {
    22:    "SSH Brute Force",
    23:    "Telnet Attack",
    25:    "SMTP Enumeration",
    445:   "SMB Attack",
    1433:  "MSSQL Attack",
    3306:  "MySQL Attack",
    3389:  "RDP Brute Force",
    5432:  "PostgreSQL Attack",
    6379:  "Redis Attack",
    27017: "MongoDB Attack",
}

# Local ranges — skip
LOCAL_PREFIXES = ("127.", "10.", "192.168.", "172.", "::1", "fe80:")


# ── Host State ─────────────────────────────────────────────────────────────────

class HostTrafficState:
    def __init__(self, ip: str):
        self.ip              = ip
        self.start_time      = time.time()
        self.packets         = 0
        self.bytes_sent      = 0
        self.bytes_received  = 0
        self.dst_ports       = defaultdict(int)
        self.dst_ips         = defaultdict(int)
        self.auth_failures   = 0
        self.syn_count       = 0
        self.arp_count       = 0
        self.c2_connections  = []
        self.attacks         = []
        self.last_updated    = time.time()
        # Time-windowed counters
        self._port_times     = []   # timestamps of port connections
        self._arp_times      = []
        self._auth_fail_times = []

    def to_dict(self) -> dict:
        duration = max(1, time.time() - self.start_time)
        return {
            "ip":                self.ip,
            "duration_seconds":  round(duration),
            "packets":           self.packets,
            "bytes_sent_mb":     round(self.bytes_sent / (1024*1024), 2),
            "bytes_received_mb": round(self.bytes_received / (1024*1024), 2),
            "unique_dst_ports":  len(self.dst_ports),
            "unique_dst_ips":    len(self.dst_ips),
            "auth_failures":     self.auth_failures,
            "syn_packets":       self.syn_count,
            "arp_requests":      self.arp_count,
            "c2_connections":    len(self.c2_connections),
            "attacks_detected":  len(self.attacks),
        }


# ── Monitor ────────────────────────────────────────────────────────────────────

class NetworkAttackMonitor:
    """
    Monitors network traffic and detects attack patterns.
    Calls on_attack_detected callback immediately when attack found.
    """

    def __init__(self):
        self.monitoring          = False
        self.host_states: dict   = {}
        self.detected_attacks    = []
        self._capture_thread     = None
        self._lock               = threading.Lock()
        self.scapy_available     = self._check_scapy()
        # Callback — set by api.py to push to WebSocket + DB
        self.on_attack_detected: Optional[Callable] = None

    def _check_scapy(self) -> bool:
        try:
            import scapy.all
            logger.info("Scapy available — deep packet inspection enabled")
            return True
        except ImportError:
            logger.info("Scapy not available — using netstat monitoring")
            return False

    def start_monitoring(self, target_ip: Optional[str] = None):
        if self.monitoring:
            logger.info("Network monitoring already running")
            return
        self.monitoring = True
        self.clear()
        logger.info("Network monitoring started (target: %s)", target_ip or "all")

        fn = self._capture_scapy if self.scapy_available else self._monitor_netstat
        self._capture_thread = threading.Thread(
            target=fn, args=(target_ip,), daemon=True
        )
        self._capture_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        logger.info("Network monitoring stopped")

    def clear(self):
        with self._lock:
            self.host_states     = {}
            self.detected_attacks = []

    # ── Scapy capture ──────────────────────────────────────────────────────────

    def _capture_scapy(self, target_ip: Optional[str]):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

            def handle(pkt):
                if not self.monitoring:
                    return
                try:
                    self._process_packet(pkt, target_ip)
                except Exception:
                    pass

            bpf = f"host {target_ip}" if target_ip else ""
            sniff(
                prn=handle,
                store=False,
                filter=bpf,
                stop_filter=lambda _: not self.monitoring,
                timeout=7200,
            )
        except Exception as e:
            logger.error("Scapy capture error: %s", str(e)[:200])

    def _process_packet(self, pkt, target_ip: Optional[str]):
        from scapy.all import IP, TCP, UDP, ARP

        src_ip = dst_ip = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_len = len(pkt[IP])
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            pkt_len = len(pkt)
        else:
            return

        if target_ip and src_ip != target_ip and dst_ip != target_ip:
            return

        # Skip local traffic unless it's the target
        if not target_ip:
            if any(src_ip.startswith(p) for p in LOCAL_PREFIXES):
                return

        with self._lock:
            if src_ip not in self.host_states:
                self.host_states[src_ip] = HostTrafficState(src_ip)
            state = self.host_states[src_ip]

        state.packets += 1
        state.bytes_sent += pkt_len
        state.last_updated = time.time()

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_port = tcp.dport
            state.dst_ports[dst_port] += 1
            if dst_ip:
                state.dst_ips[dst_ip] += 1
            state._port_times.append(time.time())

            # SYN packet
            if tcp.flags == 0x02:
                state.syn_count += 1

            # C2 port
            if dst_port in C2_PORTS:
                state.c2_connections.append({
                    "dst_ip": dst_ip, "dst_port": dst_port,
                    "time": datetime.now(timezone.utc).isoformat(),
                })

            # Auth failure (RST from auth ports)
            if tcp.flags & 0x04 and dst_port in {22, 23, 445, 3389, 21, 3306}:
                state.auth_failures += 1
                state._auth_fail_times.append(time.time())

        elif pkt.haslayer(ARP):
            if pkt[ARP].op == 1:
                state.arp_count += 1
                state._arp_times.append(time.time())

        # Run detection after every update
        self._detect_attacks(state)

    # ── Netstat fallback ───────────────────────────────────────────────────────

    def _monitor_netstat(self, target_ip: Optional[str]):
        seen = set()
        while self.monitoring:
            try:
                result = subprocess.run(
                    ["netstat", "-tn"],
                    capture_output=True, text=True,
                    timeout=5, shell=False
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and parts[0].lower().startswith("tcp"):
                            local  = parts[3]
                            remote = parts[4]
                            key = f"{local}-{remote}"
                            if key not in seen:
                                seen.add(key)
                                self._analyze_netstat_conn(local, remote, target_ip)
            except Exception:
                pass
            time.sleep(2)

    def _analyze_netstat_conn(self, local: str, remote: str, target_ip: Optional[str]):
        if target_ip and target_ip not in local and target_ip not in remote:
            return

        port_match = re.search(r":(\d+)$", remote)
        if not port_match:
            return

        port     = int(port_match.group(1))
        remote_ip = remote.rsplit(":", 1)[0]

        if any(remote_ip.startswith(p) for p in LOCAL_PREFIXES):
            return

        src_ip = local.rsplit(":", 1)[0]

        with self._lock:
            if src_ip not in self.host_states:
                self.host_states[src_ip] = HostTrafficState(src_ip)
            state = self.host_states[src_ip]

        state.dst_ports[port] += 1
        state.dst_ips[remote_ip] += 1
        state._port_times.append(time.time())

        if port in C2_PORTS:
            state.c2_connections.append({
                "dst_ip": remote_ip, "dst_port": port,
                "time": datetime.now(timezone.utc).isoformat(),
            })

        self._detect_attacks(state)

    # ── Attack Detection ───────────────────────────────────────────────────────

    def _detect_attacks(self, state: HostTrafficState):
        """Detect attack patterns from host state. Fire callback immediately."""
        now = time.time()
        existing_types = {a["type"] for a in state.attacks}
        new_attacks = []

        # ── Port scan ──────────────────────────────────────────────────────────
        if "PORT_SCAN" not in existing_types:
            # Count ports hit in last PORT_SCAN_WINDOW_SECS
            recent_ports = [t for t in state._port_times
                            if now - t <= PORT_SCAN_WINDOW_SECS]
            unique_recent = len(set(list(state.dst_ports.keys())[-len(recent_ports):]))
            if len(state.dst_ports) >= PORT_SCAN_THRESHOLD:
                new_attacks.append({
                    "type":        "PORT_SCAN",
                    "indicator":   "NETWORK:PORT_SCAN_DETECTED",
                    "technique":   "Network Service Scanning (T1046)",
                    "description": f"Port scan detected: {len(state.dst_ports)} unique ports",
                    "risk":        30,
                    "src_ip":      state.ip,
                    "evidence": {
                        "ports_scanned": len(state.dst_ports),
                        "top_ports": list(state.dst_ports.keys())[:20],
                        "syn_packets": state.syn_count,
                    },
                })

        # ── ARP sweep ─────────────────────────────────────────────────────────
        if "ARP_SWEEP" not in existing_types:
            recent_arp = [t for t in state._arp_times
                          if now - t <= ARP_SCAN_WINDOW_SECS]
            if len(recent_arp) >= ARP_SCAN_THRESHOLD:
                new_attacks.append({
                    "type":        "ARP_SWEEP",
                    "indicator":   "NETWORK:ARP_SCAN_DETECTED",
                    "technique":   "Remote System Discovery (T1018)",
                    "description": f"ARP sweep: {state.arp_count} requests",
                    "risk":        20,
                    "src_ip":      state.ip,
                    "evidence": {"arp_requests": state.arp_count},
                })

        # ── C2 connection ──────────────────────────────────────────────────────
        if "C2_CONNECTION" not in existing_types and state.c2_connections:
            new_attacks.append({
                "type":        "C2_CONNECTION",
                "indicator":   "NETWORK:C2_CONNECTION_DETECTED",
                "technique":   "Command and Control (T1572)",
                "description": f"C2 connection on port {state.c2_connections[-1]['dst_port']}",
                "risk":        50,
                "src_ip":      state.ip,
                "evidence":    {"connections": state.c2_connections[:5]},
            })

        # ── Brute force ────────────────────────────────────────────────────────
        if "BRUTE_FORCE" not in existing_types:
            recent_fails = [t for t in state._auth_fail_times
                            if now - t <= AUTH_FAIL_WINDOW_SECS]
            if len(recent_fails) >= AUTH_FAIL_THRESHOLD:
                new_attacks.append({
                    "type":        "BRUTE_FORCE",
                    "indicator":   "NETWORK:BRUTE_FORCE_DETECTED",
                    "technique":   "Brute Force (T1110)",
                    "description": f"Brute force: {state.auth_failures} auth failures",
                    "risk":        40,
                    "src_ip":      state.ip,
                    "evidence":    {"auth_failures": state.auth_failures},
                })

        # ── Exfiltration ───────────────────────────────────────────────────────
        if "EXFILTRATION" not in existing_types:
            mb_sent = state.bytes_sent / (1024 * 1024)
            if mb_sent >= EXFIL_THRESHOLD_MB:
                new_attacks.append({
                    "type":        "EXFILTRATION",
                    "indicator":   "NETWORK:DATA_EXFILTRATION",
                    "technique":   "Exfiltration Over C2 Channel (T1041)",
                    "description": f"Large transfer: {mb_sent:.1f}MB sent",
                    "risk":        45,
                    "src_ip":      state.ip,
                    "evidence":    {"mb_sent": round(mb_sent, 1)},
                })

        # ── Lateral movement ───────────────────────────────────────────────────
        if "LATERAL_MOVEMENT" not in existing_types:
            if len(state.dst_ips) >= LATERAL_IP_THRESHOLD:
                new_attacks.append({
                    "type":        "LATERAL_MOVEMENT",
                    "indicator":   "NETWORK:LATERAL_MOVEMENT_DETECTED",
                    "technique":   "Remote Services (T1021)",
                    "description": f"Contacted {len(state.dst_ips)} unique IPs",
                    "risk":        35,
                    "src_ip":      state.ip,
                    "evidence":    {
                        "unique_ips": len(state.dst_ips),
                        "sample_ips": list(state.dst_ips.keys())[:5],
                    },
                })

        # ── Fire new attacks ───────────────────────────────────────────────────
        for attack in new_attacks:
            attack["timestamp"] = datetime.now(timezone.utc).isoformat()
            state.attacks.append(attack)

            with self._lock:
                self.detected_attacks.append(attack)

            logger.warning(
                "NETWORK ATTACK: [%s] %s from %s — %s",
                attack["technique"], attack["type"],
                attack["src_ip"], attack["description"][:60]
            )

            # Fire callback to push to WebSocket + DB immediately
            if self.on_attack_detected:
                try:
                    self.on_attack_detected(attack)
                except Exception as e:
                    logger.error("Attack callback error: %s", str(e)[:100])

    # ── Report ─────────────────────────────────────────────────────────────────

    def get_attack_report(self, target_ip: Optional[str] = None) -> dict:
        with self._lock:
            attacks = list(self.detected_attacks)
            if target_ip:
                attacks = [a for a in attacks if a.get("src_ip") == target_ip]

            summaries = {}
            for ip, state in self.host_states.items():
                if not target_ip or ip == target_ip:
                    summaries[ip] = state.to_dict()

        indicators = list({a["indicator"] for a in attacks})
        total_risk = min(sum(a.get("risk", 0) for a in attacks), 100)

        mitre = {}
        for a in attacks:
            tech = a.get("technique", "Unknown")
            if tech not in mitre:
                mitre[tech] = []
            mitre[tech].append(a["description"][:100])

        return {
            "monitoring_active": self.monitoring,
            "scapy_available":   self.scapy_available,
            "attack_count":      len(attacks),
            "attacks_detected":  attacks[:50],
            "indicators":        indicators,
            "risk_score":        total_risk,
            "host_summaries":    summaries,
            "mitre_techniques":  mitre,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_monitor = NetworkAttackMonitor()


def get_monitor() -> NetworkAttackMonitor:
    return _monitor
