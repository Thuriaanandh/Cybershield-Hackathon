# LiveBoot Sentinel
### External OS Intrusion Detection System

> A cybersecurity platform that detects, monitors and forensically reconstructs attacks carried out through external Live OS boot sessions — specifically targeting scenarios where an attacker boots a machine from a Kali Linux USB drive, performs malicious activity, and attempts to leave no trace.

---

## Overview

Modern attackers increasingly use Live OS USB drives (Kali Linux, Tails, Parrot OS) to bypass endpoint security. By booting from USB they bypass Windows Defender and antivirus, EDR agents, login credentials, and all audit logging.

**LiveBoot Sentinel solves this** by operating at a layer below the OS — using RAM dump analysis, network monitoring, post-boot artifact collection and hidden partition forensics to reconstruct exactly what the attacker did, even after the USB is removed and the machine reboots normally.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  Device 2 — Target Machine (Ubuntu 24.04)   │
│                                             │
│  ┌──────────────────────────────────────┐   │
│  │  LBSENTINEL — Hidden Partition       │   │
│  │  /dev/sda3 · 2.8GB · ext4           │   │
│  │  Stores: RAM dumps, snapshots,       │   │
│  │  boot logs, forensic evidence        │   │
│  └──────────────────────────────────────┘   │
│                                             │
│  LiME Kernel Module  →  RAM Capture        │
│  GRUB Hook           →  Pre-boot scripts   │
│  Forensic Agent      →  Post-boot analysis │
└─────────────────┬───────────────────────────┘
                  │  HTTPS (TLS 1.2+)
                  │  API Key Auth
                  ▼
┌─────────────────────────────────────────────┐
│  Device 1 — Server + Dashboard (Windows)    │
│                                             │
│  FastAPI + PostgreSQL 16                    │
│  Passive Network Monitor                    │
│  WebSocket Real-time Broadcaster            │
│  SOC Dashboard (sentinel_pro.html)          │
└─────────────────────────────────────────────┘
```

---

## How Detection Works

### Channel 1 — RAM Dump Analysis (Primary Evidence)

**LiME (Linux Memory Extractor)** — a professional forensic kernel module — captures a full physical RAM image and stores it to the hidden LBSENTINEL partition before and during the Kali session. When Ubuntu reboots, **Volatility3** analyzes this dump to extract:

- Every process that ran with full command line arguments
- All network connections open during the session
- Bash history extracted directly from memory
- Loaded kernel modules indicating which tools were active
- Credential artifacts present in RAM

```bash
# LiME captures full physical RAM
insmod lime.ko "path=/mnt/lbsentinel/dumps/session.lime" "format=lime"

# Volatility3 extracts evidence
python3 vol.py -f session.lime linux.pslist.PsList
python3 vol.py -f session.lime linux.psaux.PsAux
python3 vol.py -f session.lime linux.netstat.NetStat
python3 vol.py -f session.lime linux.bash.Bash
```

**Why RAM evidence survives:** The dump is written to LBSENTINEL — a hidden partition that Kali does not know exists and cannot wipe.

### Channel 2 — Network Traffic Monitoring

Device 1 runs a passive network monitor that captures all traffic from Device 2's IP address in real time. When the attacker runs nmap or hydra, every packet is captured and analyzed:

- Port scans → T1046 Network Service Scanning
- ARP sweeps → T1018 Remote System Discovery
- Brute force → T1110 Brute Force
- C2 connections → T1572 Protocol Tunneling
- Data exfiltration → T1041 Exfiltration Over C2

### Channel 3 — Post-Boot Forensic Artifacts

When Ubuntu reboots after the Kali session the agent scans permanent system records:

- **USB Device Registry** — Windows permanently records every USB device ever connected including the Kali USB vendor ID and volume label. Even after removal `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` contains proof
- **Boot Gap Journal** — GRUB timestamps every boot. A gap between two Ubuntu boots proves an external OS ran in between
- **Windows Event Log** — Events 6006/6008 record unexpected shutdowns consistent with forced reboot for USB boot
- **Prefetch Files** — Windows records every program executed. Tools run from Kali leave permanent prefetch entries
- **File System Timestamps** — Files accessed or modified on the Windows partition during the Kali session are detected

### Channel 4 — LBSENTINEL Hidden Partition

A 2.8GB ext4 partition (`/dev/sda3`) created during setup:

- Invisible to Kali Live OS and normal file managers
- Automatically mounted by GRUB hook before any OS loads
- Stores RAM dumps, process snapshots, boot timestamps
- Cannot be detected or wiped by the attacker

---

## Detection Capabilities

| Attack Tool | Detected Via | MITRE Technique |
|-------------|-------------|----------------|
| nmap | Network monitor | T1046 |
| arp-scan | Network monitor | T1018 |
| hydra | Network monitor | T1110 |
| netcat (reverse shell) | RAM + snapshot | T1059 |
| metasploit | RAM + network | T1572 |
| sqlmap | Snapshot | T1190 |
| gobuster | Snapshot | T1083 |
| hashcat | Snapshot | T1110 |
| mimikatz | RAM analysis | T1003 |
| bloodhound | Snapshot | T1087 |

---

## Project Structure

```
liveboot-sentinel/
│
├── README.md
├── .gitignore
│
├── server/                         Device 1 — FastAPI backend
│   ├── api.py                      Main app + all REST + WebSocket endpoints
│   ├── models.py                   SQLAlchemy ORM models + Pydantic schemas
│   ├── database.py                 Async PostgreSQL connection
│   ├── alert_handler.py            Alert processing and storage
│   ├── websocket.py                WebSocket connection manager (50 conn cap)
│   ├── network_capture.py          Passive network attack detector
│   └── requirements.txt
│
├── agent/                          Device 2 — Forensic agent
│   ├── main.py                     Agent orchestration loop
│   ├── alert_client.py             HTTPS alert sender with retry
│   ├── alert_deduplicator.py       Prevents duplicate alert flooding
│   ├── boot_detector.py            Detects USB / live boot source
│   ├── boot_fingerprint.py         Baseline comparison engine
│   ├── boot_sequence_monitor.py    Boot gap detection
│   ├── disk_monitor.py             Mount point and drive analysis
│   ├── file_integrity_monitor.py   File system change detection
│   ├── forensic_evidence_collector.py  Post-boot forensic scan
│   ├── kernel_fingerprint.py       OS detection from kernel artifacts
│   ├── live_os_command_tracker.py  Command history extraction
│   ├── network_anomaly_detector.py Local network anomaly detection
│   ├── persistence_detector.py     Scheduled task + registry analysis
│   ├── post_boot_analyzer.py       Attack technique aggregator
│   ├── risk_engine.py              Weighted risk score calculator (0-200)
│   ├── sentinel_partition_reader.py LBSENTINEL partition reader + analyzer
│   ├── signature_db.py             OS signature database (15 signatures)
│   ├── tails_detector.py           Tails OS + Tor network detection
│   ├── tamper_evident_logger.py    SHA256 hash-chained audit log
│   └── uefi_monitor.py             UEFI / Secure Boot state analysis
│
├── device2_setup/                  One-time setup scripts for Device 2
│   ├── setup_device2_ubuntu.sh     Main Ubuntu setup script
│   ├── setup_partition_v3.sh       LBSENTINEL partition creation + resize
│   ├── inject_kali_squashfs.sh     Kali USB modification for demonstrations
│   ├── install_persistent_capture.sh  Persistent capture daemon
│   └── fix_agent.sh                Agent patches and improvements
│
├── dashboard/
│   └── sentinel_pro.html           Complete SOC dashboard (single HTML file)
│
└── docs/
    ├── architecture.md
    ├── setup_guide.md
    └── demo_guide.md
```

---

## Setup

### Requirements

**Device 1 (Windows 11):**
- Python 3.11+
- PostgreSQL 16
- OpenSSL (for certificate generation)
- Network adapter on same subnet as Device 2

**Device 2 (Ubuntu 24.04 LTS):**
- Python 3.11+ (pre-installed)
- sudo / root access
- Minimum 10GB free disk space for initial setup

---

### Device 1 — Server Setup

**Step 1 — Install Python dependencies:**
```powershell
pip install fastapi uvicorn[standard] sqlalchemy[asyncio] asyncpg pydantic scapy
```

**Step 2 — Create PostgreSQL database:**
```sql
CREATE USER sentinel_user WITH PASSWORD 'sentinel-db-pass-2026';
CREATE DATABASE liveboot_sentinel OWNER sentinel_user;
GRANT ALL PRIVILEGES ON DATABASE liveboot_sentinel TO sentinel_user;
```

**Step 3 — Generate TLS certificate:**
```powershell
openssl req -x509 -newkey rsa:4096 -keyout certs\server.key `
  -out certs\server.crt -days 365 -nodes `
  -subj "/CN=LiveBootSentinel"
```

**Step 4 — Start server:**
```powershell
cd server
$env:LIVEBOOT_API_KEYS     = "sentinel-dev-key-2026"
$env:LIVEBOOT_CORS_ORIGINS = "*"
$env:LIVEBOOT_ENABLE_DOCS  = "true"
$env:LIVEBOOT_DB_URL       = "postgresql+asyncpg://sentinel_user:sentinel-db-pass-2026@localhost/liveboot_sentinel"
uvicorn api:app --host 0.0.0.0 --port 8443 --ssl-keyfile ..\certs\server.key --ssl-certfile ..\certs\server.crt
```

Expected output:
```
INFO: Network monitoring auto-started
INFO: Application startup complete
INFO: Uvicorn running on https://0.0.0.0:8443
```

**Step 5 — Open dashboard:**
1. Chrome → `https://<Device1-IP>:8443/health` → Advanced → Proceed
2. Open `dashboard/sentinel_pro.html`
3. Enter server URL and API key in config modal

---

### Device 2 — Target Machine Setup

**Step 1 — Create LBSENTINEL hidden partition:**

From Ubuntu:
```bash
sudo bash device2_setup/setup_device2_ubuntu.sh
```

This installs:
- LiME kernel module (`lime-6.17.0-19-generic.ko`)
- GRUB pre-boot hook
- Process snapshot daemon (`/mnt/lbsentinel/scripts/snapshot.py`)
- Forensic agent (`/opt/liveboot-agent/agent.py`)
- Systemd service (`liveboot-sentinel.service`)

**Step 2 — Configure server connection:**
```bash
sudo nano /etc/liveboot-sentinel/env
```
```
LIVEBOOT_ALERT_URL=https://<Device1-IP>:8443/alert
LIVEBOOT_API_KEY=sentinel-dev-key-2026
LIVEBOOT_VERIFY_SSL=false
```

**Step 3 — Reboot to activate:**
```bash
sudo reboot
```

**Step 4 — Verify installation:**
```bash
sudo systemctl status liveboot-sentinel
ls /mnt/lbsentinel/
ls /mnt/lbsentinel/lime/
```

---

### Running the Agent Manually

```bash
sudo python3 /opt/liveboot-agent/agent.py
```

Expected output after a Kali session:
```
LBSENTINEL partition found
Analyzing 26 snapshots from LBSENTINEL
Analysis complete: 5 indicators, risk=105
LIVE OS SESSION CONFIRMED: kali
Snapshots analyzed: 26
Suspicious tools: 2
  [T1059] nc  — Reverse Shell (+35)
  [T1018] arp-scan — Network Discovery (+20)
Alert sent: score=105 level=CRITICAL
```

---

## API Reference

All endpoints require: `X-API-Key: <key>` header

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| POST | `/alert` | Receive forensic alert from agent |
| GET | `/alerts?limit=50` | List all alerts |
| GET | `/alerts/{id}` | Get single alert with full evidence |
| GET | `/hosts` | List all monitored hosts |
| GET | `/stats` | Dashboard statistics summary |
| GET | `/ram-analysis` | List RAM dump analyses |
| GET | `/ram-analysis/{id}` | Volatility3 results for one dump |
| POST | `/network-monitor/start` | Start network monitoring |
| GET | `/network-monitor/report` | Current attack detections |
| WS | `/ws/alerts` | Real-time WebSocket event stream |

WebSocket event types: `alert`, `stats`, `network_attack`, `connected`, `pong`

---

## Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Incident Alerts** | Real-time alert feed, risk distribution donut, full incident detail panel |
| **Host Monitor** | Registry of all monitored endpoints with status and technique history |
| **Network Monitor** | Live network attack feed with Network Risk Index and MITRE mapping |
| **Sentinel Analysis** | Tools detected, commands captured, session intelligence from LBSENTINEL |
| **Tails / Tor Detection** | Dedicated Tails OS detection and Tor circuit monitoring |
| **RAM Evidence** | RAM dump registry with Volatility3 analysis results |
| **Forensic Reports** | Post-incident forensic reports with full evidence breakdown |
| **MITRE ATT&CK** | Complete technique mapping from all evidence sources |
| **Boot Timeline** | Chronological event log with session statistics |

---

## Alert Risk Scoring

Risk scores are calculated by the agent using a weighted system (max 200):

| Indicator | Weight |
|-----------|--------|
| Live OS confirmed | +30 |
| Kali detected | +30 |
| Metasploit / msfconsole | +50 |
| Mimikatz / credential dump | +50 |
| Reverse shell (nc/bash) | +35-40 |
| Hydra brute force | +40 |
| Nmap port scan | +30 |
| ARP scan | +20 |
| Boot gap detected | +20 |
| RAM dump available | +10 |

Thresholds: `NORMAL < 30 ≤ WARNING < 50 ≤ CRITICAL`

---

## Supported OS Signatures

The signature database detects 15 live OS families:

| OS | Threat Level | Key Indicators |
|----|-------------|----------------|
| Kali Linux | 5 (Critical) | kali label, offensive tools |
| Tails | 5 (Critical) | amnesia, Tor routing |
| Parrot OS | 4 (High) | parrot label |
| BlackArch | 5 (Critical) | blackarch repos |
| DEFT Linux | 4 (High) | forensic distro |
| BackBox | 3 (Medium) | security distro |
| Whonix | 4 (High) | anonymity routing |
| Ubuntu Live | 1 (Low) | legitimate use |

---

## Security Architecture

- TLS 1.2+ enforced on all agent-to-server communication
- HMAC timing-safe API key authentication
- Per-IP rate limiting — 60 requests/minute
- Pydantic v2 strict input validation on all endpoints
- No `shell=True` in any subprocess call throughout codebase
- Credentials never logged or transmitted in plaintext
- SQLAlchemy ORM — no raw SQL strings
- CORS origin whitelist
- SHA256 hash-chained tamper-evident agent audit log
- WebSocket connection cap — 50 concurrent connections

---

## Evidence Reliability

| Evidence Type | Source | Admissibility |
|--------------|--------|--------------|
| USB device registry | Windows USBSTOR hive | Permanent — cannot be deleted by attacker |
| Boot gap proof | GRUB timestamps | System-level log — tamper evident |
| RAM process list | LiME + Volatility3 | Industry standard forensic methodology |
| Network traffic | Passive capture on Device 1 | Independent timestamped evidence |
| Bash history from RAM | Volatility3 linux.bash | Direct memory extraction |
| Prefetch execution records | Windows prefetch | Permanent OS execution record |
| MITRE ATT&CK mapping | Multi-source correlation | International standard framework |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI 0.115 + Python 3.11 |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 async |
| Real-time | WebSocket (FastAPI native) |
| RAM Capture | LiME — Linux Memory Extractor |
| RAM Analysis | Volatility3 |
| Network Monitor | Scapy + raw socket fallback |
| Dashboard | Pure HTML5 + CSS3 + Vanilla JS |
| Agent | Python 3.11 — zero external dependencies |
| Transport Security | OpenSSL TLS 1.2+ |
| Forensic Framework | Volatility3 + custom analyzers |

---

## Tested Attack Scenarios and Results

All the following were successfully detected and reconstructed:

```
Attack Session — Device 2 (Kali USB)
════════════════════════════════════

$ sudo arp-scan -l
  → DETECTED: Network Discovery T1018 [Network Monitor + Snapshot]

$ nmap -sS 11.12.66.26
  → DETECTED: Port Scanning T1046 [Network Monitor]

$ nmap -sV -sC 11.12.66.26
  → DETECTED: Service Enumeration T1046 [Network Monitor]

$ nmap -O 11.12.66.26
  → DETECTED: OS Fingerprinting T1082 [Network Monitor]

$ hydra -l root -P rockyou.txt ssh://11.12.66.26
  → DETECTED: SSH Brute Force T1110 [Network Monitor + Snapshot]

$ nc -lvnp 4444
  → DETECTED: Reverse Shell Listener T1059 [Snapshot + RAM]

Result: CRITICAL alert — score 105/200
Evidence: 26 snapshots, 2 tools, 4 commands, 50 processes captured
Dashboard: Kali confirmed, full MITRE map, forensic report generated
```

---

## Demo Guide

### Full End-to-End Test

1. Start server on Device 1
2. Open `sentinel_pro.html` in Chrome — connect to server
3. Plug Kali USB into Device 2
4. Reboot Device 2 → F12 → select USB → Live system
5. In Kali terminal run attack commands (nmap, arp-scan, hydra, nc)
6. Wait 60 seconds for snapshot cycles
7. `sudo shutdown now`
8. Ubuntu boots back — agent runs automatically via systemd
9. Dashboard shows CRITICAL alert with full evidence reconstruction

### Verify Evidence on Device 2

```bash
# Check snapshots captured during Kali session
ls /mnt/lbsentinel/snapshots/

# Check boot log
cat /mnt/lbsentinel/logs/boot.log

# Check capture log
cat /mnt/lbsentinel/logs/kali_capture.log

# View latest snapshot contents
python3 -c "
import json; from pathlib import Path
s = sorted(Path('/mnt/lbsentinel/snapshots').glob('*.json'))[-1]
d = json.loads(s.read_text())
print('OS:', d['os'])
print('Tools:', [t['tool'] for t in d.get('suspicious_tools',[])])
print('Commands:', d.get('recent_commands',[])[:5])
"
```

---

## Notes

- This tool is designed for authorized security monitoring demonstrations only
- Unauthorized use against systems without explicit permission is illegal
- Developed for academic research and law enforcement demonstration purposes
- All evidence collection follows forensically sound methodologies

---

*LiveBoot Sentinel — Detecting the Undetectable*
