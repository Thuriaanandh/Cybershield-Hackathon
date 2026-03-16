# LiveBoot Sentinel
### External OS Intrusion Detection System

> **Version:** 1.0.0 | **Platform:** Windows / Linux | **Stack:** Python · FastAPI · SQLAlchemy · WebSocket | **Classification:** CONFIDENTIAL

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Architecture](#2-system-architecture)
3. [Endpoint Agent Modules](#3-endpoint-agent-modules)
4. [Risk Scoring Engine](#4-risk-scoring-engine)
5. [Alert Server API](#5-alert-server-api)
6. [OS Signature Database](#6-os-signature-database)
7. [Security Design](#7-security-design)
8. [Deployment Reference](#8-deployment-reference)
9. [Project Structure](#9-project-structure)

---

## 1. Overview

LiveBoot Sentinel is a production-quality, multi-device security monitoring system designed to detect when any machine on a network boots from an external live operating system — such as Kali Linux, Tails, Parrot OS, or any other forensic or penetration testing environment. It operates continuously, collects forensic telemetry from endpoint agents, and streams real-time alerts to a central SOC dashboard.

The system is designed around a three-tier architecture: an endpoint agent running on monitored machines, a central FastAPI alert server, and a real-time SOC dashboard. All communications use HTTPS/TLS with API key authentication, and all logs are tamper-evident using SHA256 hash chaining.

### Key Capabilities

- Detects USB and removable media boot sources using `lsblk` (Linux) and WMI (Windows)
- Identifies live OS kernel signatures: Kali, Tails, Parrot, BlackArch, Whonix, and 11 others
- Detects `squashfs`, `overlayfs`, `aufs` mounts characteristic of live OS environments
- Compares boot fingerprints against a stored baseline — flags any deviation
- Analyzes UEFI boot entries via `efibootmgr` (Linux) and `bcdedit` (Windows)
- Computes weighted risk scores across all indicators with NORMAL / WARNING / CRITICAL classification
- Sends cryptographically authenticated HTTPS alerts to a central server
- Broadcasts real-time events to connected dashboards via WebSocket
- Maintains tamper-evident append-only logs with SHA256 hash chaining
- Supports multiple simultaneous endpoint agents reporting to one server

---

## 2. System Architecture

```
┌─────────────────────────────┐
│       ENDPOINT AGENT        │   Device 3 (monitored machine)
│  boot_detector              │
│  kernel_fingerprint         │
│  disk_monitor               │
│  uefi_monitor               │
│  boot_fingerprint           │──── HTTPS POST /alert ────▶
│  risk_engine                │     X-API-Key header
│  tamper_evident_logger      │
└─────────────────────────────┘

                    ┌─────────────────────────────┐
                    │      FASTAPI SERVER         │   Device 1
                    │  POST   /alert              │
                    │  GET    /alerts             │
                    │  GET    /alerts/critical    │──── WebSocket ────▶
                    │  GET    /hosts              │     /ws/alerts
                    │  GET    /stats              │
                    │  SQLite / PostgreSQL        │
                    └─────────────────────────────┘

                                        ┌─────────────────────────────┐
                                        │      SOC DASHBOARD          │   Device 2
                                        │  Real-time alert feed       │
                                        │  Host monitoring table      │
                                        │  Risk visualization         │
                                        │  Stats panel                │
                                        └─────────────────────────────┘
```

### Data Flow

1. Endpoint agent runs all detection modules every **10 seconds**
2. Risk engine aggregates indicators and computes a weighted score
3. If score exceeds threshold (**50**), agent POSTs alert to server via HTTPS
4. Server validates input with Pydantic, persists to database via SQLAlchemy ORM
5. Server broadcasts alert event to all connected WebSocket clients immediately
6. Dashboard receives the push event and updates the feed without page refresh

### Three-Device Deployment

| Device | Role | What Runs |
|--------|------|-----------|
| Device 1 | Alert API Server | `uvicorn api:app --port 8443` |
| Device 2 | SOC Dashboard | Antigravity UI at `localhost:5173` |
| Device 3 | Target / Monitored Machine | `python main.py` (agent) |

---

## 3. Endpoint Agent Modules

The agent is a pure Python application with **zero third-party dependencies**. All detection uses Python stdlib on both Windows and Linux. It runs a detection cycle every 10 seconds and sends alerts only when the risk score exceeds the configured threshold.

| Module | Function |
|--------|----------|
| `boot_detector.py` | Detects USB/removable boot using `lsblk` (Linux) or `Win32_DiskDrive` WMI (Windows). Emits `USB_BOOT_DETECTED`. |
| `kernel_fingerprint.py` | Reads `uname -a` (Linux) or `platform` module (Windows). Scans for 11 live OS keywords in kernel string, `os-release`, and `/proc/cmdline`. |
| `disk_monitor.py` | Scans `/proc/mounts` (Linux) or `Win32_LogicalDisk` (Windows) for squashfs, overlayfs, tmpfs-as-root, and suspicious mount points. |
| `boot_fingerprint.py` | Collects 5-field fingerprint (boot device, kernel, secure boot, root FS, disk UUID) and diffs against stored baseline. |
| `uefi_monitor.py` | Parses `efibootmgr` (Linux) or `bcdedit` (Windows) for USB boot entries and boot order changes. |
| `signature_db.py` | OS fingerprint database with 15 entries across penetration testing, anonymity, forensics, and live environment categories. |
| `risk_engine.py` | Weighted scoring across all indicators. Caps at 200. Returns NORMAL (0–29), WARNING (30–49), or CRITICAL (50+). |
| `tamper_evident_logger.py` | Append-only log with SHA256 hash chaining. Each entry: `SHA256(prev_hash + entry_json)`. Chain breakage detected by `verify_log_integrity()`. |
| `alert_client.py` | HTTPS-only sender with TLS 1.2 minimum, `hmac.compare_digest` API key, input sanitization, and exponential retry backoff. |
| `baseline_generator.py` | Run once on clean system. Stores fingerprint to `/etc/liveboot_sentinel/baseline.json` (Linux) or `%USERPROFILE%\liveboot_sentinel` (Windows). |
| `main.py` | Main loop. Runs all modules every 10 seconds. Aggregates indicators, computes score, triggers alert if score > 50. |

---

## 4. Risk Scoring Engine

Every detection cycle produces a set of indicator strings. The risk engine applies a weighted score to each indicator, sums them, and caps the total at 200.

### Risk Levels

| Score Range | Level | Action |
|-------------|-------|--------|
| 0 – 29 | ✅ NORMAL | Log only |
| 30 – 49 | ⚠️ WARNING | Log only |
| 50+ | 🔴 CRITICAL | Send alert to server |

### Indicator Weights

| Indicator | Score |
|-----------|-------|
| `USB_BOOT_DETECTED` | +40 |
| `SQUASHFS_MOUNT_DETECTED` | +30 |
| `TMPFS_ROOT_DETECTED` | +35 |
| `LIVE_OS_KERNEL:*` (any live OS match) | +28 |
| `FINGERPRINT_MISMATCH:DISK_UUID` | +30 |
| `FINGERPRINT_MISMATCH:BOOT_DEVICE` | +30 |
| `USB_UEFI_BOOT_ENTRY` | +35 |
| `USB_FIRST_IN_BOOT_ORDER` | +35 |
| `SECURE_BOOT_DISABLED` | +20 |
| `LOG_TAMPERING_DETECTED` | +50 |
| `LIVE_CMDLINE:BOOT=LIVE` | +25 |
| `LIVE_CMDLINE:CASPER` | +20 |
| `OVERLAY_FS_DETECTED` | +20 |
| `INTERNAL_DISK_SUSPICIOUS_MOUNT` | +15 |
| `BOOT_SOURCE_UNKNOWN` | +20 |
| `KERNEL_READ_FAILED` | +10 |

### Example Score Calculation

A machine booting Kali Linux from USB with Secure Boot disabled:

```
USB_BOOT_DETECTED             +40
LIVE_OS_KERNEL:KALI_LINUX     +28
SQUASHFS_MOUNT_DETECTED       +30
SECURE_BOOT_DISABLED          +20
OS_THREAT_LEVEL:Kali Linux    +25
─────────────────────────────────
Total                         143  →  CRITICAL  →  Alert sent
```

---

## 5. Alert Server API

The FastAPI server exposes REST endpoints and a WebSocket endpoint. All REST endpoints require API key authentication via the `X-API-Key` header. Rate limiting is applied per IP (60 requests/minute by default).

### Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Server health check |
| `/alert` | POST | Required | Ingest alert from endpoint agent |
| `/alerts` | GET | Required | List all alerts, newest first (paginated) |
| `/alerts/critical` | GET | Required | List alerts with `risk_score > 50` |
| `/alerts/{id}` | GET | Required | Fetch single alert by ID |
| `/hosts` | GET | Required | List all monitored hosts |
| `/stats` | GET | Required | Aggregate dashboard statistics |
| `/ws/alerts` | WebSocket | None | Real-time alert event stream |

### Alert Payload Schema (POST /alert)

```json
{
  "hostname":    "DESKTOP-F5NUAQ7",
  "timestamp":   "2026-03-16T10:30:00+00:00",
  "boot_source": "usb",
  "kernel":      "6.1.0-kali9-amd64",
  "detected_os": "Kali Linux",
  "risk_score":  95,
  "risk_level":  "CRITICAL",
  "indicators":  [
    "USB_BOOT_DETECTED",
    "LIVE_OS_KERNEL:KALI_LINUX",
    "SQUASHFS_MOUNT_DETECTED"
  ]
}
```

### WebSocket Event Types (wss://host:8443/ws/alerts)

```json
// New alert ingested
{ "type": "alert",     "data": { "id": 1, "hostname": "...", "risk_score": 95, ... } }

// Stats updated after every alert
{ "type": "stats",     "data": { "total_alerts": 5, "critical_alerts": 2, ... } }

// On WebSocket connect
{ "type": "connected", "data": { "message": "...", "connections": 1 } }

// Keepalive — send "ping", receive:
{ "type": "pong" }
```

### Dashboard Connection Values

```
REST API Base URL : https://10.119.80.246:8443
WebSocket URL     : wss://10.119.80.246:8443/ws/alerts
API Key Header    : X-API-Key: sentinel-dev-key-2026
```

---

## 6. OS Signature Database

The agent maintains a local signature database of 15 known live/security operating systems. Each entry carries a threat level from 1 (benign) to 5 (high-risk offensive tool).

| OS | Category | Threat Level |
|----|----------|-------------|
| Kali Linux | Penetration Testing | 🔴 5 / 5 |
| BlackArch | Penetration Testing | 🔴 5 / 5 |
| BackTrack | Penetration Testing | 🔴 5 / 5 |
| Parrot OS | Penetration Testing | 🟠 4 / 5 |
| Pentoo | Penetration Testing | 🟠 4 / 5 |
| Tails OS | Anonymity / Privacy | 🟠 4 / 5 |
| Whonix | Anonymity / Privacy | 🟡 3 / 5 |
| DEFT Linux | Digital Forensics | 🟡 3 / 5 |
| REMnux | Malware Analysis | 🟡 3 / 5 |
| CAINE | Digital Forensics | 🟡 3 / 5 |
| Ubuntu Live | Live Environment | 🟢 2 / 5 |
| Debian Live | Live Environment | 🟢 2 / 5 |
| Fedora Live | Live Environment | 🟢 2 / 5 |
| Manjaro Live | Live Environment | 🟢 2 / 5 |
| Casper Boot | Live Environment | 🟢 2 / 5 |

---

## 7. Security Design

### Secure Coding Practices

| Practice | Implementation |
|----------|---------------|
| No command injection | All subprocess calls use argument lists — `shell=False` everywhere |
| Input validation | Pydantic v2 schemas with field validators and cross-field consistency checks |
| SQL injection prevention | SQLAlchemy ORM only — zero raw SQL queries |
| Timing-safe auth | `hmac.compare_digest` for API key comparison |
| Rate limiting | Per-IP sliding window, 60 req/min, returns `429` with `Retry-After` |
| HTTPS enforcement | Agent refuses to transmit if URL doesn't start with `https://` |
| TLS version | Minimum TLS 1.2 enforced on all connections |
| Error sanitization | Generic messages to clients — internal details in server logs only |
| Secret management | Secrets only via environment variables — never hardcoded |
| Least privilege | Server runs as non-root user in Docker |

### Tamper-Evident Logging

Every log entry is SHA256 hash-chained to the previous entry. Modifying any historical entry breaks the chain and is immediately detected by `verify_log_integrity()`.

```
current_hash = SHA256(previous_hash + entry_json)
```

**Log entry format:**
```json
{
  "timestamp":     "2026-03-16T10:30:00+00:00",
  "event":         "Detection cycle 5: level=CRITICAL score=95 boot=usb",
  "risk_score":    95,
  "previous_hash": "a3f1bc2e047d6a1f58c3e2b904d71a8f...",
  "current_hash":  "9b2c4d7e1f3a5b8c0d2e4f6a8b0c1d3e..."
}
```

**Log locations:**
- Linux: `/var/log/liveboot_sentinel.log`
- Windows: `%USERPROFILE%\liveboot_sentinel\liveboot_sentinel.log`

**Verify integrity at any time:**
```python
from tamper_evident_logger import verify_log_integrity
result = verify_log_integrity()
# {"valid": True, "total_entries": 284, "tampered_entries": []}
```

---

## 8. Deployment Reference

### Environment Variables — Server (Device 1)

| Variable | Required | Description |
|----------|----------|-------------|
| `LIVEBOOT_API_KEYS` | Yes | Comma-separated valid API keys |
| `LIVEBOOT_DB_URL` | No | SQLAlchemy async DB URL (default: SQLite) |
| `LIVEBOOT_DB_DIR` | No | Directory for SQLite database file |
| `LIVEBOOT_CORS_ORIGINS` | No | Comma-separated allowed dashboard origins |
| `LIVEBOOT_RATE_LIMIT_MAX` | No | Max requests per window (default: 60) |
| `LIVEBOOT_RATE_LIMIT_WINDOW` | No | Window in seconds (default: 60) |
| `LIVEBOOT_ENABLE_DOCS` | No | Set `true` to enable `/docs` Swagger UI |

### Environment Variables — Agent (Device 3)

| Variable | Required | Description |
|----------|----------|-------------|
| `LIVEBOOT_ALERT_URL` | Yes | HTTPS URL of server `/alert` endpoint |
| `LIVEBOOT_API_KEY` | Yes | API key matching one in server's `LIVEBOOT_API_KEYS` |
| `LIVEBOOT_VERIFY_SSL` | No | Set `false` for self-signed certs (dev only) |
| `LIVEBOOT_CA_BUNDLE` | No | Path to custom CA certificate bundle |

### Quick Start — Device 1 (Server, Windows)

```powershell
cd $HOME\OneDrive\Desktop\liveboot_sentinel\server

$env:LIVEBOOT_API_KEYS    = "sentinel-dev-key-2026"
$env:LIVEBOOT_CORS_ORIGINS = "*"
$env:LIVEBOOT_ENABLE_DOCS  = "true"
$env:LIVEBOOT_DB_DIR       = "$HOME\liveboot_data"

uvicorn api:app --host 0.0.0.0 --port 8443 `
  --ssl-keyfile ..\certs\server.key `
  --ssl-certfile ..\certs\server.crt
```

### Quick Start — Device 3 (Agent, Windows)

```powershell
cd C:\Users\AMMA\Desktop\agent

$env:LIVEBOOT_ALERT_URL  = "https://10.119.80.246:8443/alert"
$env:LIVEBOOT_API_KEY    = "sentinel-dev-key-2026"
$env:LIVEBOOT_VERIFY_SSL = "false"

python baseline_generator.py   # run once on clean boot
python main.py
```

### Verify End-to-End (Device 1)

```python
# Test full pipeline — run this on Device 1
python -c "
import urllib.request, ssl, json
from datetime import datetime, timezone
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
payload = json.dumps({
    'hostname':    'DESKTOP-F5NUAQ7',
    'timestamp':   datetime.now(timezone.utc).isoformat(),
    'boot_source': 'usb',
    'kernel':      '6.1.0-kali9-amd64',
    'detected_os': 'Kali Linux',
    'risk_score':  95,
    'risk_level':  'CRITICAL',
    'indicators':  ['USB_BOOT_DETECTED','LIVE_OS_KERNEL:KALI_LINUX']
}).encode()
req = urllib.request.Request(
    'https://localhost:8443/alert', data=payload,
    headers={'X-API-Key':'sentinel-dev-key-2026','Content-Type':'application/json'},
    method='POST'
)
print(urllib.request.urlopen(req, context=ctx).read().decode())
"
# Expected: {"status":"accepted","alert_id":1,"risk_level":"CRITICAL"}
```

### Docker Deployment

```bash
# Generate certs first
bash gen_certs.sh

# Start server container
export LIVEBOOT_API_KEYS="sentinel-dev-key-2026"
export LIVEBOOT_CORS_ORIGINS="http://your-dashboard-url:3000"
docker-compose up -d

# Check health
curl -k https://localhost:8443/health
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `SSL: CERTIFICATE_VERIFY_FAILED` | Set `LIVEBOOT_VERIFY_SSL=false` (dev) or provide `LIVEBOOT_CA_BUNDLE` path |
| `403 Invalid API key` | Ensure agent's `LIVEBOOT_API_KEY` matches a key in server's `LIVEBOOT_API_KEYS` |
| Dashboard CORS error | Add dashboard origin to `LIVEBOOT_CORS_ORIGINS` — exact URL, no trailing slash |
| WebSocket won't connect | Use `wss://` not `ws://` — port 8443 is TLS only |
| Agent score always WARNING | Normal on Windows — `BOOT_SOURCE_UNKNOWN` (+20) and `SECURE_BOOT_DISABLED` (+20) are expected |
| Baseline not found warning | Run `python baseline_generator.py` before starting `main.py` |
| `os.geteuid` error on Windows | Use the updated `baseline_generator.py` with Windows-compatible root check |

---

## 9. Project Structure

```
liveboot_sentinel/
├── agent/
│   ├── boot_detector.py           # USB/removable boot detection
│   ├── kernel_fingerprint.py      # Live OS kernel indicators
│   ├── disk_monitor.py            # Abnormal mount detection
│   ├── boot_fingerprint.py        # Baseline comparison
│   ├── uefi_monitor.py            # UEFI boot entry analysis
│   ├── signature_db.py            # OS fingerprint database (15 entries)
│   ├── risk_engine.py             # Weighted risk score aggregation
│   ├── alert_client.py            # Secure HTTPS alert sender
│   ├── tamper_evident_logger.py   # SHA256 hash-chained append-only log
│   ├── baseline_generator.py      # One-time baseline creator
│   ├── main.py                    # Main detection loop (10s interval)
│   └── requirements.txt           # Zero dependencies (stdlib only)
│
├── server/
│   ├── api.py                     # FastAPI endpoints + WebSocket
│   ├── database.py                # Async SQLAlchemy engine
│   ├── models.py                  # ORM models + Pydantic v2 schemas
│   ├── alert_handler.py           # Alert processing business logic
│   ├── websocket.py               # WebSocket connection manager
│   ├── requirements.txt           # FastAPI, SQLAlchemy, aiosqlite
│   └── Dockerfile                 # Non-root production container
│
├── certs/
│   ├── server.key                 # TLS private key
│   └── server.crt                 # TLS certificate
│
├── docker-compose.yml             # Container orchestration
├── liveboot-sentinel.service      # systemd unit file
├── agent.env.template             # Agent configuration template
├── gen_certs.sh                   # Self-signed certificate generator
├── install_agent.sh               # Linux agent installation script
└── README.md                      # This document
```

---

*LiveBoot Sentinel — Built for production security environments.*
