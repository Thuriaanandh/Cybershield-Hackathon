# LiveBoot Sentinel

**External OS Intrusion Detection System**

A production-quality security monitoring system that detects when machines boot from external live operating systems (Kali Linux, Tails, Parrot OS, etc.) and sends forensic alerts to a central SOC dashboard in real time.

```
Endpoint Agent  ──HTTPS──▶  Alert API Server  ──WebSocket──▶  SOC Dashboard
```

---

## Architecture

```
liveboot_sentinel/
├── agent/                          # Endpoint monitoring agent (Python, no deps)
│   ├── boot_detector.py            # USB/removable boot detection
│   ├── kernel_fingerprint.py       # Live OS kernel indicators
│   ├── disk_monitor.py             # Abnormal mount detection
│   ├── boot_fingerprint.py         # Baseline comparison
│   ├── uefi_monitor.py             # UEFI boot entry analysis
│   ├── signature_db.py             # OS fingerprint database
│   ├── risk_engine.py              # Risk score aggregation
│   ├── alert_client.py             # Secure HTTPS alert sender
│   ├── tamper_evident_logger.py    # SHA256 hash-chained append-only log
│   ├── baseline_generator.py       # One-time baseline creator
│   └── main.py                     # Main detection loop (10s interval)
│
├── server/                         # FastAPI alert server
│   ├── api.py                      # REST + WebSocket endpoints
│   ├── database.py                 # SQLAlchemy async engine
│   ├── models.py                   # ORM models + Pydantic schemas
│   ├── alert_handler.py            # Alert processing business logic
│   ├── websocket.py                # Real-time WebSocket manager
│   ├── requirements.txt            # Server Python dependencies
│   └── Dockerfile                  # Container image definition
│
├── docker-compose.yml              # Container orchestration
├── liveboot-sentinel.service       # systemd unit file
├── agent.env.template              # Agent configuration template
├── gen_certs.sh                    # TLS certificate generator
└── install_agent.sh                # Agent installation script
```

---

## Quick Start

### 1. Server Setup

```bash
# Generate TLS certificates (dev only — use real CA certs in production)
bash gen_certs.sh

# Set required environment variables
export LIVEBOOT_API_KEYS="your-strong-random-api-key"
export LIVEBOOT_CORS_ORIGINS="http://localhost:3000"

# Start server
cd server
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile ../certs/server.key \
    --ssl-certfile ../certs/server.crt

# Or with Docker
docker-compose up -d
```

### 2. Agent Setup

```bash
# Install agent (requires root)
sudo bash install_agent.sh

# Configure agent
sudo nano /etc/liveboot_sentinel/agent.env
# Set LIVEBOOT_ALERT_URL and LIVEBOOT_API_KEY

# Generate baseline fingerprint (run on known-good system)
sudo python3 /opt/liveboot_sentinel/agent/baseline_generator.py

# Start agent
sudo systemctl start liveboot-sentinel
sudo systemctl status liveboot-sentinel
```

### 3. Dashboard

Connect the Antigravity-generated SOC dashboard to:

| Endpoint              | Purpose                              |
|-----------------------|--------------------------------------|
| `GET /health`         | Server health (no auth)              |
| `POST /alert`         | Ingest alerts from agents            |
| `GET /alerts`         | All alerts (paginated)               |
| `GET /alerts/critical`| Critical alerts only (score > 50)    |
| `GET /alerts/{id}`    | Single alert detail                  |
| `GET /hosts`          | Monitored hosts                      |
| `GET /stats`          | Dashboard statistics                 |
| `WS /ws/alerts`       | Real-time WebSocket stream           |

All endpoints (except `/health`) require header: `X-API-Key: <your-key>`

---

## API Reference

### POST /alert

Request body:
```json
{
  "hostname": "workstation-01",
  "timestamp": "2025-03-16T10:30:00+00:00",
  "boot_source": "usb",
  "kernel": "6.1.0-kali9-amd64",
  "detected_os": "Kali Linux",
  "risk_score": 95,
  "risk_level": "CRITICAL",
  "indicators": [
    "USB_BOOT_DETECTED",
    "LIVE_OS_KERNEL:KALI_LINUX",
    "SQUASHFS_MOUNT_DETECTED",
    "SECURE_BOOT_DISABLED"
  ]
}
```

Response:
```json
{
  "status": "accepted",
  "alert_id": 42,
  "risk_level": "CRITICAL"
}
```

### WebSocket /ws/alerts

Connect and receive real-time JSON events:

```json
// Alert event
{ "type": "alert", "data": { ...alert fields... } }

// Stats update
{ "type": "stats", "data": { "total_alerts": 42, "critical_alerts": 5, ... } }

// Connection confirmation
{ "type": "connected", "data": { "message": "...", "connections": 1 } }
```

Send `"ping"` to receive `{"type": "pong"}` for keepalive.

---

## Risk Scoring

| Indicator                        | Score |
|----------------------------------|-------|
| USB_BOOT_DETECTED                | +40   |
| LIVE_OS_KERNEL (any)             | +28   |
| SQUASHFS_MOUNT_DETECTED          | +30   |
| TMPFS_ROOT_DETECTED              | +35   |
| FINGERPRINT_MISMATCH:DISK_UUID   | +30   |
| FINGERPRINT_MISMATCH:BOOT_DEVICE | +30   |
| USB_UEFI_BOOT_ENTRY              | +35   |
| USB_FIRST_IN_BOOT_ORDER          | +35   |
| SECURE_BOOT_DISABLED             | +20   |
| LOG_TAMPERING_DETECTED           | +50   |

| Score Range | Level    |
|-------------|----------|
| 0 – 29      | NORMAL   |
| 30 – 49     | WARNING  |
| 50+         | CRITICAL |

---

## Security Design

- **No shell=True**: All subprocess calls use argument lists
- **Input validation**: Pydantic schemas with field validators on every input
- **SQL injection prevention**: SQLAlchemy ORM with parameterized queries only
- **API key auth**: Constant-time comparison (hmac.compare_digest) to prevent timing attacks
- **Rate limiting**: Per-IP sliding window (60 req/min default)
- **HTTPS only**: Agent refuses to send alerts over plain HTTP
- **Secret isolation**: Secrets in environment variables and files, never in code
- **Error sanitization**: Generic error messages to clients; details in server logs only
- **Tamper-evident logs**: SHA256 hash-chained append-only log detects any modification
- **Least privilege**: Server runs as non-root; agent uses minimal capabilities

---

## OS Signature Database

| OS            | Category            | Threat Level |
|---------------|---------------------|--------------|
| Kali Linux    | penetration_testing | 5 / 5        |
| BlackArch     | penetration_testing | 5 / 5        |
| BackTrack     | penetration_testing | 5 / 5        |
| Parrot OS     | penetration_testing | 4 / 5        |
| Pentoo        | penetration_testing | 4 / 5        |
| Tails OS      | anonymity           | 4 / 5        |
| Whonix        | anonymity           | 3 / 5        |
| DEFT Linux    | forensics           | 3 / 5        |
| REMnux        | forensics           | 3 / 5        |
| CAINE         | forensics           | 3 / 5        |
| Ubuntu Live   | live_environment    | 2 / 5        |
| Debian Live   | live_environment    | 2 / 5        |

---

## Environment Variables

### Agent (`/etc/liveboot_sentinel/agent.env`)

| Variable              | Required | Description                              |
|-----------------------|----------|------------------------------------------|
| LIVEBOOT_ALERT_URL    | Yes      | HTTPS URL of alert server endpoint       |
| LIVEBOOT_API_KEY      | Yes      | API key for this agent                   |
| LIVEBOOT_CA_BUNDLE    | No       | Path to custom CA cert bundle            |
| LIVEBOOT_VERIFY_SSL   | No       | Set "false" for dev only (default: true) |

### Server

| Variable               | Default                  | Description                           |
|------------------------|--------------------------|---------------------------------------|
| LIVEBOOT_API_KEYS      | (required)               | Comma-separated valid API keys        |
| LIVEBOOT_DB_URL        | sqlite (local)           | SQLAlchemy async DB URL               |
| LIVEBOOT_CORS_ORIGINS  | localhost variants       | Allowed dashboard origins             |
| LIVEBOOT_RATE_LIMIT_MAX| 60                       | Max requests per window               |
| LIVEBOOT_RATE_LIMIT_WINDOW| 60                    | Rate limit window in seconds          |
| LIVEBOOT_ENABLE_DOCS   | false                    | Enable Swagger UI at /docs            |

---

## Tamper-Evident Logging

Each log entry at `/var/log/liveboot_sentinel.log` is a JSON line:

```json
{
  "timestamp": "2025-03-16T10:30:00+00:00",
  "event": "Detection cycle 42: level=CRITICAL score=95 boot=usb",
  "risk_score": 95,
  "previous_hash": "a3f1...",
  "current_hash": "9b2c..."
}
```

`current_hash = SHA256(previous_hash + entry_json)`

Verify integrity at any time:
```python
from tamper_evident_logger import verify_log_integrity
result = verify_log_integrity()
print(result)
# {"valid": True, "total_entries": 284, "tampered_entries": []}
```

Any modification to any past entry breaks the chain and is detected immediately.
