"""
api.py - FastAPI application for LiveBoot Sentinel server.
Implements secure endpoints with API key auth, rate limiting, input validation,
CORS configuration, and WebSocket support for real-time dashboard updates.
"""

import json
import logging
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from database import init_db, close_db, get_db
from models import AlertModel, AlertIngest, AlertOut, HostModel, HostOut, HealthResponse
from alert_handler import create_alert, upsert_host, alert_to_dict, get_stats
from websocket import manager
from network_capture import get_monitor

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

SERVER_VERSION = "1.0.0"

# API keys from environment (comma-separated for multiple agents)
_raw_keys = os.environ.get("LIVEBOOT_API_KEYS", "dev-key-change-in-production")
VALID_API_KEYS: set[str] = {k.strip() for k in _raw_keys.split(",") if k.strip()}

# CORS origins for dashboard (set in production to specific dashboard URL)
ALLOWED_ORIGINS = os.environ.get(
    "LIVEBOOT_CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://localhost:8080"
).split(",")

# Rate limiting: max requests per time window
RATE_LIMIT_MAX = int(os.environ.get("LIVEBOOT_RATE_LIMIT_MAX", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("LIVEBOOT_RATE_LIMIT_WINDOW", "60"))  # seconds

# Pagination limits
MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 50


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class InMemoryRateLimiter:
    """
    Simple sliding-window rate limiter using IP address as key.
    Thread-safe for single-process async use.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        window_start = now - self.window

        # Sanitize client IP (prevent key injection)
        safe_ip = client_ip[:45] if client_ip else "unknown"

        # Prune old entries
        self._requests[safe_ip] = [
            t for t in self._requests[safe_ip] if t > window_start
        ]

        if len(self._requests[safe_ip]) >= self.max_requests:
            return False

        self._requests[safe_ip].append(now)
        return True


rate_limiter = InMemoryRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources on app start/stop."""
    logger.info("LiveBoot Sentinel API server starting (v%s)", SERVER_VERSION)
    await init_db()

    # Wire network monitor callback — pushes attacks to WebSocket immediately
    monitor = get_monitor()

    def on_attack(attack: dict):
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({
                        "type": "network_attack",
                        "data": {
                            "attack_type":  attack.get("type"),
                            "indicator":    attack.get("indicator"),
                            "technique":    attack.get("technique"),
                            "description":  attack.get("description"),
                            "risk":         attack.get("risk", 0),
                            "src_ip":       attack.get("src_ip"),
                            "timestamp":    attack.get("timestamp"),
                            "evidence":     attack.get("evidence", {}),
                        },
                    }),
                    loop,
                )
        except Exception as e:
            logger.error("Network attack broadcast error: %s", str(e)[:100])

    monitor.on_attack_detected = on_attack
    logger.info("Network monitor callback wired to WebSocket")

    yield
    monitor.stop_monitoring()
    await close_db()
    logger.info("LiveBoot Sentinel API server stopped")


# ─── App Initialization ───────────────────────────────────────────────────────

app = FastAPI(
    title="LiveBoot Sentinel API",
    version=SERVER_VERSION,
    description="Endpoint OS intrusion detection alert server",
    docs_url=None,  # Disable Swagger in production (enable via env var)
    redoc_url=None,
    lifespan=lifespan,
)

# Enable Swagger only in development
if os.environ.get("LIVEBOOT_ENABLE_DOCS", "false").lower() == "true":
    app.docs_url = "/docs"
    app.redoc_url = "/redoc"

# ─── CORS ─────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# ─── Security Dependencies ────────────────────────────────────────────────────

def verify_api_key(x_api_key: Annotated[str | None, Header()] = None) -> str:
    """
    Validate X-API-Key header against known valid keys.
    SECURITY: Constant-time comparison to prevent timing attacks.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # SECURITY: Use hmac.compare_digest for timing-safe comparison
    import hmac
    for valid_key in VALID_API_KEYS:
        if hmac.compare_digest(x_api_key.encode(), valid_key.encode()):
            return x_api_key

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key",
    )


def apply_rate_limit(request: Request) -> None:
    """
    Rate limit dependency. Raises 429 if limit exceeded.
    Uses X-Forwarded-For header (for reverse proxy setups) with fallback.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    client_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.client.host if request.client else "unknown")
    )

    if not rate_limiter.is_allowed(client_ip):
        logger.warning("Rate limit exceeded for IP: %s", client_ip[:45])
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )


# ─── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Generic exception handler.
    SECURITY: Never expose internal error details or stack traces to clients.
    """
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, str(exc)[:200])
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    """Public health check endpoint — no auth required."""
    return {
        "status": "ok",
        "version": SERVER_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Alert Endpoints ──────────────────────────────────────────────────────────

@app.post(
    "/alert",
    status_code=status.HTTP_201_CREATED,
    tags=["alerts"],
    dependencies=[Depends(apply_rate_limit)],
)
async def ingest_alert(
    alert_in: AlertIngest,
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
):
    """
    Receive and store a security alert from an endpoint agent.
    Requires valid API key. Rate limited.
    """
    # Persist alert
    alert = await create_alert(db, alert_in)
    await upsert_host(db, alert_in)

    alert_dict = alert_to_dict(alert)

    # Broadcast to WebSocket clients (non-blocking — don't fail on WS error)
    try:
        await manager.send_alert_event(alert_dict)
        # Also broadcast updated stats
        stats = await get_stats(db)
        await manager.send_stats_event(stats)
    except Exception as e:
        logger.warning("WebSocket broadcast failed: %s", str(e)[:200])

    logger.info(
        "Alert ingested: host=%s score=%d level=%s",
        alert_in.hostname, alert_in.risk_score, alert_in.risk_level
    )

    return {
        "status": "accepted",
        "alert_id": alert.id,
        "risk_level": alert.risk_level,
    }


@app.get(
    "/alerts",
    response_model=list[AlertOut],
    tags=["alerts"],
    dependencies=[Depends(apply_rate_limit)],
)
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
    hostname: Optional[str] = None,
):
    """
    Return alerts, newest first. Supports pagination and optional hostname filter.
    """
    # Clamp limit
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    offset = max(0, offset)

    stmt = select(AlertModel).order_by(desc(AlertModel.timestamp))

    if hostname:
        # Sanitize hostname before query (ORM handles parameterization)
        import re
        hostname_clean = re.sub(r"[^a-zA-Z0-9.\-]", "", hostname)[:253]
        stmt = stmt.where(AlertModel.hostname == hostname_clean)

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return [_alert_to_out(a) for a in alerts]


@app.get(
    "/alerts/critical",
    response_model=list[AlertOut],
    tags=["alerts"],
    dependencies=[Depends(apply_rate_limit)],
)
async def list_critical_alerts(
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
    limit: int = DEFAULT_PAGE_SIZE,
):
    """Return alerts with risk_score > 50 (CRITICAL), newest first."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    stmt = (
        select(AlertModel)
        .where(AlertModel.risk_score > 50)
        .order_by(desc(AlertModel.timestamp))
        .limit(limit)
    )
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return [_alert_to_out(a) for a in alerts]


@app.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    tags=["alerts"],
    dependencies=[Depends(apply_rate_limit)],
)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
):
    """Return a single alert by ID."""
    if alert_id < 1:
        raise HTTPException(status_code=400, detail="Invalid alert ID")

    stmt = select(AlertModel).where(AlertModel.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _alert_to_out(alert)


# ─── Host Endpoints ───────────────────────────────────────────────────────────

@app.get(
    "/hosts",
    response_model=list[HostOut],
    tags=["hosts"],
    dependencies=[Depends(apply_rate_limit)],
)
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
    limit: int = DEFAULT_PAGE_SIZE,
):
    """Return all monitored hosts with their latest status."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    stmt = select(HostModel).order_by(desc(HostModel.last_seen)).limit(limit)
    result = await db.execute(stmt)
    hosts = result.scalars().all()

    return [_host_to_out(h) for h in hosts]


# ─── Stats Endpoint ───────────────────────────────────────────────────────────

@app.get("/stats", tags=["system"], dependencies=[Depends(apply_rate_limit)])
async def system_stats(
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
):
    """Return aggregate dashboard statistics."""
    return await get_stats(db)


# ─── WebSocket Endpoint ───────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    Dashboard connects here to receive live alert events.
    No API key over WebSocket — rely on CORS + session token in production.
    """
    accepted = await manager.connect(websocket)
    if not accepted:
        return

    try:
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "data": {
                "message": "LiveBoot Sentinel WebSocket connected",
                "connections": manager.connection_count,
            }
        }))

        # Keep connection alive — handle ping/pong
        while True:
            try:
                data = await websocket.receive_text()
                # Accept ping messages
                if data.strip() == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        manager.disconnect(websocket)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe_json(val, default):
    """Safely parse a JSON text field, returning default on failure."""
    try:
        return json.loads(val) if val else default
    except (json.JSONDecodeError, TypeError):
        return default


def _alert_to_out(alert: AlertModel) -> AlertOut:
    """Convert AlertModel to AlertOut Pydantic schema."""
    return AlertOut(
        id=alert.id,
        hostname=alert.hostname,
        timestamp=alert.timestamp.isoformat() if alert.timestamp else "",
        boot_source=alert.boot_source,
        kernel=alert.kernel,
        detected_os=alert.detected_os,
        risk_score=alert.risk_score,
        risk_level=alert.risk_level,
        indicators=_safe_json(alert.indicators, []),
        attack_techniques=_safe_json(getattr(alert, "attack_techniques", None), {}),
        attack_summary=getattr(alert, "attack_summary", "") or "",
        ram_analysis=_safe_json(getattr(alert, "ram_analysis", None), {}),
        ram_dump_file=getattr(alert, "ram_dump_file", "") or "",
        created_at=alert.created_at.isoformat() if alert.created_at else None,
    )


def _host_to_out(host: HostModel) -> HostOut:
    """Convert HostModel to HostOut Pydantic schema."""
    return HostOut(
        id=host.id,
        hostname=host.hostname,
        last_seen=host.last_seen.isoformat() if host.last_seen else "",
        last_boot_source=host.last_boot_source,
        last_detected_os=host.last_detected_os,
        last_risk_score=host.last_risk_score or 0,
        last_risk_level=host.last_risk_level or "NORMAL",
        alert_count=host.alert_count or 0,
        last_attack_techniques=_safe_json(
            getattr(host, "last_attack_techniques", None), {}
        ),
        last_ram_analysis=_safe_json(
            getattr(host, "last_ram_analysis", None), {}
        ),
    )


@app.get(
    "/ram-analysis/{alert_id}",
    tags=["forensics"],
    dependencies=[Depends(apply_rate_limit)],
)
async def get_ram_analysis(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
):
    """
    Return the full RAM dump analysis for a specific alert.
    Includes processes, network connections, commands, suspicious tools.
    """
    if alert_id < 1:
        raise HTTPException(status_code=400, detail="Invalid alert ID")

    stmt = select(AlertModel).where(AlertModel.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    ram = _safe_json(getattr(alert, "ram_analysis", None), {})

    return {
        "alert_id":          alert.id,
        "hostname":          alert.hostname,
        "timestamp":         alert.timestamp.isoformat() if alert.timestamp else "",
        "ram_dump_file":     getattr(alert, "ram_dump_file", "") or "",
        "ram_analysis":      ram,
        "analysis_complete": ram.get("analysis_complete", False),
        "suspicious_tools":  ram.get("suspicious_tools", []),
        "processes":         ram.get("processes", []),
        "network_connections": ram.get("network_connections", []),
        "commands_detected": ram.get("commands_detected", []),
        "credentials_found": ram.get("credentials_found", []),
        "loaded_modules":    ram.get("loaded_modules", []),
        "indicators":        ram.get("indicators", []),
        "risk_score_increment": ram.get("risk_score_increment", 0),
    }


@app.get(
    "/ram-analysis",
    tags=["forensics"],
    dependencies=[Depends(apply_rate_limit)],
)
async def list_ram_analyses(
    db: AsyncSession = Depends(get_db),
    _api_key: str = Depends(verify_api_key),
    limit: int = DEFAULT_PAGE_SIZE,
):
    """
    Return all alerts that have RAM dump analysis data.
    """
    limit = max(1, min(limit, MAX_PAGE_SIZE))

    stmt = (
        select(AlertModel)
        .where(AlertModel.ram_analysis.isnot(None))
        .where(AlertModel.ram_analysis != "{}")
        .where(AlertModel.ram_analysis != "")
        .order_by(desc(AlertModel.timestamp))
        .limit(limit)
    )
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return [
        {
            "alert_id":       a.id,
            "hostname":       a.hostname,
            "timestamp":      a.timestamp.isoformat() if a.timestamp else "",
            "risk_score":     a.risk_score,
            "ram_dump_file":  getattr(a, "ram_dump_file", "") or "",
            "tools_found":    len(_safe_json(
                getattr(a, "ram_analysis", None), {}
            ).get("suspicious_tools", [])),
            "analysis_complete": _safe_json(
                getattr(a, "ram_analysis", None), {}
            ).get("analysis_complete", False),
        }
        for a in alerts
    ]


# ─── Network Monitoring Endpoints ─────────────────────────────────────────────

@app.post(
    "/network-monitor/start",
    tags=["network"],
    dependencies=[Depends(apply_rate_limit)],
)
async def start_network_monitoring(
    request: Request,
    _api_key: str = Depends(verify_api_key),
    target_ip: Optional[str] = None,
):
    """
    Start passive network traffic monitoring.
    Optionally filter to a specific host IP.
    Detects: port scans, C2 connections, brute force, exfiltration.
    """
    import re
    if target_ip:
        # Validate IP format
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")

    monitor = get_monitor()
    monitor.clear()
    monitor.start_monitoring(target_ip=target_ip)

    logger.info("Network monitoring started via API (target: %s)", target_ip or "all")
    return {
        "status": "monitoring_started",
        "target_ip": target_ip or "all",
        "scapy_available": monitor.scapy_available,
        "message": (
            "Deep packet inspection active" if monitor.scapy_available
            else "Connection-level monitoring active (install scapy for full DPI)"
        ),
    }


@app.post(
    "/network-monitor/stop",
    tags=["network"],
    dependencies=[Depends(apply_rate_limit)],
)
async def stop_network_monitoring(
    _api_key: str = Depends(verify_api_key),
):
    """Stop network traffic monitoring."""
    monitor = get_monitor()
    monitor.stop_monitoring()
    report = monitor.get_attack_report()
    return {
        "status":         "monitoring_stopped",
        "attacks_found":  report["attack_count"],
        "indicators":     report["indicators"],
        "risk_score":     report["risk_score"],
    }


@app.get(
    "/network-monitor/report",
    tags=["network"],
    dependencies=[Depends(apply_rate_limit)],
)
async def get_network_report(
    _api_key: str = Depends(verify_api_key),
    target_ip: Optional[str] = None,
):
    """
    Get the current network attack detection report.
    Shows all detected attacks, indicators, and MITRE ATT&CK mappings.
    """
    import re
    if target_ip:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")

    monitor = get_monitor()
    report  = monitor.get_attack_report(target_ip=target_ip)

    # Broadcast to WebSocket clients if attacks found
    if report["attack_count"] > 0:
        try:
            await manager.broadcast({
                "type": "network_attack",
                "data": {
                    "attack_count":     report["attack_count"],
                    "indicators":       report["indicators"],
                    "risk_score":       report["risk_score"],
                    "mitre_techniques": report["mitre_techniques"],
                    "timestamp":        report["timestamp"],
                },
            })
        except Exception:
            pass

    return report


@app.get(
    "/network-monitor/status",
    tags=["network"],
    dependencies=[Depends(apply_rate_limit)],
)
async def network_monitor_status(
    _api_key: str = Depends(verify_api_key),
):
    """Get current network monitoring status."""
    monitor = get_monitor()
    return {
        "monitoring_active": monitor.monitoring,
        "scapy_available":   monitor.scapy_available,
        "attacks_detected":  len(monitor.detected_attacks),
        "hosts_tracked":     len(monitor.host_states),
    }
