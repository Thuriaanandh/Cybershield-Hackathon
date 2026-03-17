"""
alert_handler.py - Business logic for processing and storing alerts.
Updated to handle RAM analysis fields.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from models import AlertModel, AlertIngest, HostModel

logger = logging.getLogger(__name__)


def _parse_timestamp(ts_str: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


async def create_alert(db: AsyncSession, alert_in: AlertIngest) -> AlertModel:
    parsed_ts = _parse_timestamp(alert_in.timestamp)

    alert = AlertModel(
        hostname           = alert_in.hostname,
        timestamp          = parsed_ts,
        boot_source        = alert_in.boot_source,
        kernel             = alert_in.kernel,
        detected_os        = alert_in.detected_os,
        risk_score         = alert_in.risk_score,
        risk_level         = alert_in.risk_level,
        indicators         = json.dumps(alert_in.indicators),
        attack_techniques  = json.dumps(alert_in.attack_techniques or {}),
        attack_summary     = alert_in.attack_summary or "",
        ram_analysis       = json.dumps(alert_in.ram_analysis or {}),
        ram_dump_file      = alert_in.ram_dump_file or "",
    )

    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    ram = alert_in.ram_analysis or {}
    logger.info(
        "Alert stored: id=%d host=%s score=%d level=%s "
        "ram_tools=%d ram_complete=%s",
        alert.id, alert.hostname, alert.risk_score, alert.risk_level,
        len(ram.get("suspicious_tools", [])),
        ram.get("analysis_complete", False),
    )
    return alert


async def upsert_host(db: AsyncSession, alert_in: AlertIngest) -> None:
    parsed_ts = _parse_timestamp(alert_in.timestamp)

    stmt = select(HostModel).where(HostModel.hostname == alert_in.hostname)
    result = await db.execute(stmt)
    host = result.scalar_one_or_none()

    if host:
        host.last_seen              = parsed_ts
        host.last_boot_source       = alert_in.boot_source
        host.last_detected_os       = alert_in.detected_os
        host.last_risk_score        = alert_in.risk_score
        host.last_risk_level        = alert_in.risk_level
        host.alert_count            = (host.alert_count or 0) + 1
        host.last_attack_techniques = json.dumps(alert_in.attack_techniques or {})
        host.last_ram_analysis      = json.dumps(alert_in.ram_analysis or {})
    else:
        host = HostModel(
            hostname                = alert_in.hostname,
            last_seen               = parsed_ts,
            last_boot_source        = alert_in.boot_source,
            last_detected_os        = alert_in.detected_os,
            last_risk_score         = alert_in.risk_score,
            last_risk_level         = alert_in.risk_level,
            alert_count             = 1,
            last_attack_techniques  = json.dumps(alert_in.attack_techniques or {}),
            last_ram_analysis       = json.dumps(alert_in.ram_analysis or {}),
        )
        db.add(host)


def alert_to_dict(alert: AlertModel) -> dict:
    def safe_json(val, default):
        try:
            return json.loads(val) if val else default
        except (json.JSONDecodeError, TypeError):
            return default

    return {
        "id":                alert.id,
        "hostname":          alert.hostname,
        "timestamp":         alert.timestamp.isoformat() if alert.timestamp else None,
        "boot_source":       alert.boot_source,
        "kernel":            alert.kernel,
        "detected_os":       alert.detected_os,
        "risk_score":        alert.risk_score,
        "risk_level":        alert.risk_level,
        "indicators":        safe_json(alert.indicators, []),
        "attack_techniques": safe_json(
            getattr(alert, "attack_techniques", None), {}
        ),
        "attack_summary":    getattr(alert, "attack_summary", "") or "",
        "ram_analysis":      safe_json(getattr(alert, "ram_analysis", None), {}),
        "ram_dump_file":     getattr(alert, "ram_dump_file", "") or "",
        "created_at":        alert.created_at.isoformat() if alert.created_at else None,
    }


async def get_stats(db: AsyncSession) -> dict:
    total    = (await db.execute(select(func.count(AlertModel.id)))).scalar() or 0
    critical = (await db.execute(
        select(func.count(AlertModel.id)).where(AlertModel.risk_level == "CRITICAL")
    )).scalar() or 0
    warning  = (await db.execute(
        select(func.count(AlertModel.id)).where(AlertModel.risk_level == "WARNING")
    )).scalar() or 0
    hosts    = (await db.execute(select(func.count(HostModel.id)))).scalar() or 0

    return {
        "total_alerts":    total,
        "critical_alerts": critical,
        "warning_alerts":  warning,
        "normal_events":   max(0, total - critical - warning),
        "monitored_hosts": hosts,
    }
