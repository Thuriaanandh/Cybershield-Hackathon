"""
alert_handler.py - Business logic for processing and storing incoming alerts.
Handles database writes and triggers WebSocket broadcasts.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from models import AlertModel, AlertOut, AlertIngest, HostModel

logger = logging.getLogger(__name__)


def _parse_timestamp(ts_str: str) -> datetime:
    """
    Safely parse ISO 8601 timestamp string to datetime.
    Returns UTC datetime.
    """
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        logger.warning("Could not parse timestamp '%s' — using current time", ts_str[:50])
        return datetime.now(timezone.utc)


async def create_alert(
    db: AsyncSession,
    alert_in: AlertIngest,
) -> AlertModel:
    """
    Persist a validated alert to the database.

    Args:
        db: Active database session.
        alert_in: Validated Pydantic alert schema.

    Returns:
        Created AlertModel ORM instance.
    """
    parsed_ts = _parse_timestamp(alert_in.timestamp)

    # Serialize indicators list to JSON text (stored as TEXT column)
    indicators_json = json.dumps(alert_in.indicators)

    alert = AlertModel(
        hostname=alert_in.hostname,
        timestamp=parsed_ts,
        boot_source=alert_in.boot_source,
        kernel=alert_in.kernel,
        detected_os=alert_in.detected_os,
        risk_score=alert_in.risk_score,
        risk_level=alert_in.risk_level,
        indicators=indicators_json,
    )

    db.add(alert)
    await db.flush()  # Get ID without committing
    await db.refresh(alert)

    logger.info(
        "Alert stored: id=%d host=%s score=%d level=%s",
        alert.id, alert.hostname, alert.risk_score, alert.risk_level
    )

    return alert


async def upsert_host(
    db: AsyncSession,
    alert_in: AlertIngest,
) -> None:
    """
    Create or update the host record based on incoming alert.
    """
    parsed_ts = _parse_timestamp(alert_in.timestamp)

    # Check if host exists
    stmt = select(HostModel).where(HostModel.hostname == alert_in.hostname)
    result = await db.execute(stmt)
    host = result.scalar_one_or_none()

    if host:
        # Update existing host
        host.last_seen = parsed_ts
        host.last_boot_source = alert_in.boot_source
        host.last_detected_os = alert_in.detected_os
        host.last_risk_score = alert_in.risk_score
        host.last_risk_level = alert_in.risk_level
        host.alert_count = (host.alert_count or 0) + 1
    else:
        # Create new host record
        host = HostModel(
            hostname=alert_in.hostname,
            last_seen=parsed_ts,
            last_boot_source=alert_in.boot_source,
            last_detected_os=alert_in.detected_os,
            last_risk_score=alert_in.risk_score,
            last_risk_level=alert_in.risk_level,
            alert_count=1,
        )
        db.add(host)


def alert_to_dict(alert: AlertModel) -> dict:
    """
    Convert an AlertModel ORM object to a serializable dict.
    Safe for WebSocket broadcast or API response.
    """
    try:
        indicators = json.loads(alert.indicators) if alert.indicators else []
    except (json.JSONDecodeError, TypeError):
        indicators = []

    return {
        "id": alert.id,
        "hostname": alert.hostname,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "boot_source": alert.boot_source,
        "kernel": alert.kernel,
        "detected_os": alert.detected_os,
        "risk_score": alert.risk_score,
        "risk_level": alert.risk_level,
        "indicators": indicators,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


async def get_stats(db: AsyncSession) -> dict:
    """
    Compute aggregate statistics for the dashboard.
    """
    # Total alerts
    total_stmt = select(func.count(AlertModel.id))
    total_result = await db.execute(total_stmt)
    total_alerts = total_result.scalar() or 0

    # Critical alerts
    critical_stmt = select(func.count(AlertModel.id)).where(AlertModel.risk_level == "CRITICAL")
    critical_result = await db.execute(critical_stmt)
    critical_count = critical_result.scalar() or 0

    # Warning alerts
    warning_stmt = select(func.count(AlertModel.id)).where(AlertModel.risk_level == "WARNING")
    warning_result = await db.execute(warning_stmt)
    warning_count = warning_result.scalar() or 0

    # Normal events
    normal_count = total_alerts - critical_count - warning_count

    # Monitored hosts
    hosts_stmt = select(func.count(HostModel.id))
    hosts_result = await db.execute(hosts_stmt)
    monitored_hosts = hosts_result.scalar() or 0

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_count,
        "warning_alerts": warning_count,
        "normal_events": max(0, normal_count),
        "monitored_hosts": monitored_hosts,
    }
