"""
models.py - SQLAlchemy ORM models and Pydantic schemas for LiveBoot Sentinel server.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase


# ─── SQLAlchemy ORM ───────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class AlertModel(Base):
    """SQLAlchemy ORM model for the alerts table."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(253), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    boot_source = Column(String(50), nullable=False)
    kernel = Column(String(256), nullable=False)
    detected_os = Column(String(100), nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(20), nullable=False, default="NORMAL")
    indicators = Column(Text, nullable=False, default="[]")  # JSON array stored as text
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class HostModel(Base):
    """SQLAlchemy ORM model for tracking monitored hosts."""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(253), unique=True, nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    last_boot_source = Column(String(50), nullable=True)
    last_detected_os = Column(String(100), nullable=True)
    last_risk_score = Column(Integer, default=0)
    last_risk_level = Column(String(20), default="NORMAL")
    alert_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─── Validation Helpers ───────────────────────────────────────────────────────

HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
INDICATOR_RE = re.compile(r"^[\w:.\-]{1,200}$")
SAFE_STRING_RE = re.compile(r"^[\w\s.\-+#()@:,/]+$")
RISK_LEVELS = {"NORMAL", "WARNING", "CRITICAL"}


# ─── Pydantic Schemas (API Input/Output) ─────────────────────────────────────

class AlertIngest(BaseModel):
    """Schema for incoming alert POST requests from agents."""

    hostname: str = Field(..., min_length=1, max_length=253)
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    boot_source: str = Field(..., min_length=1, max_length=50)
    kernel: str = Field(..., min_length=1, max_length=256)
    detected_os: Optional[str] = Field(None, max_length=100)
    risk_score: int = Field(..., ge=0, le=200)
    risk_level: str = Field(..., max_length=20)
    indicators: list[str] = Field(..., max_length=100)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip().lower()
        if not HOSTNAME_RE.match(v) and v != "localhost":
            raise ValueError("Invalid hostname format")
        return v[:253]

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Invalid ISO 8601 timestamp")
        return v[:50]

    @field_validator("boot_source")
    @classmethod
    def validate_boot_source(cls, v: str) -> str:
        allowed = {"usb", "disk", "unknown", "network", "other"}
        v = v.strip().lower()
        if v not in allowed:
            # Sanitize and return as generic string
            v = re.sub(r"[^\w]", "", v)[:50] or "unknown"
        return v

    @field_validator("kernel")
    @classmethod
    def validate_kernel(cls, v: str) -> str:
        v = v.strip()
        # Allow kernel version characters
        v = re.sub(r"[^\w\s.\-+#()@:,/]", "", v)
        return v[:256]

    @field_validator("detected_os")
    @classmethod
    def validate_detected_os(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        v = re.sub(r"[^\w\s.\-()]", "", v)
        return v[:100] or None

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in RISK_LEVELS:
            return "UNKNOWN"
        return v

    @field_validator("indicators")
    @classmethod
    def validate_indicators(cls, v: list) -> list:
        clean = []
        for ind in v[:100]:
            if isinstance(ind, str):
                ind_clean = re.sub(r"[^\w:.\-]", "", ind)[:200]
                if ind_clean:
                    clean.append(ind_clean)
        return clean

    @model_validator(mode="after")
    def validate_score_level_consistency(self) -> "AlertIngest":
        """Cross-field validation: ensure score and level are consistent."""
        score = self.risk_score
        level = self.risk_level
        if level == "CRITICAL" and score < 50:
            self.risk_level = "WARNING" if score >= 30 else "NORMAL"
        elif level == "WARNING" and score < 30:
            self.risk_level = "NORMAL"
        elif level == "NORMAL" and score >= 50:
            self.risk_level = "CRITICAL"
        return self


class AlertOut(BaseModel):
    """Schema for alert data returned to API consumers."""
    id: int
    hostname: str
    timestamp: str
    boot_source: str
    kernel: str
    detected_os: Optional[str]
    risk_score: int
    risk_level: str
    indicators: list[str]
    created_at: Optional[str]

    model_config = {"from_attributes": True}


class HostOut(BaseModel):
    """Schema for host data returned to API consumers."""
    id: int
    hostname: str
    last_seen: str
    last_boot_source: Optional[str]
    last_detected_os: Optional[str]
    last_risk_score: int
    last_risk_level: str
    alert_count: int

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    """Schema for health check endpoint."""
    status: str
    version: str
    timestamp: str
