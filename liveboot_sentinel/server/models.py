"""
models.py - SQLAlchemy ORM models and Pydantic schemas.
Updated to include post-boot attack technique fields.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import Column, DateTime, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class AlertModel(Base):
    __tablename__ = "alerts"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    hostname      = Column(String(253), nullable=False, index=True)
    timestamp     = Column(DateTime(timezone=True), nullable=False, index=True)
    boot_source   = Column(String(50), nullable=False)
    kernel        = Column(String(256), nullable=False)
    detected_os   = Column(String(100), nullable=True)
    risk_score    = Column(Integer, nullable=False, default=0)
    risk_level    = Column(String(20), nullable=False, default="NORMAL")
    indicators    = Column(Text, nullable=False, default="[]")
    # New post-boot attack fields
    attack_techniques = Column(Text, nullable=True, default="{}")
    attack_summary    = Column(Text, nullable=True, default="")
    created_at    = Column(DateTime(timezone=True), server_default=func.now())


class HostModel(Base):
    __tablename__ = "hosts"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    hostname          = Column(String(253), unique=True, nullable=False, index=True)
    last_seen         = Column(DateTime(timezone=True), nullable=False)
    last_boot_source  = Column(String(50), nullable=True)
    last_detected_os  = Column(String(100), nullable=True)
    last_risk_score   = Column(Integer, default=0)
    last_risk_level   = Column(String(20), default="NORMAL")
    alert_count       = Column(Integer, default=0)
    # New post-boot fields
    last_attack_techniques = Column(Text, nullable=True, default="{}")
    created_at        = Column(DateTime(timezone=True), server_default=func.now())


HOSTNAME_RE   = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
INDICATOR_RE  = re.compile(r"^[\w:.\-]{1,200}$")
RISK_LEVELS   = {"NORMAL", "WARNING", "CRITICAL"}


class AlertIngest(BaseModel):
    hostname:    str           = Field(..., min_length=1, max_length=253)
    timestamp:   str           = Field(...)
    boot_source: str           = Field(..., min_length=1, max_length=50)
    kernel:      str           = Field(..., min_length=1, max_length=256)
    detected_os: Optional[str] = Field(None, max_length=100)
    risk_score:  int           = Field(..., ge=0, le=200)
    risk_level:  str           = Field(..., max_length=20)
    indicators:  list[str]     = Field(..., max_length=100)
    # New optional post-boot fields
    attack_techniques: Optional[dict] = Field(default={})
    attack_summary:    Optional[str]  = Field(default="", max_length=2000)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v):
        v = v.strip().lower()
        if not HOSTNAME_RE.match(v) and v != "localhost":
            raise ValueError("Invalid hostname")
        return v[:253]

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Invalid ISO 8601 timestamp")
        return v[:50]

    @field_validator("boot_source")
    @classmethod
    def validate_boot_source(cls, v):
        allowed = {"usb", "disk", "unknown", "network", "other"}
        v = v.strip().lower()
        return v if v in allowed else re.sub(r"[^\w]", "", v)[:50] or "unknown"

    @field_validator("kernel")
    @classmethod
    def validate_kernel(cls, v):
        return re.sub(r"[^\w\s.\-+#()@:,/]", "", v.strip())[:256]

    @field_validator("detected_os")
    @classmethod
    def validate_detected_os(cls, v):
        if v is None:
            return None
        return re.sub(r"[^\w\s.\-()]", "", v.strip())[:100] or None

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        v = v.strip().upper()
        return v if v in RISK_LEVELS else "UNKNOWN"

    @field_validator("indicators")
    @classmethod
    def validate_indicators(cls, v):
        return [re.sub(r"[^\w:.\-]", "", i)[:200] for i in v[:100] if isinstance(i, str) and i]

    @field_validator("attack_techniques")
    @classmethod
    def validate_attack_techniques(cls, v):
        if not isinstance(v, dict):
            return {}
        # Sanitize keys and values
        clean = {}
        for k, val in list(v.items())[:20]:
            safe_k = re.sub(r"[^\w\s]", "", str(k))[:50]
            if isinstance(val, list):
                clean[safe_k] = [re.sub(r"[^\w:.\-]", "", str(i))[:100] for i in val[:10]]
            else:
                clean[safe_k] = str(val)[:100]
        return clean

    @model_validator(mode="after")
    def validate_score_level(self):
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
    id:          int
    hostname:    str
    timestamp:   str
    boot_source: str
    kernel:      str
    detected_os: Optional[str]
    risk_score:  int
    risk_level:  str
    indicators:  list[str]
    attack_techniques: Optional[dict]
    attack_summary:    Optional[str]
    created_at:  Optional[str]

    model_config = {"from_attributes": True}


class HostOut(BaseModel):
    id:               int
    hostname:         str
    last_seen:        str
    last_boot_source: Optional[str]
    last_detected_os: Optional[str]
    last_risk_score:  int
    last_risk_level:  str
    alert_count:      int
    last_attack_techniques: Optional[dict]

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    status:    str
    version:   str
    timestamp: str
