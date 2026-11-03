from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class EventStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    event_id: str = ""  # filled in automatically below
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    process: str | None = None
    action: str | None = None
    status: EventStatus = EventStatus.UNKNOWN
    raw_message: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def force_utc(cls, v: datetime) -> datetime:
        # Naive timestamps are assumed UTC; aware ones are converted to UTC.
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        ip_address(v)  # raises ValueError if invalid
        return v

    @model_validator(mode="after")
    def make_event_id(self) -> NormalizedEvent:
        if not self.event_id:
            key = f"{self.source_type}|{self.timestamp.isoformat()}|{self.raw_message}"
            self.event_id = "evt_" + hashlib.sha256(key.encode()).hexdigest()[:16]
        return self