"""Shared data types.

Every parser turns its raw log format into the same `Event` shape, so the
detection rules never need to know whether a line came from Windows, Linux
or a web server. This is called *normalization*, the same idea a SIEM uses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Normalized event types
LOGIN_FAILURE = "login_failure"
LOGIN_SUCCESS = "login_success"


@dataclass(slots=True)
class Event:
    timestamp: datetime
    source: str          # "linux", "windows" or "web"
    event_type: str      # LOGIN_FAILURE or LOGIN_SUCCESS
    src_ip: str | None
    user: str | None
    host: str | None = None
    raw: str = ""


@dataclass(slots=True)
class Alert:
    rule: str            # e.g. "brute_force"
    severity: str        # "low" | "medium" | "high"
    src_ip: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    users: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        """JSON-friendly form, used by --json output and the REST API."""
        return {
            "rule": self.rule,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "users": self.users,
            "description": self.description,
        }
