"""SQLite storage for events and alerts.

SQLite ships with Python, needs no server, and the same SQL works later if
you move to PostgreSQL. Events are inserted in batches inside a single
transaction, which is far faster than committing row by row.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    src_ip      TEXT,
    username    TEXT,
    host        TEXT,
    raw         TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    src_ip      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    users       TEXT,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:", store_raw: bool = True):
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)
        self.store_raw = store_raw

    def reset(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM events")
            self.conn.execute("DELETE FROM alerts")

    def save_events(self, events: Iterable[Event], batch_size: int = 10_000) -> Iterator[Event]:
        """Pass-through generator: writes events to the DB while yielding them on
        to the detector, so the log is only read once."""
        batch = []
        with self.conn:
            for ev in events:
                batch.append((ev.timestamp.isoformat(sep=" "), ev.source, ev.event_type,
                              ev.src_ip, ev.user, ev.host, ev.raw if self.store_raw else None))
                if len(batch) >= batch_size:
                    self._insert_events(batch)
                    batch.clear()
                yield ev
            if batch:
                self._insert_events(batch)

    def _insert_events(self, rows) -> None:
        self.conn.executemany(
            "INSERT INTO events (timestamp, source, event_type, src_ip, username, host, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

    def save_alerts(self, alerts: Iterable[Alert]) -> int:
        rows = [(a.rule, a.severity, a.src_ip, a.first_seen.isoformat(sep=" "),
                 a.last_seen.isoformat(sep=" "), a.event_count, ",".join(a.users), a.description)
                for a in alerts]
        with self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (rule, severity, src_ip, first_seen, last_seen, "
                "event_count, users, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        return len(rows)

    # -- queries used by the report ----------------------------------------
    def count(self, table: str) -> int:
        assert table in {"events", "alerts"}
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def alerts(self):
        return self.conn.execute(
            "SELECT severity, rule, src_ip, first_seen, event_count, description FROM alerts "
            "ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, first_seen"
        ).fetchall()

    def top_failing_ips(self, limit: int = 5):
        return self.conn.execute(
            "SELECT src_ip, COUNT(*) AS n FROM events WHERE event_type = 'login_failure' "
            "AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT ?", (limit,)
        ).fetchall()

    def close(self) -> None:
        self.conn.close()
