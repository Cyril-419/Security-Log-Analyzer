"""Rule-based detections.

Each rule keeps a *sliding time window* per source IP: a deque of recent
events, where old entries fall off the left as new ones arrive on the right.
That makes every rule O(1) amortized per event, which is what lets the tool
stream through millions of events.

Rules
-----
brute_force       many failed logins from one IP in a short window
                  (MITRE ATT&CK T1110.001 - Password Guessing)
password_spray    failed logins from one IP against many *different* users
                  (T1110.003 - Password Spraying)
success_after_fail a successful login from an IP that was just failing
                  (possible compromised account - the one to look at first)
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Iterator

from .models import LOGIN_FAILURE, LOGIN_SUCCESS, Alert, Event


@dataclass
class Thresholds:
    window_minutes: int = 5
    brute_force_failures: int = 10     # failures from one IP inside the window
    spray_distinct_users: int = 5      # distinct usernames from one IP inside the window
    success_after_failures: int = 5    # failures before a success to flag it


class Detector:
    def __init__(self, thresholds: Thresholds | None = None):
        self.t = thresholds or Thresholds()
        self.window = timedelta(minutes=self.t.window_minutes)
        # per-IP state
        self._fails: dict[str, deque[Event]] = defaultdict(deque)
        self._users: dict[str, Counter] = defaultdict(Counter)
        self._bf_alerted: set[str] = set()
        self._spray_alerted: set[str] = set()
        self._saf_alerted: set[str] = set()

    # -- window maintenance -------------------------------------------------
    def _expire(self, ip: str, now) -> None:
        q, users = self._fails[ip], self._users[ip]
        while q and now - q[0].timestamp > self.window:
            old = q.popleft()
            if old.user:
                users[old.user] -= 1
                if users[old.user] <= 0:
                    del users[old.user]
        if not q:
            # IP went quiet: allow it to alert again in a future burst
            self._bf_alerted.discard(ip)
            self._spray_alerted.discard(ip)
            self._saf_alerted.discard(ip)

    # -- main entry point ---------------------------------------------------
    def process(self, event: Event) -> list[Alert]:
        ip = event.src_ip
        if not ip:
            return []
        self._expire(ip, event.timestamp)
        q, users = self._fails[ip], self._users[ip]
        alerts: list[Alert] = []

        if event.event_type == LOGIN_FAILURE:
            q.append(event)
            if event.user:          # web logs often have no username
                users[event.user] += 1

            # Spray is checked first: it is the more specific finding, and once an
            # IP is flagged as spraying we don't also call the same burst brute force.
            if len(users) >= self.t.spray_distinct_users and ip not in self._spray_alerted:
                self._spray_alerted.add(ip)
                alerts.append(self._alert("password_spray", "high", ip, q, users,
                    f"{ip} tried {len(users)} different accounts within {self.t.window_minutes} min"))

            if (len(q) >= self.t.brute_force_failures and ip not in self._bf_alerted
                    and ip not in self._spray_alerted):
                self._bf_alerted.add(ip)
                alerts.append(self._alert("brute_force", "medium", ip, q, users,
                    f"{len(q)} failed logins from {ip} within {self.t.window_minutes} min"))

        elif event.event_type == LOGIN_SUCCESS:
            if len(q) >= self.t.success_after_failures and ip not in self._saf_alerted:
                self._saf_alerted.add(ip)
                alerts.append(Alert(
                    rule="success_after_failures", severity="high", src_ip=ip,
                    first_seen=q[0].timestamp, last_seen=event.timestamp,
                    event_count=len(q) + 1, users=[event.user or "?"],
                    description=(f"Successful login as '{event.user}' from {ip} after "
                                 f"{len(q)} failures - possible compromised account"),
                ))
        return alerts

    def _alert(self, rule, severity, ip, q, users, desc) -> Alert:
        return Alert(rule, severity, ip, q[0].timestamp, q[-1].timestamp,
                     len(q), sorted(u for u in users if u), desc)


def run_detections(events: Iterable[Event], thresholds: Thresholds | None = None) -> Iterator[Alert]:
    """Feed a time-ordered stream of events through the rules."""
    det = Detector(thresholds)
    for ev in events:
        yield from det.process(ev)
