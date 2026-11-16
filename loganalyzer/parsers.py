"""Log parsers: raw lines in, normalized `Event` objects out.

All parsers are generators, so a file is read one line at a time and memory
use stays flat no matter how big the log is.

Supported formats
-----------------
linux   : OpenSSH entries from /var/log/auth.log or /var/log/secure
windows : Security log events 4624 (success) and 4625 (failure), exported
          from PowerShell as JSON (see README for the export command)
web     : Apache/Nginx "combined" access log. A 401 response, or a 401/403
          on a login URL, counts as a failed login.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .models import LOGIN_FAILURE, LOGIN_SUCCESS, Event

# ---------------------------------------------------------------- Linux (sshd)
# Example lines:
# Nov 16 09:12:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2
# Nov 16 09:12:09 web01 sshd[1240]: Accepted password for cyril from 10.0.0.12 port 50022 ssh2
_LINUX_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_LINUX_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
_LINUX_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_LINUX_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)


def parse_linux(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse sshd lines. Syslog omits the year, so pass one in (defaults to this year)."""
    year = year or datetime.now().year
    for line in lines:
        m = _LINUX_PREFIX.match(line)
        if not m:
            continue
        msg = m["msg"]
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")

        if (hit := _LINUX_FAILED.search(msg)):
            etype = LOGIN_FAILURE
        elif (hit := _LINUX_ACCEPTED.search(msg)):
            etype = LOGIN_SUCCESS
        else:
            # "Invalid user X from IP" is logged *in addition to* the
            # "Failed password" line, so we skip it to avoid double counting.
            continue
        yield Event(ts, "linux", etype, hit["ip"], hit["user"], m["host"], line.rstrip("\n"))


# ----------------------------------------------------------- Windows (Security)
_WIN_EVENT_TYPES = {4625: LOGIN_FAILURE, 4624: LOGIN_SUCCESS}
_WIN_EMPTY = {None, "", "-", "::1", "127.0.0.1"}


def _parse_win_time(value: str) -> datetime:
    # PowerShell "o" format: 2026-11-16T09:12:01.1234567-06:00 (7 fractional digits)
    # Python accepts at most 6 fractional digits, so trim any extras.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value.strip())
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts.replace(tzinfo=None)  # compare everything as naive local time


def parse_windows(text: str) -> Iterator[Event]:
    """Accept a JSON array or JSON Lines of exported Security events."""
    text = text.strip()
    if not text:
        return
    if text.startswith("["):
        records = json.loads(text)
    else:
        records = (json.loads(l) for l in text.splitlines() if l.strip())

    for rec in records:
        event_id = int(rec.get("EventID") or rec.get("Id") or 0)
        etype = _WIN_EVENT_TYPES.get(event_id)
        if etype is None:
            continue
        # Logon type 3 = network, 10 = RDP. Ignore service/batch noise (4, 5).
        logon_type = str(rec.get("LogonType", ""))
        if logon_type in {"4", "5"}:
            continue
        ip = rec.get("IpAddress")
        yield Event(
            timestamp=_parse_win_time(rec["TimeCreated"]),
            source="windows",
            event_type=etype,
            src_ip=None if ip in _WIN_EMPTY else ip,
            user=rec.get("TargetUserName"),
            host=rec.get("Computer"),
            raw=json.dumps(rec),
        )


# ---------------------------------------------------------- Web (access log)
# 198.51.100.7 - admin [16/Nov/2026:09:12:01 -0600] "POST /login HTTP/1.1" 401 512 "-" "curl/8.0"
_WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)
_LOGIN_PATH = re.compile(r"/(login|signin|wp-login\.php|auth|admin)", re.IGNORECASE)


def parse_web(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        m = _WEB_LINE.match(line)
        if not m:
            continue
        status = int(m["status"])
        is_login_url = bool(_LOGIN_PATH.search(m["path"]))

        if status == 401 or (status == 403 and is_login_url):
            etype = LOGIN_FAILURE
        elif is_login_url and m["method"] == "POST" and status in (200, 302):
            etype = LOGIN_SUCCESS
        else:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        user = None if m["user"] == "-" else m["user"]
        yield Event(ts, "web", etype, m["ip"], user, None, line.rstrip("\n"))


# ------------------------------------------------------------- auto-detection
def detect_format_text(text: str) -> str:
    """Guess the log format from the first few KB of text."""
    head = text[:4096].lstrip("﻿ \t\r\n")
    if head.startswith("[") or head.startswith("{"):
        return "windows"
    first = head.splitlines()[0] if head else ""
    if _WEB_LINE.match(first):
        return "web"
    return "linux"


def detect_format(path: Path) -> str:
    with path.open(encoding="utf-8", errors="replace") as f:
        return detect_format_text(f.read(4096))


def parse_text(text: str, fmt: str = "auto", year: int | None = None) -> Iterator[Event]:
    """Parse logs that are already in memory (used by the REST API)."""
    if fmt == "auto":
        fmt = detect_format_text(text)
    if fmt == "windows":
        return parse_windows(text)
    if fmt == "linux":
        return parse_linux(text.splitlines(), year)
    if fmt == "web":
        return parse_web(text.splitlines())
    raise ValueError(f"unknown format: {fmt}")


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> Iterator[Event]:
    path = Path(path)
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "windows":
        yield from parse_windows(path.read_text(encoding="utf-8-sig"))
        return
    with path.open(encoding="utf-8", errors="replace") as f:
        if fmt == "linux":
            yield from parse_linux(f, year)
        elif fmt == "web":
            yield from parse_web(f)
        else:
            raise ValueError(f"unknown format: {fmt}")
