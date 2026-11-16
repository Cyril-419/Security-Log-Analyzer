"""JSON results and a small REST API.

    python -m loganalyzer serve                 # http://127.0.0.1:8080
    curl -s localhost:8080/health
    curl -s -X POST localhost:8080/analyze \\
         -H "Content-Type: application/json" \\
         -d '{"format": "linux", "logs": "<log text>"}'

Built on the standard library's http.server so the tool still has zero
dependencies. Every request is stateless: logs in, alerts out.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, fields
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterable

from . import __version__
from .detectors import Thresholds, run_detections
from .models import LOGIN_FAILURE, Event
from .parsers import detect_format_text, parse_text

MAX_BODY_BYTES = 10 * 1024 * 1024        # reject request bodies over 10 MB
FORMATS = {"auto", "linux", "windows", "web"}
THRESHOLD_FIELDS = {f.name for f in fields(Thresholds)}


class RequestError(ValueError):
    """Client sent something invalid; becomes a 400 response."""


# ------------------------------------------------------------- core analysis
def analyze_events(events: Iterable[Event], thresholds: Thresholds | None = None,
                   alert_sink: list | None = None) -> dict:
    """Run detections over events and return a JSON-ready result.

    If alert_sink is given, the Alert objects are also appended to it
    (the CLI uses this to save them to SQLite)."""
    thresholds = thresholds or Thresholds()
    counts = {"total": 0, "failures": 0, "successes": 0}
    failing_ips: dict[str, int] = {}

    def counted(stream):
        for ev in stream:
            counts["total"] += 1
            if ev.event_type == LOGIN_FAILURE:
                counts["failures"] += 1
                if ev.src_ip:
                    failing_ips[ev.src_ip] = failing_ips.get(ev.src_ip, 0) + 1
            else:
                counts["successes"] += 1
            yield ev

    start = time.perf_counter()
    alert_objs = list(run_detections(counted(events), thresholds))
    if alert_sink is not None:
        alert_sink.extend(alert_objs)
    alerts = [a.to_dict() for a in alert_objs]
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    top = sorted(failing_ips.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return {
        "summary": {
            "events": counts["total"],
            "login_failures": counts["failures"],
            "login_successes": counts["successes"],
            "alerts": len(alerts),
            "elapsed_ms": elapsed_ms,
        },
        "thresholds": asdict(thresholds),
        "alerts": alerts,
        "top_failing_ips": [{"src_ip": ip, "failures": n} for ip, n in top],
    }


def parse_thresholds(raw) -> Thresholds:
    if raw is None:
        return Thresholds()
    if not isinstance(raw, dict):
        raise RequestError("'thresholds' must be an object")
    unknown = set(raw) - THRESHOLD_FIELDS
    if unknown:
        raise RequestError(f"unknown threshold(s): {', '.join(sorted(unknown))}; "
                           f"allowed: {', '.join(sorted(THRESHOLD_FIELDS))}")
    for k, v in raw.items():
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 100_000:
            raise RequestError(f"threshold '{k}' must be a whole number from 1 to 100000")
    return Thresholds(**raw)


def analyze_request(body: dict) -> dict:
    """Validate an /analyze request body and run the analysis."""
    if not isinstance(body, dict):
        raise RequestError("request body must be a JSON object")
    logs = body.get("logs")
    if not isinstance(logs, str) or not logs.strip():
        raise RequestError("'logs' is required and must be a non-empty string")
    fmt = body.get("format", "auto")
    if fmt not in FORMATS:
        raise RequestError(f"'format' must be one of: {', '.join(sorted(FORMATS))}")
    year = body.get("year")
    if year is not None and (not isinstance(year, int) or not 1970 <= year <= 2100):
        raise RequestError("'year' must be a 4-digit year")

    resolved = detect_format_text(logs) if fmt == "auto" else fmt
    try:
        events = list(parse_text(logs, resolved, year))
    except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError) as err:
        raise RequestError(f"could not parse logs as {resolved}: {err}") from None
    # Logs from different sources may be unsorted; the detectors need time order.
    events.sort(key=lambda e: e.timestamp)

    result = analyze_events(events, parse_thresholds(body.get("thresholds")))
    result["format"] = resolved
    return result


# --------------------------------------------------------------- HTTP server
class Handler(BaseHTTPRequestHandler):
    server_version = f"loganalyzer/{__version__}"
    quiet = False

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._send(status, {"error": status.phrase, "message": message})

    def log_message(self, fmt, *args):  # keep test output clean when quiet
        if not self.quiet:
            super().log_message(fmt, *args)

    def do_GET(self):
        if self.path == "/health":
            self._send(HTTPStatus.OK, {"status": "ok", "version": __version__})
        elif self.path == "/analyze":
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "use POST for /analyze")
        else:
            self._error(HTTPStatus.NOT_FOUND, f"no route for {self.path}")

    def do_POST(self):
        if self.path != "/analyze":
            return self._error(HTTPStatus.NOT_FOUND, f"no route for {self.path}")
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send Content-Type: application/json")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length header is required")
        if length > MAX_BODY_BYTES:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               f"body is over the {MAX_BODY_BYTES // (1024 * 1024)} MB limit")
        try:
            body = json.loads(self.rfile.read(length) or b"null")
            self._send(HTTPStatus.OK, analyze_request(body))
        except json.JSONDecodeError:
            self._error(HTTPStatus.BAD_REQUEST, "body is not valid JSON")
        except RequestError as err:
            self._error(HTTPStatus.BAD_REQUEST, str(err))
        except Exception:  # never leak a stack trace to the client
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "unexpected error while analyzing logs")

    def do_PUT(self):
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "only GET /health and POST /analyze are supported")

    do_DELETE = do_PATCH = do_PUT


def make_server(host: str = "127.0.0.1", port: int = 8080, quiet: bool = False) -> ThreadingHTTPServer:
    handler = type("QuietHandler" if quiet else "Handler", (Handler,), {"quiet": quiet})
    return ThreadingHTTPServer((host, port), handler)
