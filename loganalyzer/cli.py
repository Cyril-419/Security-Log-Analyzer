"""Command-line interface.

    python -m loganalyzer analyze sample_logs/*  --db results.db
    python -m loganalyzer report --db results.db
"""
from __future__ import annotations

import argparse
import heapq
import json
import sys
import time
from pathlib import Path

from .api import analyze_events, make_server
from .detectors import Thresholds
from .parsers import parse_file
from .storage import Store

SEV_COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"


def _color(sev: str, text: str, enabled: bool) -> str:
    return f"{SEV_COLOR.get(sev, '')}{text}{RESET}" if enabled else text


def print_report(store: Store, color: bool) -> None:
    print(f"\nEvents stored: {store.count('events'):,}   Alerts: {store.count('alerts'):,}\n")
    rows = store.alerts()
    if rows:
        print("ALERTS")
        for sev, rule, ip, first, count, desc in rows:
            tag = _color(sev, f"[{sev.upper():6}]", color)
            print(f"  {tag} {first}  {rule:<24} {desc}")
    else:
        print("No alerts.")
    top = store.top_failing_ips()
    if top:
        print("\nTOP SOURCES OF FAILED LOGINS")
        for ip, n in top:
            print(f"  {ip:<40} {n:>8,}")
    print()


def cmd_analyze(args) -> int:
    paths = [Path(p) for p in args.files]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"error: file not found: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2

    thresholds = Thresholds(args.window, args.bf_threshold, args.spray_threshold,
                            args.saf_threshold)
    store = Store(args.db, store_raw=not args.no_raw)
    if not args.append:
        store.reset()

    start = time.perf_counter()
    # Each file is already in time order; heapq.merge interleaves them into one
    # time-ordered stream without loading everything into memory.
    streams = [parse_file(p, args.format, args.year) for p in paths]
    merged = heapq.merge(*streams, key=lambda e: e.timestamp)

    alerts = []
    result = analyze_events(store.save_events(merged), thresholds, alert_sink=alerts)
    store.save_alerts(alerts)
    elapsed = time.perf_counter() - start
    store.close()

    if args.json:
        result["files"] = [str(p) for p in paths]
        result["database"] = args.db
        print(json.dumps(result, indent=2))
    else:
        n_events = result["summary"]["events"]
        rate = n_events / elapsed if elapsed else 0
        print(f"Processed {n_events:,} events from {len(paths)} file(s) in {elapsed:.2f}s "
              f"({rate:,.0f} events/sec) -> {len(alerts)} alert(s). DB: {args.db}")
        store = Store(args.db)
        print_report(store, color=sys.stdout.isatty() and not args.no_color)
        store.close()
    return 1 if alerts and args.fail_on_alert else 0


def cmd_report(args) -> int:
    if not Path(args.db).exists():
        print(f"error: database not found: {args.db}", file=sys.stderr)
        return 2
    store = Store(args.db)
    if args.json:
        print(json.dumps({"events": store.count("events"),
                          "alerts": [dict(zip(("severity", "rule", "src_ip", "first_seen",
                                                   "event_count", "description"), row))
                                     for row in store.alerts()]}, indent=2))
    else:
        print_report(store, color=sys.stdout.isatty() and not args.no_color)
    store.close()
    return 0


def cmd_serve(args) -> int:
    server = make_server(args.host, args.port)
    host, port = server.server_address[:2]
    print(f"loganalyzer API listening on http://{host}:{port}  (GET /health, POST /analyze)")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: listening on a non-local address with no authentication", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loganalyzer",
                                description="Detect brute force and password spraying in auth logs.")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="parse logs, run detections, store results")
    a.add_argument("files", nargs="+", help="log files to analyze")
    a.add_argument("--format", choices=["auto", "linux", "windows", "web"], default="auto")
    a.add_argument("--db", default="results.db", help="SQLite output (default: results.db)")
    a.add_argument("--year", type=int, help="year for Linux syslog timestamps (default: current)")
    a.add_argument("--window", type=int, default=5, help="detection window in minutes")
    a.add_argument("--bf-threshold", type=int, default=10, help="failures for brute force alert")
    a.add_argument("--spray-threshold", type=int, default=5, help="distinct users for spray alert")
    a.add_argument("--saf-threshold", type=int, default=5,
                   help="failures before a success to flag it")
    a.add_argument("--append", action="store_true",
                   help="add to an existing database instead of starting fresh")
    a.add_argument("--no-raw", action="store_true", help="don't store raw lines (smaller DB)")
    a.add_argument("--fail-on-alert", action="store_true", help="exit 1 if any alert fires")
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--json", action="store_true", help="print results as JSON instead of a report")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("report", help="print alerts from an existing database")
    r.add_argument("--db", default="results.db")
    r.add_argument("--no-color", action="store_true")
    r.add_argument("--json", action="store_true", help="print results as JSON")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("serve", help="run the REST API (GET /health, POST /analyze)")
    s.add_argument("--host", default="127.0.0.1", help="address to bind (default: 127.0.0.1, local only)")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
