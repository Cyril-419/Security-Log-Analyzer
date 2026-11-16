"""Command-line interface.

    python -m loganalyzer analyze sample_logs/*  --db results.db
    python -m loganalyzer report --db results.db
"""
from __future__ import annotations

import argparse
import heapq
import sys
import time
from pathlib import Path

from .detectors import Thresholds, run_detections
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
    counter = {"n": 0}

    def counted(events):
        for ev in events:
            counter["n"] += 1
            yield ev

    n_alerts = store.save_alerts(run_detections(store.save_events(counted(merged)), thresholds))
    elapsed = time.perf_counter() - start

    n_events = counter["n"]
    rate = n_events / elapsed if elapsed else 0
    print(f"Processed {n_events:,} events from {len(paths)} file(s) in {elapsed:.2f}s "
          f"({rate:,.0f} events/sec) -> {n_alerts} alert(s). DB: {args.db}")
    print_report(store, color=sys.stdout.isatty() and not args.no_color)
    store.close()
    return 1 if n_alerts and args.fail_on_alert else 0


def cmd_report(args) -> int:
    if not Path(args.db).exists():
        print(f"error: database not found: {args.db}", file=sys.stderr)
        return 2
    store = Store(args.db)
    print_report(store, color=sys.stdout.isatty() and not args.no_color)
    store.close()
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
    a.add_argument("--no-raw",action="store_true", help="don't store raw lines (smaller DB)")
    a.add_argument("--fail-on-alert", action="store_true", help="exit 1 if any alert fires")
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("report", help="print alerts from an existing database")
    r.add_argument("--db", default="results.db")
    r.add_argument("--no-color", action="store_true")
    r.set_defaults(func=cmd_report)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
