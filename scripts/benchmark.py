"""Measure throughput on a large synthetic log.

    python scripts/benchmark.py --events 1000000

Generates ~1M auth events (Linux sshd format, with planted attacks), runs the
full pipeline (parse -> SQLite -> detect), and checks that every planted attack
was found and nothing else.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=1_000_000)
    ap.add_argument("--keep", action="store_true", help="keep the generated files")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="loganalyzer-bench-"))
    try:
        print(f"Generating {args.events:,} events...")
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_logs.py"),
                        "--out", str(work), "--events", str(args.events), "--only", "linux"],
                       check=True)
        log = work / "auth.log"
        size_mb = log.stat().st_size / 1e6
        db = work / "bench.db"

        print(f"Analyzing {log.name} ({size_mb:,.0f} MB)...")
        t0 = time.perf_counter()
        subprocess.run([sys.executable, "-m", "loganalyzer", "analyze", str(log), "--db", str(db),
                        "--year", "2026", "--no-color", "--no-raw"],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        elapsed = time.perf_counter() - t0

        con = sqlite3.connect(db)
        n_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = dict(con.execute("SELECT rule, COUNT(*) FROM alerts GROUP BY rule").fetchall())
        expected = {"brute_force": 1, "password_spray": 1, "success_after_failures": 1}

        print("\n--- RESULTS ---")
        print(f"Events processed : {n_events:,}")
        print(f"Log size         : {size_mb:,.0f} MB")
        print(f"Wall time        : {elapsed:.1f} s (includes Python startup)")
        print(f"Throughput       : {n_events / elapsed:,.0f} events/sec")
        print(f"Alerts           : {alerts}")
        print(f"Detection check  : {'PASS - all planted attacks found, no false positives' if alerts == expected else 'FAIL - expected ' + str(expected)}")
    finally:
        if args.keep:
            print(f"Files kept in {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
