import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from loganalyzer.cli import main
from loganalyzer.models import LOGIN_FAILURE, Alert, Event
from loganalyzer.storage import Store

ROOT = Path(__file__).resolve().parent.parent


def test_store_roundtrip():
    store = Store(":memory:")
    ev = Event(datetime(2026, 11, 16, 9), "linux", LOGIN_FAILURE, "1.2.3.4", "root", "web01", "raw line")
    passed = list(store.save_events([ev, ev]))
    assert len(passed) == 2                       # events flow through unchanged
    assert store.count("events") == 2
    store.save_alerts([Alert("brute_force", "medium", "1.2.3.4", ev.timestamp, ev.timestamp,
                             10, ["root"], "test")])
    assert store.count("alerts") == 1
    assert store.top_failing_ips() == [("1.2.3.4", 2)]


def test_cli_end_to_end_on_sample_logs(tmp_path, capsys):
    db = tmp_path / "out.db"
    samples = sorted(str(p) for p in (ROOT / "sample_logs").iterdir())
    assert main(["analyze", *samples, "--db", str(db), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "password_spray" in out and "brute_force" in out and "success_after_failures" in out

    rows = sqlite3.connect(db).execute("SELECT rule, COUNT(*) FROM alerts GROUP BY rule").fetchall()
    # 3 planted attacks x 3 log sources, and nothing else
    assert dict(rows) == {"brute_force": 3, "password_spray": 3, "success_after_failures": 3}


def test_rerun_replaces_results(tmp_path):
    db = tmp_path / "out.db"
    sample = str(ROOT / "sample_logs" / "auth.log")
    main(["analyze", sample, "--db", str(db), "--no-color"])
    main(["analyze", sample, "--db", str(db), "--no-color"])
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3


def test_fail_on_alert_exit_code(tmp_path):
    sample = str(ROOT / "sample_logs" / "auth.log")
    assert main(["analyze", sample, "--db", str(tmp_path / "x.db"), "--fail-on-alert"]) == 1


def test_missing_file_returns_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.log"), "--db", str(tmp_path / "x.db")]) == 2


def test_runs_as_module(tmp_path):
    r = subprocess.run([sys.executable, "-m", "loganalyzer", "report", "--db", str(tmp_path / "none.db")],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 2 and "not found" in r.stderr
