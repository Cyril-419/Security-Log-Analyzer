"""Generate realistic synthetic logs with known attacks planted in them.

Used for the sample_logs/ folder and for the benchmark. Because we know exactly
which attacks were planted, we can check the analyzer finds them.

    python scripts/generate_logs.py --out sample_logs --events 2000
    python scripts/generate_logs.py --out bench --events 1000000 --only linux
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

USERS = ["cyril", "jsmith", "mgarcia", "akim", "tnguyen", "backup", "dev", "hr_admin"]
SPRAY_TARGETS = ["admin", "administrator", "root", "test", "guest", "oracle", "postgres",
                 "ubuntu", "user", "support"]
INTERNAL = [f"10.0.0.{i}" for i in range(2, 60)]
BRUTE_IP, SPRAY_IP, COMPROMISE_IP = "203.0.113.45", "198.51.100.23", "192.0.2.77"


def _timeline(n: int, start: datetime, rng: random.Random, offset_h: int = 0):
    """n normal events plus three planted attacks, sorted by time.
    Yields (timestamp, kind, user, ip) where kind is 'fail' or 'ok'."""
    span = timedelta(hours=24)
    # Scale the number of internal hosts with volume so normal traffic per host
    # stays realistic (about 50 logins per host per day).
    n_hosts = max(len(INTERNAL), n // 50)
    hosts = INTERNAL if n_hosts == len(INTERNAL) else [
        f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}" for i in range(256, 256 + n_hosts)]
    rows = []
    for _ in range(n):
        ts = start + timedelta(seconds=rng.uniform(0, span.total_seconds()))
        # each host mostly belongs to one person
        ip = rng.choice(hosts)
        user = USERS[int(ip.rsplit(".", 1)[1]) % len(USERS)] if rng.random() < 0.9 else rng.choice(USERS)
        # ~8% of normal logins are fat-fingered passwords
        rows.append((ts, "fail" if rng.random() < 0.08 else "ok", user, ip))

    # Attack 1: brute force - 40 guesses at one account in ~2 minutes
    t = start + timedelta(hours=3 + offset_h)
    rows += [(t + timedelta(seconds=3 * i), "fail", "root", BRUTE_IP) for i in range(40)]
    # Attack 2: password spray - one guess each at 10 accounts, slow and quiet
    t = start + timedelta(hours=9 + offset_h)
    rows += [(t + timedelta(seconds=20 * i), "fail", u, SPRAY_IP) for i, u in enumerate(SPRAY_TARGETS)]
    # Attack 3: guessing that *succeeds*
    t = start + timedelta(hours=15 + offset_h)
    rows += [(t + timedelta(seconds=5 * i), "fail", "jsmith", COMPROMISE_IP) for i in range(8)]
    rows.append((t + timedelta(seconds=45), "ok", "jsmith", COMPROMISE_IP))

    rows.sort(key=lambda r: r[0])
    return rows


def write_linux(path: Path, rows, host="web01") -> None:
    with path.open("w") as f:
        for i, (ts, kind, user, ip) in enumerate(rows):
            stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"   # syslog pads the day with a space
            pid = 1000 + i % 30000
            if kind == "fail":
                invalid = "invalid user " if user not in USERS else ""
                if invalid:
                    f.write(f"{stamp} {host} sshd[{pid}]: Invalid user {user} from {ip} port {40000 + i % 20000}\n")
                f.write(f"{stamp} {host} sshd[{pid}]: Failed password for {invalid}{user} from {ip} port {40000 + i % 20000} ssh2\n")
            else:
                f.write(f"{stamp} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {40000 + i % 20000} ssh2\n")
                f.write(f"{stamp} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}\n")


def write_windows(path: Path, rows, host="DC01.corp.local") -> None:
    records = [{
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0-06:00",
        "EventID": 4625 if kind == "fail" else 4624,
        "Computer": host,
        "TargetUserName": user,
        "IpAddress": ip,
        "LogonType": "3",
    } for ts, kind, user, ip in rows]
    path.write_text(json.dumps(records, indent=1))


def write_web(path: Path, rows) -> None:
    with path.open("w") as f:
        for ts, kind, user, ip in rows:
            stamp = ts.strftime("%d/%b/%Y:%H:%M:%S -0600")
            status = 401 if kind == "fail" else 302
            f.write(f'{ip} - {user} [{stamp}] "POST /login HTTP/1.1" {status} 512 "-" "Mozilla/5.0"\n')
            # normal page traffic that the analyzer should ignore
            f.write(f'{ip} - - [{stamp}] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sample_logs")
    ap.add_argument("--events", type=int, default=2000, help="normal events per log type")
    ap.add_argument("--only", choices=["linux", "windows", "web"])
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 11, 16, 0, 0, 0)
    writers = {"linux": ("auth.log", write_linux),
               "windows": ("windows_security.json", write_windows),
               "web": ("access.log", write_web)}
    for i, (name, (fname, writer)) in enumerate(writers.items()):
        if args.only and name != args.only:
            continue
        rows = _timeline(args.events, start, random.Random(args.seed + i), offset_h=i)
        writer(out / fname, rows)
        print(f"wrote {out / fname} ({len(rows):,} auth events)")


if __name__ == "__main__":
    main()
