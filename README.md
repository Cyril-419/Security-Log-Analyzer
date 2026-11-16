# Security Log Analyzer

[![CI](https://github.com/Cyril-419/Security-Log-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Cyril-419/Security-Log-Analyzer/actions/workflows/ci.yml)

A Python command-line tool that parses authentication logs from **Linux, Windows and web servers**, normalizes them into one event format, stores them in **SQLite**, and runs **rule-based detections** for brute-force attacks, password spraying, and logins that succeed after repeated failures.

Pure Python standard library, no dependencies to run it (pytest for the tests).

```
$ python -m loganalyzer analyze sample_logs/*

Processed 6,177 events from 3 file(s) in 0.13s -> 9 alert(s). DB: results.db

ALERTS
  [HIGH  ] 2026-11-16 09:00:00  password_spray           198.51.100.23 tried 5 different accounts within 5 min
  [HIGH  ] 2026-11-16 15:00:00  success_after_failures   Successful login as 'jsmith' from 192.0.2.77 after 8 failures - possible compromised account
  [MEDIUM] 2026-11-16 03:00:00  brute_force              10 failed logins from 203.0.113.45 within 5 min
  ...
TOP SOURCES OF FAILED LOGINS
  203.0.113.45                                  120
  198.51.100.23                                  30
```

## Measured performance

`python scripts/benchmark.py --events 1000000`

| Metric | Result |
|---|---|
| Events processed | 1,000,059 (178 MB sshd log) |
| Wall time | ~26 s, single process |
| Throughput | ~39,000 events/sec |
| Detection accuracy on planted attacks | 3 of 3 found, 0 false positives |

Memory stays flat because files are streamed line by line, not loaded whole. Numbers will vary by machine, so run the benchmark yourself.

## How it works

```
 auth.log ─┐                                  ┌─> SQLite (events, alerts)
 security.json ─┼─> parsers ─> Event stream ─┤
 access.log ─┘   (normalize)  (time-ordered)  └─> detectors ─> alerts
```

1. **Parse and normalize** (`parsers.py`). Each format has its own parser, but they all output the same `Event` (timestamp, source, type, IP, user). Detection rules never care where a log came from, which is the same idea a SIEM uses.
2. **Merge.** Each file is already in time order, so `heapq.merge` combines them into one time-ordered stream without loading everything into memory. Because rules key on source IP, an attacker hitting SSH and the web login is tracked as one actor.
3. **Store** (`storage.py`). Events go into SQLite in batches of 10,000 inside a single transaction (far faster than committing each row). Indexes on IP and timestamp keep queries fast.
4. **Detect** (`detectors.py`). Each IP gets a sliding 5-minute window (a `deque`). New events go on the right, old ones fall off the left, so each event costs O(1) work.

### Detection rules

| Rule | Logic (defaults) | Severity | MITRE ATT&CK |
|---|---|---|---|
| `brute_force` | 10+ failed logins from one IP in 5 min | Medium | T1110.001 Password Guessing |
| `password_spray` | Failures against 5+ different usernames from one IP in 5 min | High | T1110.003 Password Spraying |
| `success_after_failures` | A successful login from an IP with 5+ recent failures | High | T1110 / T1078 Valid Accounts |

Design choices worth knowing:
- **One alert per burst.** An IP alerts once, then not again until it goes quiet for a full window, so a 1,000-guess attack is one alert, not 100.
- **Spray beats brute force.** A spray burst also has lots of failures, so spray (the more specific finding) suppresses the brute-force alert for the same burst.
- **Thresholds are tunable** from the command line (`--window`, `--bf-threshold`, `--spray-threshold`, `--saf-threshold`), since a busy VPN gateway and a small server need different numbers.

## Supported log formats

**Linux** (`/var/log/auth.log`, `/var/log/secure`): OpenSSH `Failed password`, `Failed publickey` and `Accepted` lines. The duplicate `Invalid user` line is skipped so failures aren't counted twice. Syslog has no year, so pass `--year` for old logs.

**Windows** Security log, Event IDs **4625** (failed logon) and **4624** (success). Service and batch logons (types 4, 5) are filtered as noise. Export from PowerShell (run as Administrator):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 50000 |
  Sort-Object TimeCreated |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated.ToString('o'); EventID = $_.Id; Computer = $_.MachineName
      TargetUserName = $d.TargetUserName; IpAddress = $d.IpAddress; LogonType = $d.LogonType
    }
  } | ConvertTo-Json | Out-File security.json -Encoding utf8
```

**Web** (Apache/Nginx combined format): a `401` anywhere, or a `403` on a login URL (`/login`, `/wp-login.php`, `/admin`...), is a failed login. A `POST` to a login URL returning 200/302 is a success. Normal page traffic is ignored.

The format is auto-detected; override with `--format linux|windows|web`.

## Usage

```bash
# analyze any mix of files (results.db is replaced each run; --append to keep old data)
python -m loganalyzer analyze /var/log/auth.log security.json access.log --db results.db

# show the report again later
python -m loganalyzer report --db results.db

# exit code 1 if anything fires (useful in a cron job or CI pipeline)
python -m loganalyzer analyze auth.log --fail-on-alert

# machine-readable results (for scripts, SIEMs, other tools)
python -m loganalyzer analyze auth.log --json

# query the database directly
sqlite3 results.db "SELECT src_ip, COUNT(*) FROM events WHERE event_type='login_failure' GROUP BY src_ip ORDER BY 2 DESC LIMIT 10;"
```

## REST API

Run the analyzer as a small web service so other tools can send it logs over HTTP. It uses only Python's built-in `http.server`, so there's still nothing to install.

```bash
python -m loganalyzer serve            # http://127.0.0.1:8080
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness check: `{"status": "ok", "version": "1.1.0"}` |
| `POST` | `/analyze` | Send logs as JSON, get alerts back |

```bash
curl -s -X POST localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
        "format": "linux",
        "logs": "Nov 16 09:00:01 web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n...",
        "thresholds": {"brute_force_failures": 10, "window_minutes": 5}
      }'
```

Request fields: `logs` (required, the raw log text), `format` (`auto`, `linux`, `windows`, `web`; default `auto`), `year` (for Linux syslog), and `thresholds` (any of `window_minutes`, `brute_force_failures`, `spray_distinct_users`, `success_after_failures`).

Response (same shape as `analyze --json`):

```json
{
  "format": "linux",
  "summary": {"events": 2059, "login_failures": 199, "login_successes": 1860, "alerts": 3, "elapsed_ms": 1.4},
  "thresholds": {"window_minutes": 5, "brute_force_failures": 10, "spray_distinct_users": 5, "success_after_failures": 5},
  "alerts": [
    {"rule": "brute_force", "severity": "medium", "src_ip": "203.0.113.45",
     "first_seen": "2026-11-16T03:00:00", "last_seen": "2026-11-16T03:00:27",
     "event_count": 10, "users": ["root"], "description": "10 failed logins from 203.0.113.45 within 5 min"}
  ],
  "top_failing_ips": [{"src_ip": "203.0.113.45", "failures": 40}]
}
```

**Hardening built in:**
- Binds to `127.0.0.1` by default; exposing it on another address prints a warning, since there's no authentication
- Request bodies over 10 MB are rejected (`413`) before they're read
- Strict input validation: wrong types, unknown thresholds and out-of-range values return `400` with a clear message
- Correct status codes for bad JSON (`400`), wrong content type (`415`), unknown routes (`404`) and wrong methods (`405`)
- Unexpected errors return a generic `500` and never leak a stack trace
- Stateless: nothing from a request is stored on the server

## Tests and CI

```bash
pip install pytest
python -m pytest -v
```

48 tests cover each parser (including edge cases like space-padded syslog days, IPv6, and noise lines), each detection rule (thresholds, window expiry, one-alert-per-burst, IP separation), SQLite storage, the CLI end to end, JSON output, and every REST API route and error case (using a real server on a random port).

**GitHub Actions** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every push and pull request:
1. **Tests** on Python 3.10, 3.11, 3.12 and 3.13 in parallel
2. **Smoke test**: runs the CLI on the sample logs and checks all 9 planted attacks are found, then starts the API and calls `/health` and `/analyze` with curl
3. **Benchmark**: 100,000 events, failing the build if any planted attack is missed or a false positive appears

The workflow uses read-only permissions and cancels older runs when a newer commit is pushed.

## Sample data

`sample_logs/` was made by `scripts/generate_logs.py`: about 2,000 normal logins per source (with realistic typos) plus three planted attacks in each. Regenerate or scale it with `python scripts/generate_logs.py --events 50000`.

## Project layout

```
loganalyzer/
  models.py      Event and Alert data classes
  parsers.py     Linux / Windows / web parsers and format auto-detection
  detectors.py   sliding-window detection rules
  storage.py     SQLite schema and batched inserts
  api.py         JSON results and the REST API server
  cli.py         command-line interface (analyze, report, serve)
scripts/
  generate_logs.py   synthetic logs with planted attacks
  benchmark.py       1M-event throughput and accuracy test
tests/               pytest suite
.github/workflows/   CI pipeline
sample_logs/         ready-to-run examples
```

## Ideas for next versions

- Read `.evtx` files directly (`python-evtx`) instead of a PowerShell export
- GeoIP lookup on source IPs and "impossible travel" detection
- Allowlist for known scanners and internal hosts
- Send alerts to Slack or a webhook
- API key authentication and rate limiting for the REST API
- Export detections as Sigma rules
