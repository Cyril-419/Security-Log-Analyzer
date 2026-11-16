import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from loganalyzer import __version__
from loganalyzer.api import MAX_BODY_BYTES, RequestError, analyze_request, make_server
from loganalyzer.cli import main

ROOT = Path(__file__).resolve().parent.parent
AUTH_LOG = (ROOT / "sample_logs" / "auth.log").read_text()

BRUTE = "\n".join(
    f"Nov 16 09:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
    for i in range(12)
)


# ------------------------------------------------------------ analyze_request
def test_analyze_request_finds_planted_attacks():
    result = analyze_request({"logs": AUTH_LOG, "year": 2026})
    assert result["format"] == "linux"
    assert {a["rule"] for a in result["alerts"]} == {"brute_force", "password_spray", "success_after_failures"}
    assert result["summary"]["alerts"] == 3
    assert result["top_failing_ips"][0]["src_ip"] == "203.0.113.45"


def test_custom_thresholds_are_applied():
    result = analyze_request({"logs": BRUTE, "thresholds": {"brute_force_failures": 20}})
    assert result["alerts"] == []
    assert result["thresholds"]["brute_force_failures"] == 20


@pytest.mark.parametrize("body, message", [
    ([], "JSON object"),
    ({}, "'logs' is required"),
    ({"logs": "   "}, "'logs' is required"),
    ({"logs": BRUTE, "format": "syslog"}, "'format' must be one of"),
    ({"logs": BRUTE, "year": "2026"}, "'year'"),
    ({"logs": BRUTE, "thresholds": {"nope": 1}}, "unknown threshold"),
    ({"logs": BRUTE, "thresholds": {"window_minutes": 0}}, "whole number"),
    ({"logs": BRUTE, "thresholds": {"window_minutes": True}}, "whole number"),
    ({"logs": "[{\"EventID\": 4625}]", "format": "windows"}, "could not parse"),
])
def test_invalid_requests_are_rejected(body, message):
    with pytest.raises(RequestError, match=message):
        analyze_request(body)


# ---------------------------------------------------------------- HTTP server
@pytest.fixture(scope="module")
def base_url():
    server = make_server("127.0.0.1", 0, quiet=True)   # port 0 = any free port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def call(url, method="GET", body=None, content_type="application/json", raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read()), resp.headers
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read()), err.headers


def test_health(base_url):
    status, body, headers = call(f"{base_url}/health")
    assert status == 200
    assert body == {"status": "ok", "version": __version__}
    assert headers["Content-Type"] == "application/json"


def test_post_analyze(base_url):
    status, body, _ = call(f"{base_url}/analyze", "POST", {"logs": BRUTE, "format": "linux"})
    assert status == 200
    assert body["alerts"][0]["rule"] == "brute_force"
    assert body["alerts"][0]["src_ip"] == "203.0.113.9"


def test_bad_json_is_400(base_url):
    status, body, _ = call(f"{base_url}/analyze", "POST", raw=b"{not json")
    assert status == 400 and "valid JSON" in body["message"]


def test_validation_error_is_400(base_url):
    status, body, _ = call(f"{base_url}/analyze", "POST", {"logs": ""})
    assert status == 400 and body["error"] == "Bad Request"


def test_wrong_content_type_is_415(base_url):
    status, _, _ = call(f"{base_url}/analyze", "POST", raw=b"logs", content_type="text/plain")
    assert status == 415


def test_oversized_body_is_413(base_url):
    req = urllib.request.Request(f"{base_url}/analyze", data=b"{}", method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", str(MAX_BODY_BYTES + 1))   # server rejects before reading
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=10)
    assert err.value.code == 413


def test_unknown_route_and_wrong_method(base_url):
    assert call(f"{base_url}/nope")[0] == 404
    assert call(f"{base_url}/analyze")[0] == 405
    assert call(f"{base_url}/analyze", "DELETE")[0] == 405


# ---------------------------------------------------------------- CLI --json
def test_cli_json_output_matches_api(tmp_path, capsys):
    log = ROOT / "sample_logs" / "auth.log"
    assert main(["analyze", str(log), "--db", str(tmp_path / "x.db"), "--year", "2026", "--json"]) == 0
    cli = json.loads(capsys.readouterr().out)
    api = analyze_request({"logs": log.read_text(), "format": "linux", "year": 2026})
    assert cli["alerts"] == api["alerts"]
    assert cli["summary"]["events"] == api["summary"]["events"]


def test_report_json(tmp_path, capsys):
    db = str(tmp_path / "x.db")
    main(["analyze", str(ROOT / "sample_logs" / "auth.log"), "--db", db, "--no-color"])
    capsys.readouterr()
    assert main(["report", "--db", db, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["alerts"]) == 3
