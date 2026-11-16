import json
from datetime import datetime

from loganalyzer.models import LOGIN_FAILURE, LOGIN_SUCCESS
from loganalyzer.parsers import detect_format, parse_file, parse_linux, parse_web, parse_windows


# ---------------------------------------------------------------- Linux
def test_linux_failed_password_invalid_user():
    line = "Nov 16 09:12:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52314 ssh2"
    [ev] = list(parse_linux([line], year=2026))
    assert ev.event_type == LOGIN_FAILURE
    assert ev.user == "admin"
    assert ev.src_ip == "203.0.113.5"
    assert ev.host == "web01"
    assert ev.timestamp == datetime(2026, 11, 16, 9, 12, 1)


def test_linux_accepted_login():
    line = "Nov 16 09:12:09 web01 sshd[1240]: Accepted publickey for cyril from 10.0.0.12 port 50022 ssh2"
    [ev] = list(parse_linux([line], year=2026))
    assert ev.event_type == LOGIN_SUCCESS
    assert ev.user == "cyril"


def test_linux_single_digit_day_is_space_padded():
    line = "Nov  6 01:02:03 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    [ev] = list(parse_linux([line], year=2026))
    assert ev.timestamp == datetime(2026, 11, 6, 1, 2, 3)


def test_linux_ignores_noise_and_avoids_double_count():
    lines = [
        "Nov 16 09:12:01 web01 sshd[1]: Invalid user admin from 203.0.113.5 port 1",
        "Nov 16 09:12:01 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 1 ssh2",
        "Nov 16 09:12:02 web01 sshd[2]: pam_unix(sshd:session): session opened for user bob",
        "Nov 16 09:12:03 web01 CRON[99]: (root) CMD (run-parts /etc/cron.hourly)",
        "garbage line",
    ]
    events = list(parse_linux(lines, year=2026))
    assert len(events) == 1


def test_linux_ipv6_source():
    line = "Nov 16 09:12:01 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    [ev] = list(parse_linux([line], year=2026))
    assert ev.src_ip == "2001:db8::1"


# -------------------------------------------------------------- Windows
def _win(event_id, user="bob", ip="198.51.100.9", logon_type="3"):
    return {"TimeCreated": "2026-11-16T09:12:01.1234567-06:00", "EventID": event_id,
            "TargetUserName": user, "IpAddress": ip, "LogonType": logon_type,
            "Computer": "DC01"}


def test_windows_json_array():
    text = json.dumps([_win(4625), _win(4624)])
    evs = list(parse_windows(text))
    assert [e.event_type for e in evs] == [LOGIN_FAILURE, LOGIN_SUCCESS]
    assert evs[0].timestamp == datetime(2026, 11, 16, 9, 12, 1, 123456)
    assert evs[0].host == "DC01"


def test_windows_json_lines_and_filtering():
    lines = "\n".join(json.dumps(r) for r in [
        _win(4625),
        _win(4634),                    # logoff - not an auth event we use
        _win(4624, logon_type="5"),    # service logon - noise
        _win(4625, ip="-"),            # local failure, no network source
    ])
    evs = list(parse_windows(lines))
    assert len(evs) == 2
    assert evs[1].src_ip is None


# ------------------------------------------------------------------ Web
def test_web_401_is_failure_and_200_page_is_ignored():
    lines = [
        '198.51.100.7 - admin [16/Nov/2026:09:12:01 -0600] "POST /login HTTP/1.1" 401 512 "-" "curl/8.0"',
        '198.51.100.7 - - [16/Nov/2026:09:12:02 -0600] "GET /index.html HTTP/1.1" 200 2048 "-" "x"',
    ]
    [ev] = list(parse_web(lines))
    assert ev.event_type == LOGIN_FAILURE
    assert ev.user == "admin"
    assert ev.timestamp == datetime(2026, 11, 16, 9, 12, 1)


def test_web_login_success_and_403_on_login_page():
    lines = [
        '10.0.0.5 - - [16/Nov/2026:09:00:00 -0600] "POST /wp-login.php HTTP/1.1" 403 0 "-" "x"',
        '10.0.0.5 - bob [16/Nov/2026:09:00:05 -0600] "POST /login HTTP/1.1" 302 0 "-" "x"',
        '10.0.0.5 - - [16/Nov/2026:09:00:06 -0600] "GET /private HTTP/1.1" 403 0 "-" "x"',
    ]
    evs = list(parse_web(lines))
    assert [e.event_type for e in evs] == [LOGIN_FAILURE, LOGIN_SUCCESS]
    assert evs[0].user is None


# ---------------------------------------------------------- auto-detect
def test_detect_format(tmp_path):
    (tmp_path / "a.log").write_text("Nov 16 09:12:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
    (tmp_path / "b.log").write_text('1.2.3.4 - - [16/Nov/2026:09:12:01 -0600] "GET / HTTP/1.1" 200 1 "-" "x"\n')
    (tmp_path / "c.json").write_text(json.dumps([_win(4625)]))
    assert detect_format(tmp_path / "a.log") == "linux"
    assert detect_format(tmp_path / "b.log") == "web"
    assert detect_format(tmp_path / "c.json") == "windows"
    assert len(list(parse_file(tmp_path / "c.json"))) == 1
