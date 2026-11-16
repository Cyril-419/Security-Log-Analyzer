from datetime import datetime, timedelta

from loganalyzer.detectors import Thresholds, run_detections
from loganalyzer.models import LOGIN_FAILURE, LOGIN_SUCCESS, Event

T0 = datetime(2026, 11, 16, 9, 0, 0)


def fail(sec, user="root", ip="203.0.113.5"):
    return Event(T0 + timedelta(seconds=sec), "linux", LOGIN_FAILURE, ip, user)


def ok(sec, user="root", ip="203.0.113.5"):
    return Event(T0 + timedelta(seconds=sec), "linux", LOGIN_SUCCESS, ip, user)


def rules(alerts):
    return [a.rule for a in alerts]


def test_brute_force_fires_at_threshold():
    events = [fail(i) for i in range(10)]
    alerts = list(run_detections(events))
    assert rules(alerts) == ["brute_force"]
    assert alerts[0].event_count == 10
    assert alerts[0].src_ip == "203.0.113.5"


def test_brute_force_below_threshold_is_quiet():
    assert list(run_detections([fail(i) for i in range(9)])) == []


def test_brute_force_alerts_once_per_burst():
    alerts = list(run_detections([fail(i) for i in range(50)]))
    assert rules(alerts) == ["brute_force"]


def test_failures_spread_beyond_window_do_not_alert():
    # 10 failures, one every 40 seconds = 6 minutes, so never 10 inside 5 minutes
    events = [fail(i * 40) for i in range(10)]
    assert list(run_detections(events)) == []


def test_new_burst_after_quiet_period_alerts_again():
    first = [fail(i) for i in range(10)]
    second = [fail(3600 + i) for i in range(10)]   # an hour later
    assert rules(run_detections(first + second)) == ["brute_force", "brute_force"]


def test_password_spray_and_no_duplicate_brute_force():
    users = ["admin", "root", "test", "guest", "oracle", "ubuntu", "user", "dev", "a", "b"]
    events = [fail(i * 10, user=u) for i, u in enumerate(users)]
    alerts = list(run_detections(events))
    assert rules(alerts) == ["password_spray"]
    assert alerts[0].severity == "high"
    assert len(alerts[0].users) == 5


def test_same_user_many_times_is_not_spray():
    alerts = list(run_detections([fail(i, user="root") for i in range(20)]))
    assert "password_spray" not in rules(alerts)


def test_different_ips_are_tracked_separately():
    events = [fail(i, ip=f"10.0.0.{i}") for i in range(30)]
    assert list(run_detections(events)) == []


def test_success_after_failures():
    events = [fail(i, user="jsmith") for i in range(6)] + [ok(10, user="jsmith")]
    alerts = list(run_detections(events))
    assert rules(alerts) == ["success_after_failures"]
    assert alerts[0].users == ["jsmith"]


def test_normal_typo_then_success_is_fine():
    events = [fail(0, user="cyril", ip="10.0.0.4"), ok(5, user="cyril", ip="10.0.0.4")]
    assert list(run_detections(events)) == []


def test_events_without_ip_are_ignored():
    events = [Event(T0 + timedelta(seconds=i), "windows", LOGIN_FAILURE, None, "bob") for i in range(20)]
    assert list(run_detections(events)) == []


def test_custom_thresholds():
    t = Thresholds(window_minutes=1, brute_force_failures=3)
    assert rules(run_detections([fail(0), fail(1), fail(2)], t)) == ["brute_force"]
