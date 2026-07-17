from datetime import datetime, timedelta

from log_sentinel.detector import (
    Severity,
    Thresholds,
    detect_brute_force,
    detect_success_after_failures,
    detect_user_enumeration,
    run_all_detections,
)
from log_sentinel.parser import AuthEvent, EventType

BASE = datetime(2026, 3, 14, 7, 40, 0)


def make_event(
    event_type: EventType,
    ip: str = "203.0.113.45",
    user: str = "root",
    offset_seconds: int = 0,
) -> AuthEvent:
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        host="web01",
        event_type=event_type,
        user=user,
        ip=ip,
        port=55000,
        raw="<test>",
    )


class TestBruteForce:
    def test_burst_of_failures_is_flagged(self):
        events = [
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 10)
            for i in range(6)
        ]
        findings = detect_brute_force(events, Thresholds())
        assert len(findings) == 1
        assert findings[0].rule == "brute_force"
        assert findings[0].ip == "203.0.113.45"

    def test_failures_spread_over_hours_not_flagged(self):
        events = [
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 3600)
            for i in range(6)
        ]
        assert detect_brute_force(events, Thresholds()) == []

    def test_below_threshold_not_flagged(self):
        events = [
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 10)
            for i in range(4)
        ]
        assert detect_brute_force(events, Thresholds()) == []

    def test_large_attack_is_critical(self):
        events = [
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 5)
            for i in range(25)
        ]
        findings = detect_brute_force(events, Thresholds())
        assert findings[0].severity == Severity.CRITICAL


class TestUserEnumeration:
    def test_many_distinct_users_flagged(self):
        events = [
            make_event(EventType.INVALID_USER, user=name, offset_seconds=i)
            for i, name in enumerate(["admin", "oracle", "postgres"])
        ]
        findings = detect_user_enumeration(events, Thresholds())
        assert len(findings) == 1
        assert findings[0].users == ["admin", "oracle", "postgres"]

    def test_same_user_repeated_not_enumeration(self):
        events = [
            make_event(EventType.FAILED_LOGIN, user="root", offset_seconds=i)
            for i in range(10)
        ]
        assert detect_user_enumeration(events, Thresholds()) == []


class TestSuccessAfterFailures:
    def test_success_after_failures_is_critical(self):
        events = [
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 10)
            for i in range(5)
        ]
        events.append(make_event(EventType.ACCEPTED_LOGIN, offset_seconds=100))
        findings = detect_success_after_failures(events, Thresholds())
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_clean_success_not_flagged(self):
        events = [make_event(EventType.ACCEPTED_LOGIN, ip="192.0.2.10")]
        assert detect_success_after_failures(events, Thresholds()) == []

    def test_success_from_different_ip_not_flagged(self):
        events = [
            make_event(EventType.FAILED_LOGIN, ip="203.0.113.45", offset_seconds=i)
            for i in range(5)
        ]
        events.append(
            make_event(EventType.ACCEPTED_LOGIN, ip="192.0.2.10", offset_seconds=99)
        )
        assert detect_success_after_failures(events, Thresholds()) == []


def test_run_all_sorts_by_severity():
    events = [
        # enumeration only (medium) from one IP
        *[
            make_event(
                EventType.INVALID_USER,
                ip="198.51.100.23",
                user=name,
                offset_seconds=i,
            )
            for i, name in enumerate(["a", "b", "c"])
        ],
        # brute force + compromise (critical) from another
        *[
            make_event(EventType.FAILED_LOGIN, offset_seconds=i * 10)
            for i in range(6)
        ],
        make_event(EventType.ACCEPTED_LOGIN, offset_seconds=100),
    ]
    findings = run_all_detections(events)
    severities = [f.severity for f in findings]
    assert severities == sorted(
        severities,
        key=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW].index,
    )
    assert findings[0].severity == Severity.CRITICAL
