import json
from datetime import datetime

from log_sentinel.detector import Finding, Severity
from log_sentinel.parser import AuthEvent, EventType
from log_sentinel.report import render_console, render_json, summarize_events


def _events():
    base = datetime(2026, 3, 14, 7, 0, 0)
    return [
        AuthEvent(base, "web01", EventType.FAILED_LOGIN, "root", "203.0.113.45", 1, "x"),
        AuthEvent(base, "web01", EventType.FAILED_LOGIN, "root", "203.0.113.45", 2, "x"),
        AuthEvent(base, "web01", EventType.ACCEPTED_LOGIN, "deploy", "192.0.2.10", 3, "x"),
    ]


def _finding():
    return Finding(
        rule="brute_force",
        severity=Severity.HIGH,
        ip="203.0.113.45",
        summary="2 failed logins",
        count=2,
        users=["root"],
    )


def test_summarize_events():
    stats = summarize_events(_events())
    assert stats["total_events"] == 3
    assert stats["failed_logins"] == 2
    assert stats["accepted_logins"] == 1
    assert stats["unique_source_ips"] == 2
    assert stats["top_attacker_ips"][0] == ("203.0.113.45", 2)


def test_console_report_mentions_findings():
    output = render_console(_events(), [_finding()])
    assert "brute_force" in output
    assert "[HIGH]" in output
    assert "Findings: 1" in output


def test_console_report_clean_log():
    output = render_console(_events(), [])
    assert "No suspicious activity detected." in output


def test_json_report_is_valid_and_complete():
    payload = json.loads(render_json(_events(), [_finding()]))
    assert payload["summary"]["failed_logins"] == 2
    assert payload["findings"][0]["rule"] == "brute_force"
    assert payload["findings"][0]["severity"] == "high"
