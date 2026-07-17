"""Render analysis results for the console or as JSON."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime

from .detector import Finding
from .parser import AuthEvent, EventType

SEVERITY_TAGS = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
}


def summarize_events(events: list[AuthEvent]) -> dict:
    """Aggregate statistics over the parsed events."""
    by_type = Counter(e.event_type for e in events)
    top_attackers = Counter(
        e.ip for e in events if e.event_type == EventType.FAILED_LOGIN
    )
    return {
        "total_events": len(events),
        "failed_logins": by_type[EventType.FAILED_LOGIN],
        "accepted_logins": by_type[EventType.ACCEPTED_LOGIN],
        "invalid_users": by_type[EventType.INVALID_USER],
        "unique_source_ips": len({e.ip for e in events}),
        "top_attacker_ips": top_attackers.most_common(5),
    }


def render_console(events: list[AuthEvent], findings: list[Finding]) -> str:
    """Human-readable report."""
    stats = summarize_events(events)
    lines = [
        "=" * 62,
        " LOG SENTINEL - SSH Authentication Analysis",
        "=" * 62,
        f" Events parsed     : {stats['total_events']}",
        f" Failed logins     : {stats['failed_logins']}",
        f" Accepted logins   : {stats['accepted_logins']}",
        f" Invalid users     : {stats['invalid_users']}",
        f" Unique source IPs : {stats['unique_source_ips']}",
        "",
    ]

    if stats["top_attacker_ips"]:
        lines.append(" Top attacker IPs (by failed logins):")
        for ip, count in stats["top_attacker_ips"]:
            lines.append(f"   {ip:<18} {count} failures")
        lines.append("")

    lines.append(f" Findings: {len(findings)}")
    lines.append("-" * 62)
    if not findings:
        lines.append(" No suspicious activity detected.")
    for finding in findings:
        tag = SEVERITY_TAGS[finding.severity.value]
        lines.append(f" {tag} {finding.rule}: {finding.summary}")
    lines.append("=" * 62)
    return "\n".join(lines)


def render_json(events: list[AuthEvent], findings: list[Finding]) -> str:
    """Machine-readable report (e.g. to feed a SIEM or dashboard)."""
    stats = summarize_events(events)
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            **{k: v for k, v in stats.items() if k != "top_attacker_ips"},
            "top_attacker_ips": [
                {"ip": ip, "failed_logins": count}
                for ip, count in stats["top_attacker_ips"]
            ],
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)
