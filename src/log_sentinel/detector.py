"""Detection rules over parsed authentication events.

Three classic SSH attack patterns:

- Brute force: many failed logins from one IP inside a time window.
- User enumeration: one IP probing many distinct usernames.
- Possible compromise: a successful login from an IP that had
  previously accumulated failed attempts (credential stuffing that
  eventually worked).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum

from .parser import AuthEvent, EventType


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A detected suspicious pattern."""

    rule: str
    severity: Severity
    ip: str
    summary: str
    count: int
    users: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "ip": self.ip,
            "summary": self.summary,
            "count": self.count,
            "users": self.users,
        }


@dataclass
class Thresholds:
    """Tunable detection thresholds."""

    brute_force_attempts: int = 5
    brute_force_window_minutes: int = 10
    enumeration_distinct_users: int = 3
    compromise_prior_failures: int = 3


def detect_brute_force(
    events: list[AuthEvent], thresholds: Thresholds
) -> list[Finding]:
    """Sliding-window count of failed logins per source IP."""
    window = timedelta(minutes=thresholds.brute_force_window_minutes)
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)

    for event in events:
        if event.event_type == EventType.FAILED_LOGIN:
            failures_by_ip[event.ip].append(event)

    findings = []
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e.timestamp)
        start = 0
        best = 0
        for end in range(len(failures)):
            while failures[end].timestamp - failures[start].timestamp > window:
                start += 1
            best = max(best, end - start + 1)

        if best >= thresholds.brute_force_attempts:
            total = len(failures)
            severity = Severity.CRITICAL if best >= 20 else Severity.HIGH
            findings.append(
                Finding(
                    rule="brute_force",
                    severity=severity,
                    ip=ip,
                    summary=(
                        f"{best} failed logins within "
                        f"{thresholds.brute_force_window_minutes} min "
                        f"({total} total) from {ip}"
                    ),
                    count=total,
                    users=sorted({e.user for e in failures}),
                )
            )
    return findings


def detect_user_enumeration(
    events: list[AuthEvent], thresholds: Thresholds
) -> list[Finding]:
    """One IP probing several distinct (often invalid) usernames."""
    users_by_ip: dict[str, set[str]] = defaultdict(set)

    for event in events:
        if event.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER):
            users_by_ip[event.ip].add(event.user)

    findings = []
    for ip, users in users_by_ip.items():
        if len(users) >= thresholds.enumeration_distinct_users:
            findings.append(
                Finding(
                    rule="user_enumeration",
                    severity=Severity.MEDIUM,
                    ip=ip,
                    summary=(
                        f"{ip} probed {len(users)} distinct usernames: "
                        + ", ".join(sorted(users)[:5])
                        + ("..." if len(users) > 5 else "")
                    ),
                    count=len(users),
                    users=sorted(users),
                )
            )
    return findings


def detect_success_after_failures(
    events: list[AuthEvent], thresholds: Thresholds
) -> list[Finding]:
    """Successful login from an IP with prior failed attempts."""
    failures_so_far: dict[str, int] = defaultdict(int)
    findings = []

    for event in sorted(events, key=lambda e: e.timestamp):
        if event.event_type == EventType.FAILED_LOGIN:
            failures_so_far[event.ip] += 1
        elif event.event_type == EventType.ACCEPTED_LOGIN:
            prior = failures_so_far[event.ip]
            if prior >= thresholds.compromise_prior_failures:
                findings.append(
                    Finding(
                        rule="success_after_failures",
                        severity=Severity.CRITICAL,
                        ip=event.ip,
                        summary=(
                            f"Successful login as '{event.user}' from "
                            f"{event.ip} after {prior} failed attempts "
                            "- possible compromise"
                        ),
                        count=prior,
                        users=[event.user],
                    )
                )
    return findings


def run_all_detections(
    events: list[AuthEvent], thresholds: Thresholds | None = None
) -> list[Finding]:
    """Run every rule and return findings sorted by severity."""
    thresholds = thresholds or Thresholds()
    findings = [
        *detect_success_after_failures(events, thresholds),
        *detect_brute_force(events, thresholds),
        *detect_user_enumeration(events, thresholds),
    ]
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    findings.sort(key=lambda f: order.index(f.severity))
    return findings
