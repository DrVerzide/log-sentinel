"""Parse OpenSSH authentication log lines (syslog format) into events.

Handles the three line families relevant for intrusion detection:

    Failed password for [invalid user] <user> from <ip> port <port> ssh2
    Accepted password|publickey for <user> from <ip> port <port> ssh2
    Invalid user <user> from <ip> port <port>
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator

SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class EventType(Enum):
    FAILED_LOGIN = "failed_login"
    ACCEPTED_LOGIN = "accepted_login"
    INVALID_USER = "invalid_user"


@dataclass(frozen=True)
class AuthEvent:
    """A single authentication event extracted from the log."""

    timestamp: datetime
    host: str
    event_type: EventType
    user: str
    ip: str
    port: int | None
    raw: str


def _parse_timestamp(month: str, day: str, time: str, year: int) -> datetime:
    hour, minute, second = (int(part) for part in time.split(":"))
    return datetime(year, MONTHS[month], int(day), hour, minute, second)


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Parse one log line. Returns None for lines we don't care about.

    Syslog timestamps lack a year, so callers may pin one; defaults to
    the current year.
    """
    prefix = SYSLOG_PREFIX.match(line.strip())
    if not prefix:
        return None

    message = prefix.group("message")

    # Order matters: "Failed password for invalid user x" must match
    # FAILED, not INVALID_USER.
    for pattern, event_type in (
        (FAILED, EventType.FAILED_LOGIN),
        (ACCEPTED, EventType.ACCEPTED_LOGIN),
        (INVALID_USER, EventType.INVALID_USER),
    ):
        match = pattern.search(message)
        if match:
            port = match.groupdict().get("port")
            return AuthEvent(
                timestamp=_parse_timestamp(
                    prefix.group("month"),
                    prefix.group("day"),
                    prefix.group("time"),
                    year or datetime.now().year,
                ),
                host=prefix.group("host"),
                event_type=event_type,
                user=match.group("user"),
                ip=match.group("ip"),
                port=int(port) if port else None,
                raw=line.strip(),
            )
    return None


def parse_log(path: str | Path, year: int | None = None) -> Iterator[AuthEvent]:
    """Yield every recognized auth event in a log file."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_line(line, year=year)
            if event:
                yield event
