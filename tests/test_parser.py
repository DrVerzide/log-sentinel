from log_sentinel.parser import EventType, parse_line

FAILED_LINE = (
    "Mar 14 07:40:01 web01 sshd[2201]: "
    "Failed password for root from 203.0.113.45 port 55010 ssh2"
)
FAILED_INVALID_LINE = (
    "Mar 14 06:15:34 web01 sshd[1902]: "
    "Failed password for invalid user admin from 198.51.100.23 port 41022 ssh2"
)
ACCEPTED_LINE = (
    "Mar 14 06:02:11 web01 sshd[1841]: "
    "Accepted publickey for deploy from 192.0.2.10 port 50122 ssh2"
)
INVALID_LINE = (
    "Mar 14 06:15:33 web01 sshd[1902]: "
    "Invalid user admin from 198.51.100.23 port 41022"
)
IRRELEVANT_LINE = (
    "Mar 14 09:12:30 web01 sshd[2601]: "
    "pam_unix(sshd:session): session opened for user deploy(uid=1001)"
)


def test_failed_login_parsed():
    event = parse_line(FAILED_LINE, year=2026)
    assert event is not None
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.user == "root"
    assert event.ip == "203.0.113.45"
    assert event.port == 55010
    assert event.host == "web01"
    assert (event.timestamp.month, event.timestamp.day) == (3, 14)


def test_failed_invalid_user_is_failed_login_not_invalid_user():
    event = parse_line(FAILED_INVALID_LINE, year=2026)
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.user == "admin"


def test_accepted_login_parsed():
    event = parse_line(ACCEPTED_LINE, year=2026)
    assert event.event_type == EventType.ACCEPTED_LOGIN
    assert event.user == "deploy"
    assert event.ip == "192.0.2.10"


def test_invalid_user_parsed():
    event = parse_line(INVALID_LINE, year=2026)
    assert event.event_type == EventType.INVALID_USER
    assert event.user == "admin"


def test_irrelevant_line_returns_none():
    assert parse_line(IRRELEVANT_LINE, year=2026) is None


def test_garbage_line_returns_none():
    assert parse_line("not a log line at all", year=2026) is None
    assert parse_line("", year=2026) is None
