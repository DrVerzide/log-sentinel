# log-sentinel

A blue-team tool that analyzes **SSH authentication logs** (`auth.log` / syslog format) and detects classic attack patterns, producing both human-readable and JSON reports. Zero runtime dependencies — pure standard library.

## Detection rules

| Rule | What it catches | Severity |
|------|-----------------|----------|
| `brute_force` | N+ failed logins from one IP inside a sliding time window | High / Critical |
| `user_enumeration` | One IP probing several distinct usernames (`admin`, `oracle`, `postgres`…) | Medium |
| `success_after_failures` | A **successful** login from an IP that had accumulated failed attempts — the signature of a brute force that worked | Critical |

All thresholds (attempt count, window size) are configurable from the CLI.

## Installation

```bash
git clone https://github.com/<your-user>/log-sentinel.git
cd log-sentinel
pip install .
```

## Usage

```bash
# Analyze a log file
log-sentinel /var/log/auth.log

# Try it right away with the included sample log
log-sentinel data/sample_auth.log

# Custom thresholds + JSON report for a SIEM/dashboard
log-sentinel data/sample_auth.log --brute-threshold 8 --window 5 --json report.json
```

Example output:

```
==============================================================
 LOG SENTINEL - SSH Authentication Analysis
==============================================================
 Events parsed     : 20
 Failed logins     : 12
 Accepted logins   : 3
 Invalid users     : 4
 Unique source IPs : 3

 Top attacker IPs (by failed logins):
   203.0.113.45       8 failures
   198.51.100.23      4 failures

 Findings: 3
--------------------------------------------------------------
 [CRIT] success_after_failures: Successful login as 'root' from 203.0.113.45 after 8 failed attempts - possible compromise
 [HIGH] brute_force: 8 failed logins within 10 min (8 total) from 203.0.113.45
 [MED ] user_enumeration: 198.51.100.23 probed 4 distinct usernames: admin, oracle, postgres, test
==============================================================
```

The process exits with code `1` when findings exist, so it can gate scripts or CI/monitoring jobs.

## Design notes

- **Parser** (`parser.py`): regex-based syslog parsing into typed `AuthEvent` dataclasses. Unrecognized lines are skipped safely.
- **Detector** (`detector.py`): each rule is an independent pure function over the event list; brute force uses an O(n) sliding window.
- **Report** (`report.py`): rendering is fully separated from detection, making it trivial to add new output formats.

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

## Ethical note

This is a **defensive** tool: it consumes logs you already own to surface attacks *against* your systems. Sample data uses RFC 5737 documentation IPs.

## License

MIT
