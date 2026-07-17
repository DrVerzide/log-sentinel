"""Command-line interface for log-sentinel."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detector import Thresholds, run_all_detections
from .parser import parse_log
from .report import render_console, render_json


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description=(
            "Analyze SSH authentication logs for brute-force attacks, "
            "user enumeration and possible compromises."
        ),
    )
    parser.add_argument("logfile", type=Path, help="path to an auth.log file")
    parser.add_argument(
        "--json",
        type=Path,
        metavar="FILE",
        help="also write a JSON report to FILE",
    )
    parser.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        help="failed attempts within the window to flag brute force (default 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="brute-force sliding window in minutes (default 10)",
    )
    args = parser.parse_args(argv)

    if not args.logfile.is_file():
        parser.error(f"log file not found: {args.logfile}")

    events = list(parse_log(args.logfile))
    thresholds = Thresholds(
        brute_force_attempts=args.brute_threshold,
        brute_force_window_minutes=args.window,
    )
    findings = run_all_detections(events, thresholds)

    print(render_console(events, findings))

    if args.json:
        args.json.write_text(render_json(events, findings), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")

    # Non-zero exit when something was found, so scripts/CI can react.
    return 1 if findings else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
