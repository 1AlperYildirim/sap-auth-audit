# SAP Concept: Command-line runner for offline SAP authorization and Basis security audit.
"""CLI entry point for `python -m sapauth`."""

import argparse
from datetime import date
from pathlib import Path
import sys

from sapauth.checks import run_all_checks
from sapauth.loader import load_dir, parse_sap_date
from sapauth.report import generate_reports


def main(argv: list[str] | None = None) -> int:
    """Parses CLI arguments, executes checks, writes output files, and prints ASCII summary."""
    parser = argparse.ArgumentParser(
        prog="sapauth",
        description="Offline SAP Authorization & Basis Security Audit Toolkit",
    )
    parser.add_argument("--data", required=True, type=Path, help="Input directory containing SAP CSV exports")
    parser.add_argument("--out", required=True, type=Path, help="Output directory for report.html, findings.csv, findings.json")
    parser.add_argument("--today", default=None, help="Audit reference date YYYY-MM-DD (default: today)")
    parser.add_argument("--dormant-days", type=int, default=90, help="Dormant dialog user threshold in days (default: 90)")
    args = parser.parse_args(argv)

    today = parse_sap_date(args.today) if args.today else date.today()
    assert today is not None, "Invalid --today date"

    dataset = load_dir(args.data)
    findings = run_all_checks(dataset, today=today, dormant_days=args.dormant_days)
    summary = generate_reports(dataset, findings, args.out, today=today)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())