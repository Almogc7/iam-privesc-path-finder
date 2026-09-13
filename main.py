"""CLI entry point: python main.py --input samples/ [--html report.html]"""

from __future__ import annotations

import argparse
import sys

from detectors import DETECTORS
from parser import load_principals
from report import render_cli_table, render_html_report


def main() -> int:
    arg_parser = argparse.ArgumentParser(
        description="Detects known AWS IAM privilege-escalation paths in a set "
        "of offline, synthetic IAM policy JSON files."
    )
    arg_parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON file or a directory of JSON files (see samples/).",
    )
    arg_parser.add_argument(
        "--html",
        default=None,
        help="Optional path to also write a static HTML report (e.g. report.html).",
    )
    args = arg_parser.parse_args()

    try:
        principals = load_principals(args.input)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error loading input: {e}", file=sys.stderr)
        return 1

    if not principals:
        print(f"No principals found in {args.input}", file=sys.stderr)
        return 1

    findings = []
    for detector in DETECTORS:
        findings.extend(detector.detect(principals))

    render_cli_table(findings)

    if args.html:
        render_html_report(findings, args.html)
        print(f"HTML report written to {args.html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
