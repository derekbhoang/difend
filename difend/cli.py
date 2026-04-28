from __future__ import annotations

import argparse
from pathlib import Path

from difend.models import STATUS_FAIL, STATUS_MANUAL_REVIEW
from difend.scanner import scan_repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="difend")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("scan", help="Scan the current Git diff.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan()
    parser.error(f"Unknown command: {args.command}")
    return 1


def _run_scan() -> int:
    print("Difend scan started\n")

    def progress(label: str, status: str) -> None:
        print(f"{label}... {status}")

    try:
        result = scan_repository(Path.cwd(), progress=progress)
    except RuntimeError as error:
        print(f"\nDifend scan failed: {error}")
        return 1

    print("")
    print(f"Status: {result.status}")
    print(f"Report written to: {result.output_path}")
    print(f"Next: ask Codex to read {result.output_path / 'codex-instructions.md'}")

    if result.status == STATUS_FAIL:
        return 1
    if result.status == STATUS_MANUAL_REVIEW:
        return 2
    return 0
