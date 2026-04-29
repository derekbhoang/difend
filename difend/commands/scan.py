"""Implementation of the difend scan command."""

from __future__ import annotations

import argparse

from difend.sdk import scan


def run_scan(args: argparse.Namespace) -> int:
    print("Difend scan started")
    print()
    report = scan(progress=_print_progress)
    print()
    print(f"Status: {report.status.value}")
    print(f"Report written to: {report.output_folder}")
    print(f"Next: ask Codex to read {report.output_folder / 'codex-instructions.md'}")
    return 0


def _print_progress(label: str, status: str) -> None:
    print(f"{label}... {status}")
