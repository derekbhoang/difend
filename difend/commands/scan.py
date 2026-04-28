"""Implementation of the difend scan command."""

from __future__ import annotations

import argparse

from difend.sdk import scan


def run_scan(args: argparse.Namespace) -> int:
    report = scan()
    print(report.name)
    print(f"Unstaged diff: {_format_diff_state(report.diff.unstaged)}")
    print(f"Staged diff: {_format_diff_state(report.diff.staged)}")
    return 0


def _format_diff_state(diff: str) -> str:
    if diff.strip():
        return "captured"

    return "none"
