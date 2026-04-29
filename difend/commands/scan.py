"""Implementation of the difend scan command."""

from __future__ import annotations

import argparse

from difend.agents import AgenticScanError
from difend.sdk import ScanStatus, scan


def run_scan(args: argparse.Namespace) -> int:
    try:
        report = scan()
    except AgenticScanError as exc:
        print("Difend scan failed before producing a trusted security status.")
        print(f"Error: {exc}")
        return 2

    print("Difend scan started")
    print(report.name)
    for agent in report.agents:
        suffix = f" - {agent.detail}" if agent.detail else ""
        print(f"{agent.name}: {agent.status.value}{suffix}")
    print(f"Status: {report.status.value}")
    print(f"Risk score: {report.risk_score}")
    print(f"Unstaged diff: {_format_diff_state(report.diff.unstaged)}")
    print(f"Staged diff: {_format_diff_state(report.diff.staged)}")
    print(f"Untracked diff: {_format_diff_state(report.diff.untracked)}")
    print(f"Report written to: {report.output_folder}")
    print(f"Next: ask Codex to read {report.output_folder / 'codex-instructions.md'}")
    if report.status == ScanStatus.FAIL:
        return 1
    return 0


def _format_diff_state(diff: str) -> str:
    if diff.strip():
        return "captured"

    return "none"
