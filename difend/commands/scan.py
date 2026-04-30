"""Implementation of Difend scan commands."""

from __future__ import annotations

import argparse

from difend.sdk import ScanStatus, agent_scan, scan


def run_scan(args: argparse.Namespace) -> int:
    try:
        report = scan()
    except Exception as exc:
        print("Difend scan failed before producing a trusted security status.")
        print(f"Error: {exc}")
        return 2

    return _print_report(
        command_label="Difend scan",
        report=report,
        strict=False,
        show_agents=False,
    )


def run_agent_scan(args: argparse.Namespace) -> int:
    try:
        report = agent_scan(
            model=getattr(args, "model", None),
            use_cache=not getattr(args, "no_cache", False),
        )
    except Exception as exc:
        print("Difend agent-scan failed before producing a trusted security status.")
        print(f"Error: {exc}")
        return 2

    return _print_report(
        command_label="Difend agent-scan",
        report=report,
        strict=getattr(args, "strict", False),
        show_agents=getattr(args, "agents", False),
    )


def _print_report(
    command_label: str,
    report,
    strict: bool,
    show_agents: bool,
) -> int:
    print(f"{command_label} started")
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
    if show_agents:
        _print_agent_details(report)
    if report.status == ScanStatus.FAIL:
        return 1
    if report.status == ScanStatus.MANUAL_REVIEW_REQUIRED and strict:
        return 1
    return 0


def _format_diff_state(diff: str) -> str:
    if diff.strip():
        return "captured"

    return "none"


def _print_agent_details(report) -> None:
    print("")
    print("Agent execution:")
    for agent in report.agents:
        suffix = f"  {agent.detail}" if agent.detail else ""
        print(
            f"{agent.name}: {agent.status.value}  "
            f"used_llm={str(agent.used_llm).lower()}{suffix}"
        )
    print(f"Cache hit: {str(report.cache_hit).lower()}")
    if report.trace_path:
        print(f"Trace: {report.trace_path}")
