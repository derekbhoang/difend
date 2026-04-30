"""Implementation of Difend scan commands."""

from __future__ import annotations

import argparse

from difend.observability import AGENT_SCAN_PHASES, SCAN_PHASES, ScanObserver
from difend.sdk import ScanStatus, agent_scan, scan


def run_scan(args: argparse.Namespace) -> int:
    observer = ScanObserver("difend scan", SCAN_PHASES, display=True)
    print("Difend scan started")
    observer.start_run("Difend scan started.")
    try:
        report = scan(observer=observer)
    except Exception as exc:
        observer.fail("execution_error", str(exc))
        print("Difend scan failed before producing a trusted security status.")
        print(f"Error: {exc}")
        return 2

    return _print_report(
        report=report,
        strict=False,
        show_agents=False,
    )


def run_agent_scan(args: argparse.Namespace) -> int:
    use_cache = not getattr(args, "no_cache", False)
    observer = ScanObserver(
        "difend agent-scan",
        AGENT_SCAN_PHASES,
        display=True,
        default_metadata={
            "requested_model": getattr(args, "model", None) or "",
            "use_cache": use_cache,
            "strict": getattr(args, "strict", False),
            "agents_flag": getattr(args, "agents", False),
        },
    )
    print("Difend agent-scan started")
    observer.start_run("Difend agent-scan started.")
    try:
        report = agent_scan(
            model=getattr(args, "model", None),
            use_cache=use_cache,
            observer=observer,
        )
    except Exception as exc:
        observer.fail("execution_error", str(exc))
        print("Difend agent-scan failed before producing a trusted security status.")
        print(f"Error: {exc}")
        return 2

    return _print_report(
        report=report,
        strict=getattr(args, "strict", False),
        show_agents=getattr(args, "agents", False),
    )


def _print_report(
    report,
    strict: bool,
    show_agents: bool,
) -> int:
    print("")
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
    if report.log_path:
        print(f"Log written to: {report.log_path}")
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
    if report.log_path:
        print(f"Log: {report.log_path}")
