"""Implementation of the difend scan command."""

from __future__ import annotations

import argparse

from difend.sdk import scan


def run_scan(args: argparse.Namespace) -> int:
    include_staged = not args.unstaged_only
    include_unstaged = not args.staged_only
    report = scan(
        repository_path=args.repo,
        output_root=args.output_root,
        include_staged=include_staged,
        include_unstaged=include_unstaged,
        context_lines=args.context,
    )
    summary = report.parsed_diff["summary"]

    print("Difend scan started")
    print()
    print("Checking git diff... done")
    print("Parsing structured diff... done")
    for check in report.gates["checks"]:
        print(f"Checking {check['name']}... {check['status']}")
    print()
    print(f"Status: {report.status.value}")
    print(f"Changed files: {summary['file_count']}")
    print(f"Added lines: {summary['added_lines']}")
    print(f"Removed lines: {summary['removed_lines']}")
    print(f"Findings: {len(report.gates['findings'])}")
    print(f"Manual review items: {len(report.gates['manual_review'])}")
    print(f"Report written to: {report.output_folder}")
    print(f"Next: ask Codex to read {report.output_folder / 'codex-instructions.md'}")
    return 1 if report.status.value == "fail" else 0
