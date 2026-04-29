"""Command line interface for Difend."""

from __future__ import annotations

import argparse

from difend.commands.scan import run_scan
from difend.diff import DEFAULT_CONTEXT_LINES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="difend",
        description="Diff-aware security review tooling.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan the current Git diff.",
    )
    scan_parser.add_argument(
        "--repo",
        default=".",
        help="Git repository to scan. Defaults to the current directory.",
    )
    scan_parser.add_argument(
        "--output-root",
        default=".difend/runs",
        help="Folder for scan runs, relative to the repository.",
    )
    scan_parser.add_argument(
        "--context",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="Number of Git diff context lines to capture.",
    )
    scope = scan_parser.add_mutually_exclusive_group()
    scope.add_argument("--staged-only", action="store_true", help="Scan only staged changes.")
    scope.add_argument("--unstaged-only", action="store_true", help="Scan only unstaged changes.")
    scan_parser.set_defaults(handler=run_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
