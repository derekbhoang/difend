"""Command line interface for Difend."""

from __future__ import annotations

import argparse

from difend.commands.feedback import run_feedback
from difend.commands.scan import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="difend",
        description="Diff-aware security review tooling.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "agent-scan",
        help="Scan the current Git diff.",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable scan cache lookup and writes for this run.",
    )
    scan_parser.add_argument(
        "--model",
        help="OpenAI model to use for LLM-backed agent nodes.",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a nonzero exit code when manual review is required.",
    )
    scan_parser.add_argument(
        "--agents",
        action="store_true",
        help="Print expanded per-agent execution details.",
    )
    scan_parser.set_defaults(handler=run_scan)

    feedback_parser = subparsers.add_parser(
        "feedback",
        help="Record feedback for a previous scan finding.",
    )
    feedback_parser.add_argument("--run-id", required=True)
    feedback_parser.add_argument("--finding-id", required=True)
    feedback_parser.add_argument(
        "--label",
        required=True,
        choices=["false_positive"],
    )
    feedback_parser.add_argument("--reason", default="")
    feedback_parser.set_defaults(handler=run_feedback)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
