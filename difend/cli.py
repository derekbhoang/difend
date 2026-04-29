"""Command line interface for Difend."""

from __future__ import annotations

import argparse

from difend.commands.review import run_review
from difend.commands.scan import run_scan


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
    scan_parser.set_defaults(handler=run_scan)

    review_parser = subparsers.add_parser(
        "review",
        help="Ask the Codex agent to confirm findings for a scan bundle.",
    )
    review_parser.add_argument(
        "run_folder",
        nargs="?",
        help="Scan output folder. Defaults to the latest .difend/runs entry.",
    )
    review_parser.add_argument(
        "--model",
        help="OpenAI model to use. Defaults to DIFEND_AGENT_MODEL or gpt-5.1-codex.",
    )
    review_parser.set_defaults(handler=run_review)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
