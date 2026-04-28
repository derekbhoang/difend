"""Command line interface for Difend."""

from __future__ import annotations

import argparse

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
