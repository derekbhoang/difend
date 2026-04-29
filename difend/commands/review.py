"""Implementation of the difend review command."""

from __future__ import annotations

import argparse

from difend.agent import AgentReviewError, review_scan_bundle


def run_review(args: argparse.Namespace) -> int:
    print("Difend agent review started")
    print()

    try:
        result = review_scan_bundle(
            run_folder=args.run_folder,
            model=args.model,
        )
    except AgentReviewError as error:
        print(f"Agent review failed: {error}")
        return 1

    print(f"Status: {result.status}")
    print(f"Run folder: {result.run_folder}")
    print(f"Findings written to: {result.findings_path}")
    print(f"Solution proposals written to: {result.solution_proposals_path}")
    print(f"Report updated: {result.report_path}")
    return 0
