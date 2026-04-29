"""Implementation of local Difend feedback commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from difend.agents.feedback import FeedbackStore
from difend.agents.schemas import FeedbackRecord


def run_feedback(args: argparse.Namespace) -> int:
    repository_path = Path(".")
    report_path = repository_path / ".difend" / "runs" / args.run_id / "report.json"
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        return 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    item = _find_report_item(report, args.finding_id)
    if item is None:
        print(f"Finding not found in report: {args.finding_id}")
        return 2

    record = FeedbackRecord(
        item_id=args.finding_id,
        label=args.label,
        evidence_fingerprint=item["evidence_fingerprint"],
        reason=args.reason or "",
    )
    path = FeedbackStore(repository_path).add(record)
    print(f"Feedback written to: {path}")
    return 0


def _find_report_item(report: dict, item_id: str) -> dict | None:
    for key in ("findings", "manual_review"):
        for item in report.get(key, []):
            if item.get("finding_id") == item_id or item.get("manual_review_id") == item_id:
                return item
    return None
