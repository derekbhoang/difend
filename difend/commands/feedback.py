"""Implementation of local Difend feedback commands."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from difend.agents.feedback import FeedbackStore
from difend.agents.schemas import FeedbackRecord, Severity


def run_feedback(args: argparse.Namespace) -> int:
    repository_path = Path(".")
    reason = (args.reason or "").strip()
    if args.label == "false_positive" and not reason:
        print("Feedback reason is required for false_positive labels.")
        return 2

    report_path = repository_path / ".difend" / "runs" / args.run_id / "report.json"
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        return 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    found = _find_report_item(report, args.finding_id)
    if found is None:
        print(f"Finding not found in report: {args.finding_id}")
        return 2
    item_type, item = found
    severity = item.get("severity") or item.get("risk_level")
    severity_value = Severity(severity) if severity in Severity._value2member_map_ else None
    if args.label == "false_positive" and severity_value == Severity.CRITICAL:
        print("Critical items cannot be suppressed without explicit force metadata.")
        return 2

    record = FeedbackRecord(
        item_id=args.finding_id,
        item_type=item_type,
        label=args.label,
        evidence_fingerprint=item["evidence_fingerprint"],
        reason=reason,
        run_id=args.run_id,
        created_at=datetime.now(UTC).isoformat(),
        file=item.get("file", ""),
        line=item.get("line"),
        severity=severity_value,
        force=False,
    )
    path = FeedbackStore(repository_path).add(record)
    print(f"Feedback written to: {path}")
    return 0


def _find_report_item(report: dict, item_id: str) -> tuple[str, dict] | None:
    for key, item_type in (("findings", "finding"), ("manual_review", "manual_review")):
        for item in report.get(key, []):
            if item.get("finding_id") == item_id or item.get("manual_review_id") == item_id:
                return item_type, item
    return None
