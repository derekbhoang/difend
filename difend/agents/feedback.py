"""Local feedback records for false-positive suppression."""

from __future__ import annotations

import json
from pathlib import Path

from difend.agents.schemas import FeedbackRecord, Finding, ManualReviewItem
from difend.agents.utils import stable_hash


class FeedbackStore:
    def __init__(self, repository_path: Path) -> None:
        self.root = repository_path / ".difend" / "feedback"

    def add(self, record: FeedbackRecord) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{record.item_id}.json"
        path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return path

    def load(self) -> list[FeedbackRecord]:
        if not self.root.exists():
            return []
        records: list[FeedbackRecord] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                records.append(
                    FeedbackRecord.model_validate_json(path.read_text(encoding="utf-8"))
                )
            except (OSError, ValueError):
                continue
        return records

    def digest(self) -> str:
        records = [record.model_dump(mode="json") for record in self.load()]
        return stable_hash(json.dumps(records, sort_keys=True))


def apply_feedback(
    findings: list[Finding],
    records: list[FeedbackRecord],
) -> tuple[list[Finding], list[Finding]]:
    false_positive_fingerprints = {
        record.evidence_fingerprint
        for record in records
        if record.label == "false_positive"
    }
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        if finding.evidence_fingerprint in false_positive_fingerprints:
            finding.suppressed = True
            finding.suppression_reason = "Suppressed by exact false-positive feedback."
            suppressed.append(finding)
        else:
            active.append(finding)
    return active, suppressed


def apply_manual_review_feedback(
    manual_review: list[ManualReviewItem],
    records: list[FeedbackRecord],
) -> tuple[list[ManualReviewItem], list[ManualReviewItem]]:
    false_positive_fingerprints = {
        record.evidence_fingerprint
        for record in records
        if record.label == "false_positive"
    }
    active: list[ManualReviewItem] = []
    suppressed: list[ManualReviewItem] = []
    for item in manual_review:
        if item.evidence_fingerprint in false_positive_fingerprints:
            suppressed.append(item)
        else:
            active.append(item)
    return active, suppressed
