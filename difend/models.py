from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_MANUAL_REVIEW = "manual review required"


@dataclass(frozen=True)
class DiffLine:
    file: str
    line: int | None
    content: str


@dataclass(frozen=True)
class ParsedDiff:
    changed_files: tuple[str, ...]
    added_lines: tuple[DiffLine, ...]


@dataclass(frozen=True)
class DiffBundle:
    staged: str
    unstaged: str
    untracked: str = ""

    @property
    def combined(self) -> str:
        parts = []
        if self.unstaged:
            parts.append("# Unstaged diff\n" + self.unstaged.rstrip())
        if self.staged:
            parts.append("# Staged diff\n" + self.staged.rstrip())
        if self.untracked:
            parts.append("# Untracked files diff\n" + self.untracked.rstrip())
        return "\n\n".join(parts) + ("\n" if parts else "")

    @property
    def is_empty(self) -> bool:
        return (
            not self.staged.strip()
            and not self.unstaged.strip()
            and not self.untracked.strip()
        )


@dataclass(frozen=True)
class Finding:
    gate: str
    severity: str
    file: str
    line: int | None
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ManualReviewItem:
    gate: str
    file: str
    line: int | None
    reason: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    status: str
    run_id: str
    repo_path: Path
    output_path: Path
    diff: str
    findings: tuple[Finding, ...]
    manual_review_items: tuple[ManualReviewItem, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "run_id": self.run_id,
            "repo_path": str(self.repo_path),
            "output_path": str(self.output_path),
            "diff": self.diff,
            "findings": [finding.to_dict() for finding in self.findings],
            "manual_review_items": [
                item.to_dict() for item in self.manual_review_items
            ],
        }
