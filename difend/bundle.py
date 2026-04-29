"""Scan bundle creation for Difend."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from difend.diff import CodeDiff
from difend.models import Finding


BUNDLE_FILE_NAMES = (
    "summary.md",
    "findings.md",
    "manual-review.md",
    "codex-instructions.md",
    "diff.patch",
    "report.json",
)


@dataclass(frozen=True)
class ScanBundle:
    """Files and folder created for one scan run."""

    scan_id: str
    output_folder: Path

    @property
    def summary_path(self) -> Path:
        return self.output_folder / "summary.md"

    @property
    def findings_path(self) -> Path:
        return self.output_folder / "findings.md"

    @property
    def manual_review_path(self) -> Path:
        return self.output_folder / "manual-review.md"

    @property
    def codex_instructions_path(self) -> Path:
        return self.output_folder / "codex-instructions.md"

    @property
    def diff_path(self) -> Path:
        return self.output_folder / "diff.patch"

    @property
    def report_path(self) -> Path:
        return self.output_folder / "report.json"


@dataclass(frozen=True)
class ScanBundleRequest:
    """Input needed to write a scan bundle."""

    repository_path: Path
    output_root: Path
    status: str
    diff: CodeDiff
    findings: tuple[Finding, ...] = ()


class ScanBundleWriter:
    """Create the persistent files for a Difend scan."""

    def write(self, request: ScanBundleRequest) -> ScanBundle:
        output_root = request.repository_path / request.output_root
        scan_id = self._next_scan_id(output_root)
        bundle = ScanBundle(
            scan_id=scan_id,
            output_folder=output_root / scan_id,
        )
        bundle.output_folder.mkdir(parents=True, exist_ok=False)

        self._write_text(bundle.summary_path, self._summary_markdown(request, bundle))
        self._write_text(bundle.findings_path, self._findings_markdown(request))
        self._write_text(bundle.manual_review_path, self._manual_review_markdown())
        self._write_text(
            bundle.codex_instructions_path,
            self._codex_instructions_markdown(request, bundle),
        )
        self._write_text(bundle.diff_path, self._patch_text(request.diff))
        self._write_json(bundle.report_path, self._report_json(request, bundle))

        return bundle

    def _next_scan_id(self, output_root: Path) -> str:
        prefix = date.today().isoformat()
        output_root.mkdir(parents=True, exist_ok=True)
        existing = [
            path.name
            for path in output_root.iterdir()
            if path.is_dir() and path.name.startswith(f"{prefix}-")
        ]

        next_number = len(existing) + 1
        return f"{prefix}-{next_number:03d}"

    def _summary_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        return "\n".join(
            [
                "# Difend Scan Summary",
                "",
                f"Status: {request.status}",
                f"Run ID: {bundle.scan_id}",
                f"Repository: {request.repository_path}",
                "",
                "## Checks Performed",
                "",
                "- Git diff capture",
                "",
                "## Next Steps",
                "",
                f"Ask Codex to read `{bundle.codex_instructions_path}`.",
                "",
            ]
        )

    def _findings_markdown(self, request: ScanBundleRequest) -> str:
        lines = [
            "# Findings",
            "",
        ]

        if not request.findings:
            lines.extend(
                [
                    "No automated security findings detected.",
                    "",
                ]
            )
            return "\n".join(lines)

        for index, finding in enumerate(request.findings, start=1):
            location = finding.file
            if finding.line is not None:
                location = f"{location}:{finding.line}"

            lines.extend(
                [
                    f"## {index}. {finding.gate}",
                    "",
                    f"- Severity: {finding.severity.value}",
                    f"- Location: {location}",
                    f"- Evidence: {finding.evidence}",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ]
            )

        return "\n".join(lines)

    def _manual_review_markdown(self) -> str:
        return "\n".join(
            [
                "# Manual Review",
                "",
                "No manual review checks have run yet.",
                "",
            ]
        )

    def _codex_instructions_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        return "\n".join(
            [
                "# Codex Instructions",
                "",
                "Review this Difend scan bundle before continuing the task.",
                "",
                "## Context",
                "",
                f"- Status: {request.status}",
                f"- Repository: {request.repository_path}",
                f"- Diff: {bundle.diff_path}",
                "",
                "## Suggested Action",
                "",
                "Inspect `diff.patch` first, then use `summary.md`, `findings.md`, "
                "and `manual-review.md` as supporting context.",
                "",
            ]
        )

    def _patch_text(self, diff: CodeDiff) -> str:
        return diff.unstaged + diff.staged + diff.untracked

    def _report_json(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> dict[str, Any]:
        return {
            "scan_id": bundle.scan_id,
            "status": request.status,
            "repository_path": str(request.repository_path),
            "output_folder": str(bundle.output_folder),
            "diff": {
                "has_changes": request.diff.has_changes,
                "unstaged_bytes": len(request.diff.unstaged.encode()),
                "staged_bytes": len(request.diff.staged.encode()),
                "untracked_bytes": len(request.diff.untracked.encode()),
            },
            "findings": [
                finding.to_dict()
                for finding in request.findings
            ],
            "manual_review": [],
        }

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, content: dict[str, Any]) -> None:
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
