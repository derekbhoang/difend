"""Scan bundle creation for Difend."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from difend.diff import CodeDiff, ParsedDiff
from difend.gates import (
    SEVERITY_MANUAL_REVIEW,
    Finding,
    GateResult,
)


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
    parsed_diff: ParsedDiff
    findings: tuple[Finding, ...]
    gate_results: tuple[GateResult, ...]


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
        self._write_text(bundle.manual_review_path, self._manual_review_markdown(request))
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
                *[
                    f"- {result.gate}: {result.status}"
                    for result in request.gate_results
                ],
                "",
                "## Diff Scope",
                "",
                f"- Changed files: {len(request.parsed_diff.changed_files)}",
                f"- Added lines scanned: {len(request.parsed_diff.added_lines)}",
                f"- Automated findings: {len(request.findings)}",
                f"- Manual review items: {len(_manual_review_findings(request.findings))}",
                "",
                "## Next Steps",
                "",
                f"Ask Codex to read `{bundle.codex_instructions_path}`.",
                "",
            ]
        )

    def _findings_markdown(self, request: ScanBundleRequest) -> str:
        lines = [
            "# Automated Gate Findings",
            "",
            "This is the combined partial report from all automated gates.",
            "",
        ]

        if not request.findings:
            lines.extend(["No automated gate findings were detected.", ""])
            return "\n".join(lines)

        for finding in request.findings:
            lines.extend(_finding_markdown(finding))

        return "\n".join(lines)

    def _manual_review_markdown(self, request: ScanBundleRequest) -> str:
        manual_review_findings = _manual_review_findings(request.findings)
        lines = [
            "# Manual Review",
            "",
        ]

        if not manual_review_findings:
            lines.extend(["No manual review items were detected.", ""])
            return "\n".join(lines)

        lines.extend(
            [
                "Review these suspicious security-sensitive changes before treating "
                "the diff as safe.",
                "",
            ]
        )
        for finding in manual_review_findings:
            lines.extend(_finding_markdown(finding))

        return "\n".join(lines)

    def _codex_instructions_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        changed_files = request.parsed_diff.changed_files
        manual_review_findings = _manual_review_findings(request.findings)
        file_lines = [f"- `{file_path}`" for file_path in changed_files]
        finding_lines = [
            f"- {_format_location(finding.file, finding.line)} "
            f"[{finding.severity}] {finding.gate}: {finding.evidence}"
            for finding in request.findings
        ]
        manual_lines = [
            f"- {_format_location(finding.file, finding.line)}: {finding.evidence}"
            for finding in manual_review_findings
        ]

        return "\n".join(
            [
                "# Codex Handoff Prompt",
                "",
                "Use this as the direct prompt for continuing the security review:",
                "",
                "You are reviewing a Difend scan bundle for security issues in the "
                "current Git diff. Focus on the changed and added lines first. Do "
                "not review unrelated old code unless it is needed to understand "
                "the changed lines.",
                "",
                "## Context",
                "",
                f"- Status: {request.status}",
                f"- Repository: {request.repository_path}",
                f"- Scan folder: {bundle.output_folder}",
                f"- Diff patch: {bundle.diff_path}",
                f"- Added lines scanned: {len(request.parsed_diff.added_lines)}",
                "",
                "## Files To Inspect",
                "",
                *(file_lines or ["- No changed files were detected."]),
                "",
                "## Automated Findings",
                "",
                *(finding_lines or ["- No automated findings were detected."]),
                "",
                "## Manual Review Focus",
                "",
                *(manual_lines or ["- No manual review items were detected."]),
                "",
                "## Suggested Action",
                "",
                "1. Read `diff.patch` to understand the exact scanned changes.",
                "2. Read `findings.md` and verify each automated finding.",
                "3. Read `manual-review.md` and inspect related code only where "
                "needed to judge the changed lines.",
                "4. Recommend a minimal fix for any confirmed issue, or explain why "
                "the diff appears safe.",
                "",
            ]
        )

    def _patch_text(self, diff: CodeDiff) -> str:
        return diff.patch_text

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
                "changed_files": list(request.parsed_diff.changed_files),
                "added_lines": len(request.parsed_diff.added_lines),
            },
            "gates": [result.to_dict() for result in request.gate_results],
            "findings": [finding.to_dict() for finding in request.findings],
            "manual_review": [
                finding.to_dict()
                for finding in _manual_review_findings(request.findings)
            ],
        }

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, content: dict[str, Any]) -> None:
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")


def _finding_markdown(finding: Finding) -> list[str]:
    return [
        f"## {_format_location(finding.file, finding.line)}",
        "",
        f"- Gate: {finding.gate}",
        f"- Severity: {finding.severity}",
        f"- Evidence: `{finding.evidence}`",
        f"- Recommendation: {finding.recommendation}",
        "",
    ]


def _manual_review_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(
        finding
        for finding in findings
        if finding.requires_manual_review
        or finding.severity == SEVERITY_MANUAL_REVIEW
    )


def _format_location(file_path: str, line: int | None) -> str:
    if line is None:
        return file_path

    return f"{file_path}:{line}"
