"""Scan bundle creation for Difend."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from difend.diff import CodeDiff


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
    parsed_diff: dict[str, Any]
    gates: dict[str, Any]


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
        self._write_text(bundle.findings_path, self._findings_markdown(request.gates["findings"]))
        self._write_text(bundle.manual_review_path, self._manual_review_markdown(request.gates["manual_review"]))
        self._write_text(
            bundle.codex_instructions_path,
            self._codex_instructions_markdown(request, bundle),
        )
        self._write_text(bundle.diff_path, request.diff.combined)
        self._write_json(bundle.report_path, self._report_json(request, bundle))

        return bundle

    def _next_scan_id(self, output_root: Path) -> str:
        prefix = date.today().isoformat()
        output_root.mkdir(parents=True, exist_ok=True)
        highest = 0

        for path in output_root.iterdir():
            if not path.is_dir() or not path.name.startswith(f"{prefix}-"):
                continue
            suffix = path.name.removeprefix(f"{prefix}-")
            if suffix.isdigit():
                highest = max(highest, int(suffix))

        return f"{prefix}-{highest + 1:03d}"

    def _summary_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        summary = request.parsed_diff["summary"]
        gate_lines = [f"- {check['name']}: {check['status']}" for check in request.gates["checks"]]
        return "\n".join(
            [
                "# Difend Scan Summary",
                "",
                f"Status: {request.status}",
                f"Run ID: {bundle.scan_id}",
                f"Repository: {request.repository_path}",
                "",
                "## Diff Scanned",
                "",
                f"- Files changed: {summary['file_count']}",
                f"- Hunks: {summary['hunk_count']}",
                f"- Added lines: {summary['added_lines']}",
                f"- Removed lines: {summary['removed_lines']}",
                f"- Context lines: {summary['context_lines']}",
                "",
                "## Checks Performed",
                "",
                "- Git diff capture: done",
                "- Structured diff parse: done",
                *gate_lines,
                "",
                "## Result Counts",
                "",
                f"- Automated findings: {len(request.gates['findings'])}",
                f"- Manual review items: {len(request.gates['manual_review'])}",
                "",
                "## Next Steps",
                "",
                self._next_step_text(request, bundle),
                "",
            ]
        )

    def _findings_markdown(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "\n".join(
                [
                    "# Findings",
                    "",
                    "No automated security findings were detected.",
                    "",
                ]
            )

        sections = ["# Findings", ""]
        for finding in findings:
            sections.extend(
                [
                    f"## {finding['id']}: {finding['severity'].upper()} - {finding['gate']}",
                    "",
                    f"Location: `{finding['file']}:{finding['line_range']}`",
                    "",
                    "Evidence:",
                    "",
                    "```text",
                    finding["evidence"],
                    "```",
                    "",
                    f"Recommendation: {finding['recommendation']}",
                    "",
                ]
            )
        return "\n".join(sections)

    def _manual_review_markdown(self, manual_review: list[dict[str, Any]]) -> str:
        if not manual_review:
            return "\n".join(
                [
                    "# Manual Review",
                    "",
                    "No manual review items were detected.",
                    "",
                ]
            )

        sections = ["# Manual Review", ""]
        for item in manual_review:
            checklist = "\n".join(f"- [ ] {entry}" for entry in item["checklist"])
            sections.extend(
                [
                    f"## {item['id']}: {item['category']}",
                    "",
                    f"Gate: {item['gate']}",
                    f"Location: `{item['file']}:{item['line_range']}`",
                    "",
                    "Evidence:",
                    "",
                    "```text",
                    item["evidence"],
                    "```",
                    "",
                    f"Reason: {item['reason']}",
                    "",
                    "Checklist:",
                    "",
                    checklist,
                    "",
                    f"Recommendation: {item['recommendation']}",
                    "",
                ]
            )
        return "\n".join(sections)

    def _codex_instructions_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        paths = request.parsed_diff["summary"]["paths"]
        changed_files = "\n".join(f"- `{path}`" for path in paths) or "- No changed files detected."

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
                f"- Raw diff: {bundle.diff_path}",
                f"- Structured report: {bundle.report_path}",
                f"- Findings: {bundle.findings_path}",
                f"- Manual review: {bundle.manual_review_path}",
                "",
                "## Changed Files",
                "",
                changed_files,
                "",
                "## Suggested Action",
                "",
                "Inspect `findings.md` first. If findings are present, fix those concrete security issues. "
                "Then inspect `manual-review.md` for areas that need deeper judgement, using `diff.patch` "
                "and the `parsed_diff` section in `report.json` as source context.",
                "",
            ]
        )

    def _next_step_text(self, request: ScanBundleRequest, bundle: ScanBundle) -> str:
        if request.gates["findings"]:
            return f"Fix the concrete issues in `{bundle.findings_path}`, then run `difend scan` again."
        if request.gates["manual_review"]:
            return f"Review `{bundle.manual_review_path}` before merging."
        return f"Ask Codex to read `{bundle.codex_instructions_path}` if you want a second-pass review."

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
                "context_lines": request.diff.context_lines,
                "unstaged_bytes": len(request.diff.unstaged.encode()),
                "staged_bytes": len(request.diff.staged.encode()),
            },
            "parsed_diff": request.parsed_diff,
            "gates": {
                "checks": request.gates["checks"],
                "summary": request.gates["summary"],
            },
            "findings": request.gates["findings"],
            "manual_review": request.gates["manual_review"],
        }

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, content: dict[str, Any]) -> None:
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")
