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
    GateResult,
    RuleSignal,
)


BUNDLE_FILE_NAMES = (
    "summary.md",
    "context-signals.md",
    "findings.md",
    "manual-review.md",
    "solution-proposals.md",
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
    def context_signals_path(self) -> Path:
        return self.output_folder / "context-signals.md"

    @property
    def manual_review_path(self) -> Path:
        return self.output_folder / "manual-review.md"

    @property
    def solution_proposals_path(self) -> Path:
        return self.output_folder / "solution-proposals.md"

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
    rule_signals: tuple[RuleSignal, ...]
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
        self._write_text(
            bundle.context_signals_path,
            self._context_signals_markdown(request),
        )
        self._write_text(bundle.findings_path, self._findings_markdown())
        self._write_text(bundle.manual_review_path, self._manual_review_markdown(request))
        self._write_text(
            bundle.solution_proposals_path,
            self._solution_proposals_markdown(),
        )
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
                f"- Rule signals: {len(request.rule_signals)}",
                f"- Agent-confirmed findings: 0",
                f"- Manual review items: {len(_manual_review_signals(request.rule_signals))}",
                "",
                "## Next Steps",
                "",
                f"Ask Codex to read `{bundle.codex_instructions_path}` and `{bundle.report_path}`.",
                "",
            ]
        )

    def _context_signals_markdown(self, request: ScanBundleRequest) -> str:
        lines = [
            "# Context Signals",
            "",
            "These are rule-based automated gate signals. Treat them as context "
            "for Codex or another review agent, not as final confirmed findings.",
            "",
        ]

        if not request.rule_signals:
            lines.extend(["No rule-based context signals were detected.", ""])
            return "\n".join(lines)

        for signal in request.rule_signals:
            lines.extend(_signal_markdown(signal))

        return "\n".join(lines)

    def _findings_markdown(self) -> str:
        return "\n".join(
            [
                "# Agent-Confirmed Findings",
                "",
                "No agent-confirmed findings have been generated yet.",
                "",
                "Automated gates only collected rule-based context signals. "
                "Ask Codex or another review agent to read `report.json`, "
                "`context-signals.md`, and `diff.patch` before writing confirmed "
                "findings here.",
                "",
            ]
        )

    def _manual_review_markdown(self, request: ScanBundleRequest) -> str:
        manual_review_signals = _manual_review_signals(request.rule_signals)
        lines = [
            "# Manual Review",
            "",
        ]

        if not manual_review_signals:
            lines.extend(["No manual review items were detected.", ""])
            return "\n".join(lines)

        lines.extend(
            [
                "Review these suspicious security-sensitive changes before treating "
                "the diff as safe.",
                "",
            ]
        )
        for signal in manual_review_signals:
            lines.extend(_signal_markdown(signal))

        return "\n".join(lines)

    def _solution_proposals_markdown(self) -> str:
        return "\n".join(
            [
                "# Solution Proposals",
                "",
                "No solution proposals have been generated yet.",
                "",
                "This file is reserved for a later non-mutating Codex or agent "
                "step that reads `report.json`, validates the rule signals, and "
                "proposes minimal fixes with suggested tests.",
                "",
            ]
        )

    def _codex_instructions_markdown(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> str:
        changed_files = request.parsed_diff.changed_files
        manual_review_signals = _manual_review_signals(request.rule_signals)
        file_lines = [f"- `{file_path}`" for file_path in changed_files]
        signal_lines = [
            f"- {_format_location(signal.file, signal.line)} "
            f"[{signal.severity}] {signal.gate}: {signal.evidence}"
            for signal in request.rule_signals
        ]
        manual_lines = [
            f"- {_format_location(signal.file, signal.line)}: {signal.evidence}"
            for signal in manual_review_signals
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
                f"- Machine report: {bundle.report_path}",
                f"- Added lines scanned: {len(request.parsed_diff.added_lines)}",
                "",
                "## Files To Inspect",
                "",
                *(file_lines or ["- No changed files were detected."]),
                "",
                "## Rule-Based Context Signals",
                "",
                *(signal_lines or ["- No rule-based context signals were detected."]),
                "",
                "## Manual Review Focus",
                "",
                *(manual_lines or ["- No manual review items were detected."]),
                "",
                "## Suggested Action",
                "",
                "1. Read `report.json` first. Treat `rule_signals` as context, "
                "not final findings.",
                "2. Read `diff.patch` to understand the exact scanned changes.",
                "3. Use `context-signals.md` and `manual-review.md` to decide "
                "which signals are real security issues.",
                "4. Write confirmed security issues into `findings.md` or explain "
                "why the diff appears safe.",
                "5. Write non-mutating fix ideas into `solution-proposals.md` "
                "before editing code.",
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
        codex_next_steps = [
            "Read report.json first; treat rule_signals as context, not final findings.",
            "Read context-signals.md and diff.patch before confirming any issue.",
            "Write confirmed security issues into findings.md.",
            "Write non-mutating fix ideas into solution-proposals.md before editing.",
        ]
        if not request.rule_signals:
            codex_next_steps.append("No rule-based context signals were detected.")

        return {
            "tool": "difend",
            "scan_id": bundle.scan_id,
            "status": request.status,
            "repo_path": str(request.repository_path),
            "output_dir": str(bundle.output_folder),
            "diff_patch_file": str(bundle.diff_path),
            "changed_files": list(request.parsed_diff.changed_files),
            "diff": {
                "has_changes": request.diff.has_changes,
                "unstaged_bytes": len(request.diff.unstaged.encode()),
                "staged_bytes": len(request.diff.staged.encode()),
                "untracked_bytes": len(request.diff.untracked.encode()),
                "changed_files": list(request.parsed_diff.changed_files),
                "added_lines": len(request.parsed_diff.added_lines),
            },
            "rule_signals": [signal.to_dict() for signal in request.rule_signals],
            "checks": [result.to_dict() for result in request.gate_results],
            "findings": [],
            "manual_review": [
                signal.to_dict()
                for signal in _manual_review_signals(request.rule_signals)
            ],
            "solution_proposals": [],
            "codex_next_steps": codex_next_steps,
        }

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, content: dict[str, Any]) -> None:
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")


def _signal_markdown(signal: RuleSignal) -> list[str]:
    return [
        f"## {_format_location(signal.file, signal.line)}",
        "",
        f"- Gate: {signal.gate}",
        f"- Severity: {signal.severity}",
        f"- Evidence: `{signal.evidence}`",
        f"- Recommendation: {signal.recommendation}",
        "",
    ]


def _manual_review_signals(
    rule_signals: tuple[RuleSignal, ...],
) -> tuple[RuleSignal, ...]:
    return tuple(
        signal
        for signal in rule_signals
        if signal.requires_manual_review
        or signal.severity == SEVERITY_MANUAL_REVIEW
    )


def _format_location(file_path: str, line: int | None) -> str:
    if line is None:
        return file_path

    return f"{file_path}:{line}"
