"""Scan bundle creation for Difend."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from difend.agents.schemas import (
    AgentExecution,
    ExpandedContext,
    Finding,
    HandoffResult,
    ManualReviewItem,
    RiskArea,
)
from difend.agents.utils import model_dump
from difend.diff import CodeDiff
from difend.observability import ScanEvent


BUNDLE_FILE_NAMES = (
    "summary.md",
    "findings.md",
    "manual-review.md",
    "codex-instructions.md",
    "diff.patch",
    "report.json",
    "agent-trace.json",
    "scan-log.jsonl",
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

    @property
    def agent_trace_path(self) -> Path:
        return self.output_folder / "agent-trace.json"

    @property
    def scan_log_path(self) -> Path:
        return self.output_folder / "scan-log.jsonl"


@dataclass(frozen=True)
class ScanBundleRequest:
    """Input needed to write a scan bundle."""

    repository_path: Path
    output_root: Path
    status: str
    diff: CodeDiff
    risk_areas: list[RiskArea] = field(default_factory=list)
    expanded_context: ExpandedContext = field(default_factory=ExpandedContext)
    findings: list[Finding] = field(default_factory=list)
    manual_review: list[ManualReviewItem] = field(default_factory=list)
    covered_manual_review: list[ManualReviewItem] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    suppressed_manual_review: list[ManualReviewItem] = field(default_factory=list)
    risk_score: int = 0
    handoff: HandoffResult = field(default_factory=HandoffResult)
    agents: list[AgentExecution] = field(default_factory=list)
    model: str = ""
    cache_hit: bool = False
    cache_key: str = ""
    context_hash: str = ""
    feedback_digest: str = ""
    trace: dict[str, Any] = field(default_factory=dict)
    events: list[ScanEvent] = field(default_factory=list)


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
        self._write_json(bundle.agent_trace_path, self._agent_trace_json(request, bundle))
        self.write_scan_log(bundle, request.events)

        return bundle

    def write_scan_log(
        self,
        bundle: ScanBundle,
        events: list[ScanEvent],
    ) -> None:
        lines = [json.dumps(event.model_dump(mode="json")) for event in events]
        content = "\n".join(lines) + ("\n" if lines else "")
        bundle.scan_log_path.write_text(content, encoding="utf-8")

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
                f"Model: {request.model or 'not used'}",
                f"Risk score: {request.risk_score}",
                f"Cache hit: {str(request.cache_hit).lower()}",
                f"Risk areas: {self._format_risk_areas(request.risk_areas)}",
                "",
                "## Checks Performed",
                "",
                "- Git diff capture",
                *[
                    f"- {agent.name}: {agent.status.value}"
                    + (f" ({agent.detail})" if agent.detail else "")
                    for agent in request.agents
                ],
                "",
                "## Next Steps",
                "",
                request.handoff.safest_next_action,
                "",
                f"Ask Codex to read `{bundle.codex_instructions_path}`.",
                "",
            ]
        )

    def _findings_markdown(self, request: ScanBundleRequest) -> str:
        if not request.findings and not request.suppressed_findings:
            return "\n".join(["# Findings", "", "No concrete findings.", ""])

        lines = ["# Findings", ""]
        for finding in request.findings:
            lines.extend(
                [
                    f"## {finding.finding_id}",
                    "",
                    f"- Type: {finding.vulnerability_type}",
                    f"- Gate: {finding.gate_name}",
                    f"- Severity: {finding.severity.value}",
                    f"- Confidence: {finding.confidence:.2f}",
                    f"- Location: {finding.file}:{finding.line or '?'}",
                    f"- Evidence: `{finding.evidence}`",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ]
            )

        if request.suppressed_findings:
            lines.extend(["## Suppressed Findings", ""])
            for finding in request.suppressed_findings:
                lines.append(
                    f"- {finding.finding_id}: {finding.vulnerability_type} "
                    f"at {finding.file}:{finding.line or '?'}"
                )
            lines.append("")

        return "\n".join(lines)

    def _manual_review_markdown(self, request: ScanBundleRequest) -> str:
        if not request.manual_review:
            lines = ["# Manual Review", "", "No manual review items.", ""]
            if request.covered_manual_review:
                lines.extend(["## Covered By Automated Gates", ""])
                lines.extend(
                    [
                        f"- {item.manual_review_id}: {item.vulnerability_type} "
                        f"at {item.file}:{item.line or '?'}"
                        for item in request.covered_manual_review
                    ]
                )
                lines.append("")
            if request.suppressed_manual_review:
                lines.extend(["## Suppressed Manual Review", ""])
                lines.extend(
                    [
                        f"- {item.manual_review_id}: {item.vulnerability_type} "
                        f"at {item.file}:{item.line or '?'}"
                        for item in request.suppressed_manual_review
                    ]
                )
                lines.append("")
            return "\n".join(lines)

        lines = ["# Manual Review", ""]
        for item in request.manual_review:
            lines.extend(
                [
                    f"## {item.manual_review_id}",
                    "",
                    f"- Area: {item.area.value}",
                    f"- Type: {item.vulnerability_type}",
                    f"- Risk level: {item.risk_level.value}",
                    f"- Confidence: {item.confidence:.2f}",
                    f"- Location: {item.file}:{item.line or '?'}",
                    f"- Reason: {item.reason}",
                    f"- Evidence: `{item.evidence}`",
                    "",
                    "Questions:",
                    *[f"- {question}" for question in item.questions],
                    "",
                ]
            )
        if request.covered_manual_review:
            lines.extend(["## Covered By Automated Gates", ""])
            for item in request.covered_manual_review:
                lines.append(
                    f"- {item.manual_review_id}: {item.vulnerability_type} "
                    f"at {item.file}:{item.line or '?'}"
                )
            lines.append("")
        if request.suppressed_manual_review:
            lines.extend(["## Suppressed Manual Review", ""])
            for item in request.suppressed_manual_review:
                lines.append(
                    f"- {item.manual_review_id}: {item.vulnerability_type} "
                    f"at {item.file}:{item.line or '?'}"
                )
            lines.append("")
        return "\n".join(lines)

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
                f"- Risk areas: {self._format_risk_areas(request.risk_areas)}",
                f"- Findings: {len(request.findings)}",
                f"- Manual review items: {len(request.manual_review)}",
                "",
                "## Inspect Next",
                "",
                *[f"- {path}" for path in request.handoff.inspect_next],
                "",
                "## Codex Tasks",
                "",
                *[f"- {task}" for task in request.handoff.codex_tasks],
                "",
                "## Checklist",
                "",
                *[f"- {item}" for item in request.handoff.checklist],
                "",
                "## Safest Next Action",
                "",
                request.handoff.safest_next_action,
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
            "risk_areas": [area.value for area in request.risk_areas],
            "expanded_context": model_dump(request.expanded_context),
            "findings": [model_dump(finding) for finding in request.findings],
            "manual_review": [model_dump(item) for item in request.manual_review],
            "covered_manual_review": [
                model_dump(item) for item in request.covered_manual_review
            ],
            "suppressed_findings": [
                model_dump(finding) for finding in request.suppressed_findings
            ],
            "suppressed_manual_review": [
                model_dump(item) for item in request.suppressed_manual_review
            ],
            "risk_score": request.risk_score,
            "handoff": model_dump(request.handoff),
            "agents": [model_dump(agent) for agent in request.agents],
            "model": request.model,
            "cache_hit": request.cache_hit,
            "cache_key": request.cache_key,
            "context_hash": request.context_hash,
            "feedback_digest": request.feedback_digest,
            "trace_path": str(bundle.agent_trace_path),
            "log_path": str(bundle.scan_log_path),
        }

    def _agent_trace_json(
        self,
        request: ScanBundleRequest,
        bundle: ScanBundle,
    ) -> dict[str, Any]:
        return {
            "scan_id": bundle.scan_id,
            "status": request.status,
            "cache": {
                "hit": request.cache_hit,
                "cache_key": request.cache_key,
                "context_hash": request.context_hash,
                "feedback_digest": request.feedback_digest,
            },
            "agents": [model_dump(agent) for agent in request.agents],
            "trace": request.trace,
        }

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, content: dict[str, Any]) -> None:
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")

    def _format_risk_areas(self, risk_areas: list[RiskArea]) -> str:
        if not risk_areas:
            return "none"
        return ", ".join(area.value for area in risk_areas)
