"""Public SDK interface for Difend scans."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from difend.agents import run_agentic_scan
from difend.agents.context import prepare_scan_context
from difend.agents.feedback import FeedbackStore, apply_feedback
from difend.agents.gates import run_automated_gates
from difend.agents.handoff import run_handoff
from difend.agents.model import DEFAULT_MODEL
from difend.agents.schemas import (
    AgentExecution,
    AgentStatus,
    DiffClassifierResult,
    ExpandedContext,
    Finding,
    HandoffResult,
    ManualReviewItem,
    RiskArea,
)
from difend.agents.scoring import decide_status, risk_score
from difend.bundle import ScanBundleRequest, ScanBundleWriter
from difend.config import load_environment
from difend.diff import CodeDiff, GitDiffCapture


class ScanStatus(str, Enum):
    """Final status values returned by a scan."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual review required"


@dataclass(frozen=True)
class ScanRequest:
    """Input contract for a Difend scan."""

    repository_path: Path
    output_root: Path = Path(".difend/runs")
    include_staged: bool = True
    include_unstaged: bool = True
    include_untracked: bool = True
    model: str | None = None
    use_cache: bool = True

    @classmethod
    def from_path(
        cls,
        repository_path: str | Path = ".",
        output_root: str | Path = ".difend/runs",
        model: str | None = None,
        use_cache: bool = True,
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
            model=model,
            use_cache=use_cache,
        )


@dataclass(frozen=True)
class ScanReport:
    """Output contract returned by a Difend scan."""

    name: str
    scan_id: str
    repository_path: Path
    output_folder: Path
    status: ScanStatus
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
    model: str = DEFAULT_MODEL
    cache_hit: bool = False
    cache_key: str = ""
    context_hash: str = ""
    feedback_digest: str = ""
    trace_path: Path | None = None
    trace: dict[str, Any] = field(default_factory=dict)


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        load_environment(request.repository_path)
        diff = self._capture_diff(request)
        scan_context = prepare_scan_context(diff)
        feedback_store = FeedbackStore(request.repository_path)
        gates, gates_execution = run_automated_gates(scan_context, model_client=None)
        active_findings, suppressed_findings = apply_feedback(
            gates.findings,
            feedback_store.load(),
        )
        gates = gates.model_copy(update={"findings": active_findings})
        status = ScanStatus(decide_status(active_findings, []))
        score = risk_score(active_findings, [])
        handoff, handoff_execution = run_handoff(
            scan_context=scan_context,
            classifier=DiffClassifierResult(),
            findings=active_findings,
            manual_review=[],
            status=status.value,
            model_client=None,
        )
        agents = [
            AgentExecution(
                name="prepare_scan_context",
                status=AgentStatus.COMPLETED,
                detail=f"Prepared {len(scan_context.changed_files)} changed file(s).",
            ),
            gates_execution,
            AgentExecution(
                name="orchestrator_merge",
                status=AgentStatus.COMPLETED,
                detail="Applied feedback suppression and finalized Gates findings.",
            ),
            handoff_execution,
            AgentExecution(
                name="orchestrator_finalize",
                status=AgentStatus.COMPLETED,
                detail=f"Final status: {status.value}.",
            ),
        ]
        trace = {
            "prepare_scan_context": {
                "scan_context": scan_context.model_dump(mode="json"),
            },
            "automated_gates": {
                "candidates": [
                    candidate.model_dump(mode="json") for candidate in gates.candidates
                ],
                "findings": [
                    finding.model_dump(mode="json") for finding in gates.findings
                ],
                "used_llm_validation": False,
            },
            "orchestrator_merge": {
                "active_findings": [
                    finding.finding_id for finding in active_findings
                ],
                "suppressed_findings": [
                    finding.model_dump(mode="json")
                    for finding in suppressed_findings
                ],
                "risk_score": score,
                "status": status.value,
            },
            "handoff": {
                "handoff": handoff.model_dump(mode="json"),
            },
            "orchestrator_finalize": {
                "status": status.value,
                "cache_hit": False,
            },
        }
        feedback_digest = feedback_store.digest()
        bundle = ScanBundleWriter().write(
            ScanBundleRequest(
                repository_path=request.repository_path,
                output_root=request.output_root,
                status=status.value,
                diff=diff,
                findings=active_findings,
                suppressed_findings=suppressed_findings,
                risk_score=score,
                handoff=handoff,
                agents=agents,
                model="",
                cache_hit=False,
                feedback_digest=feedback_digest,
                trace=trace,
            )
        )

        return ScanReport(
            name="difend scan",
            scan_id=bundle.scan_id,
            repository_path=request.repository_path,
            output_folder=bundle.output_folder,
            status=status,
            diff=diff,
            findings=active_findings,
            suppressed_findings=suppressed_findings,
            risk_score=score,
            handoff=handoff,
            agents=agents,
            model="",
            cache_hit=False,
            feedback_digest=feedback_digest,
            trace_path=bundle.agent_trace_path,
            trace=trace,
        )

    def agent_scan(self, request: ScanRequest) -> ScanReport:
        load_environment(request.repository_path)
        diff = self._capture_diff(request)
        model = request.model or os.getenv("DIFEND_OPENAI_MODEL") or DEFAULT_MODEL
        agentic_result = run_agentic_scan(
            request.repository_path,
            diff,
            model=model,
            use_cache=request.use_cache,
        )
        status = ScanStatus(agentic_result.status)
        bundle = ScanBundleWriter().write(
            ScanBundleRequest(
                repository_path=request.repository_path,
                output_root=request.output_root,
                status=status.value,
                diff=diff,
                risk_areas=agentic_result.classifier.risk_areas,
                expanded_context=agentic_result.expanded_context,
                findings=agentic_result.gates.findings,
                manual_review=agentic_result.manual_review,
                covered_manual_review=agentic_result.covered_manual_review,
                suppressed_findings=agentic_result.suppressed_findings,
                suppressed_manual_review=agentic_result.suppressed_manual_review,
                risk_score=agentic_result.risk_score,
                handoff=agentic_result.handoff,
                agents=agentic_result.agents,
                model=agentic_result.model,
                cache_hit=agentic_result.cache_hit,
                cache_key=agentic_result.cache_key,
                context_hash=agentic_result.context_hash,
                feedback_digest=agentic_result.feedback_digest,
                trace=agentic_result.trace,
            )
        )

        return ScanReport(
            name="difend agent-scan",
            scan_id=bundle.scan_id,
            repository_path=request.repository_path,
            output_folder=bundle.output_folder,
            status=status,
            diff=diff,
            risk_areas=agentic_result.classifier.risk_areas,
            expanded_context=agentic_result.expanded_context,
            findings=agentic_result.gates.findings,
            manual_review=agentic_result.manual_review,
            covered_manual_review=agentic_result.covered_manual_review,
            suppressed_findings=agentic_result.suppressed_findings,
            suppressed_manual_review=agentic_result.suppressed_manual_review,
            risk_score=agentic_result.risk_score,
            handoff=agentic_result.handoff,
            agents=agentic_result.agents,
            model=agentic_result.model,
            cache_hit=agentic_result.cache_hit,
            cache_key=agentic_result.cache_key,
            context_hash=agentic_result.context_hash,
            feedback_digest=agentic_result.feedback_digest,
            trace_path=bundle.agent_trace_path,
            trace=agentic_result.trace,
        )

    def _capture_diff(self, request: ScanRequest) -> CodeDiff:
        return GitDiffCapture(request.repository_path).capture(
            include_staged=request.include_staged,
            include_unstaged=request.include_unstaged,
            include_untracked=request.include_untracked,
        )


def scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    model: str | None = None,
    use_cache: bool = True,
) -> ScanReport:
    """Run deterministic Automated Gates through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        model=model,
        use_cache=use_cache,
    )
    return DifendSDK().scan(request)


def agent_scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    model: str | None = None,
    use_cache: bool = True,
) -> ScanReport:
    """Run the full agentic Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        model=model,
        use_cache=use_cache,
    )
    return DifendSDK().agent_scan(request)
