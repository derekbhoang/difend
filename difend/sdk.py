"""Public SDK interface for Difend scans."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from difend.agents import run_agentic_scan
from difend.agents.model import DEFAULT_MODEL
from difend.agents.schemas import (
    AgentExecution,
    ExpandedContext,
    Finding,
    HandoffResult,
    ManualReviewItem,
    RiskArea,
)
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
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
            model=model,
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
        diff = GitDiffCapture(request.repository_path).capture(
            include_staged=request.include_staged,
            include_unstaged=request.include_unstaged,
            include_untracked=request.include_untracked,
        )
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
            name="difend scan",
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


def scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    model: str | None = None,
) -> ScanReport:
    """Run a Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        model=model,
    )
    return DifendSDK().scan(request)
