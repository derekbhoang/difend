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
from difend.observability import AGENT_SCAN_PHASES, SCAN_PHASES, ScanObserver


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
    observer: ScanObserver | None = None

    @classmethod
    def from_path(
        cls,
        repository_path: str | Path = ".",
        output_root: str | Path = ".difend/runs",
        model: str | None = None,
        use_cache: bool = True,
        observer: ScanObserver | None = None,
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
            model=model,
            use_cache=use_cache,
            observer=observer,
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
    log_path: Path | None = None
    trace: dict[str, Any] = field(default_factory=dict)


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        load_environment(request.repository_path)
        observer = _ensure_observer(request.observer, "difend scan", SCAN_PHASES)
        _start_phase(observer, "diff_capture")
        diff = self._capture_diff(request)
        _complete_phase(
            observer,
            "diff_capture",
            _diff_capture_detail(diff),
            metadata=_diff_metadata(diff),
        )
        scan_context = prepare_scan_context(diff)
        _complete_phase(
            observer,
            "prepare_scan_context",
            f"Prepared {len(scan_context.changed_files)} changed file(s).",
            metadata={
                "changed_files": len(scan_context.changed_files),
                "added_lines": len(scan_context.added_lines),
            },
        )
        feedback_store = FeedbackStore(request.repository_path)
        gates, gates_execution = run_automated_gates(scan_context, model_client=None)
        _record_agent(
            observer,
            gates_execution,
            metadata={
                "candidates": len(gates.candidates),
                "findings": len(gates.findings),
            },
        )
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
        _record_agent(observer, agents[2])
        _record_agent(
            observer,
            handoff_execution,
            metadata={
                "inspect_next": len(handoff.inspect_next),
                "codex_tasks": len(handoff.codex_tasks),
            },
        )
        _record_agent(
            observer,
            agents[-1],
            metadata={"status": status.value, "risk_score": score},
        )
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
        writer = ScanBundleWriter()
        bundle = writer.write(
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
                events=observer.events,
            )
        )
        _complete_phase(
            observer,
            "bundle_write",
            f"Wrote scan bundle to {bundle.output_folder}.",
            metadata={"output_folder": str(bundle.output_folder)},
        )
        writer.write_scan_log(bundle, observer.events)

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
            log_path=bundle.scan_log_path,
            trace=trace,
        )

    def agent_scan(self, request: ScanRequest) -> ScanReport:
        load_environment(request.repository_path)
        observer = _ensure_observer(
            request.observer,
            "difend agent-scan",
            AGENT_SCAN_PHASES,
        )
        _start_phase(observer, "diff_capture")
        diff = self._capture_diff(request)
        _complete_phase(
            observer,
            "diff_capture",
            _diff_capture_detail(diff),
            metadata=_diff_metadata(diff),
        )
        model = request.model or os.getenv("DIFEND_OPENAI_MODEL") or DEFAULT_MODEL
        observer.add_default_metadata({"model": model, "use_cache": request.use_cache})
        agentic_result = run_agentic_scan(
            request.repository_path,
            diff,
            model=model,
            use_cache=request.use_cache,
            observer=observer,
        )
        status = ScanStatus(agentic_result.status)
        writer = ScanBundleWriter()
        bundle = writer.write(
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
                events=observer.events,
            )
        )
        _complete_phase(
            observer,
            "bundle_write",
            f"Wrote scan bundle to {bundle.output_folder}.",
            metadata={"output_folder": str(bundle.output_folder)},
        )
        writer.write_scan_log(bundle, observer.events)

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
            log_path=bundle.scan_log_path,
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
    observer: ScanObserver | None = None,
) -> ScanReport:
    """Run deterministic Automated Gates through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        model=model,
        use_cache=use_cache,
        observer=observer,
    )
    return DifendSDK().scan(request)


def agent_scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    model: str | None = None,
    use_cache: bool = True,
    observer: ScanObserver | None = None,
) -> ScanReport:
    """Run the full agentic Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        model=model,
        use_cache=use_cache,
        observer=observer,
    )
    return DifendSDK().agent_scan(request)


def _start_phase(observer: ScanObserver | None, phase: str) -> None:
    if observer is not None:
        observer.start(phase)


def _complete_phase(
    observer: ScanObserver | None,
    phase: str,
    detail: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    if observer is not None:
        observer.complete(phase, detail, metadata=metadata)


def _record_agent(
    observer: ScanObserver | None,
    agent: AgentExecution,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    if observer is not None:
        observer.record_agent(agent, metadata=metadata)


def _ensure_observer(
    observer: ScanObserver | None,
    command: str,
    phases: tuple[str, ...],
) -> ScanObserver:
    active = observer or ScanObserver(command, phases)
    if not active.events:
        active.start_run(f"{command} started.")
    return active


def _diff_capture_detail(diff: CodeDiff) -> str:
    captured = []
    if diff.unstaged.strip():
        captured.append("unstaged")
    if diff.staged.strip():
        captured.append("staged")
    if diff.untracked.strip():
        captured.append("untracked")
    if not captured:
        return "No Git diff was captured."
    return f"Captured {', '.join(captured)} diff."


def _diff_metadata(diff: CodeDiff) -> dict[str, Any]:
    return {
        "has_changes": diff.has_changes,
        "unstaged_bytes": len(diff.unstaged.encode()),
        "staged_bytes": len(diff.staged.encode()),
        "untracked_bytes": len(diff.untracked.encode()),
    }
