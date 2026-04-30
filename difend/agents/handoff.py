"""Handoff Agent that creates follow-up instructions only."""

from __future__ import annotations

from difend.agents.model import StructuredModelClient
from difend.agents.prompts import HANDOFF_PROMPT, PROMPT_VERSION
from difend.agents.schemas import (
    AgentExecution,
    AgentStatus,
    DiffClassifierResult,
    Finding,
    HandoffResult,
    LLMHandoffResult,
    ManualReviewItem,
    ScanContext,
)


def run_handoff(
    scan_context: ScanContext,
    classifier: DiffClassifierResult,
    findings: list[Finding],
    manual_review: list[ManualReviewItem],
    status: str,
    model_client: StructuredModelClient | None,
) -> tuple[HandoffResult, AgentExecution]:
    if not scan_context.has_changes:
        return HandoffResult(
            inspect_next=[],
            codex_tasks=["No code diff was captured; continue normal development."],
            checklist=["Confirm there were no intended uncommitted changes."],
            safest_next_action="No security action is needed because no diff was scanned.",
        ), AgentExecution(
            name="handoff",
            status=AgentStatus.COMPLETED,
            detail="Generated deterministic no-diff handoff.",
        )

    if model_client is None:
        return _deterministic_handoff(findings, manual_review, status), AgentExecution(
            name="handoff",
            status=AgentStatus.COMPLETED,
            detail="Generated deterministic handoff without LLM.",
        )

    result = model_client.invoke_structured(
        HANDOFF_PROMPT,
        {
            "prompt_version": PROMPT_VERSION,
            "status": status,
            "risk_areas": [area.value for area in classifier.risk_areas],
            "changed_files": [file.path for file in scan_context.changed_files],
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "manual_review": [item.model_dump(mode="json") for item in manual_review],
        },
        LLMHandoffResult,
        node_name="handoff",
    )
    return _normalize_handoff(result), AgentExecution(
        name="handoff",
        status=AgentStatus.COMPLETED,
        used_llm=True,
        detail="Generated handoff from merged scan result.",
    )


def _deterministic_handoff(
    findings: list[Finding],
    manual_review: list[ManualReviewItem],
    status: str,
) -> HandoffResult:
    files = sorted({item.file for item in [*findings, *manual_review] if item.file})
    tasks: list[str] = []
    if findings:
        tasks.append("Fix the concrete Automated Gates findings before merge.")
    if manual_review:
        tasks.append("Review each manual-review item with the surrounding application context.")
    if not tasks:
        tasks.append("No security follow-up tasks were generated.")
    return HandoffResult(
        inspect_next=files,
        codex_tasks=tasks,
        checklist=[
            "Inspect diff.patch first.",
            "Confirm each listed finding or manual-review item.",
            "Add or update tests for any security-sensitive behavior.",
        ],
        safest_next_action=(
            "Do not merge until findings are fixed."
            if status == "fail"
            else "Proceed after manual review is complete."
            if status == "manual review required"
            else "Proceed with normal review."
        ),
    )


def _normalize_handoff(result: LLMHandoffResult) -> HandoffResult:
    return HandoffResult(
        inspect_next=result.inspect_next,
        codex_tasks=result.codex_tasks,
        checklist=result.checklist,
        safest_next_action=result.safest_next_action,
    )
