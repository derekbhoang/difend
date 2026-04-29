"""Security Reasoning Agent."""

from __future__ import annotations

from difend.agents.model import StructuredModelClient
from difend.agents.prompts import PROMPT_VERSION, SECURITY_REASONING_PROMPT
from difend.agents.schemas import (
    AgentExecution,
    AgentStatus,
    AutomatedGatesResult,
    DiffClassifierResult,
    ExpandedContext,
    ManualReviewItem,
    ScanContext,
    SecurityReasoningResult,
)
from difend.agents.utils import evidence_fingerprint, stable_short_hash


def run_security_reasoning(
    scan_context: ScanContext,
    classifier: DiffClassifierResult,
    gates: AutomatedGatesResult,
    expanded_context: ExpandedContext,
    model_client: StructuredModelClient | None,
) -> tuple[list[ManualReviewItem], AgentExecution]:
    if not classifier.should_run_security_reasoning:
        return [], AgentExecution(
            name="security_reasoning",
            status=AgentStatus.SKIPPED,
            detail="Classifier did not route contextual security reasoning.",
        )

    if model_client is None:
        return [], AgentExecution(
            name="security_reasoning",
            status=AgentStatus.SKIPPED,
            detail="No model client was provided.",
        )

    result = model_client.invoke_structured(
        SECURITY_REASONING_PROMPT,
        {
            "prompt_version": PROMPT_VERSION,
            "risk_areas": [area.value for area in classifier.risk_areas],
            "sensitive_files": classifier.sensitive_files,
            "patch": scan_context.patch,
            "expanded_context": [
                file.model_dump(mode="json") for file in expanded_context.files
            ],
            "automated_findings": [
                finding.model_dump(mode="json") for finding in gates.findings
            ],
        },
        SecurityReasoningResult,
        node_name="security_reasoning",
    )
    normalized = [_normalize_item(item) for item in result.manual_review]
    return normalized, AgentExecution(
        name="security_reasoning",
        status=AgentStatus.COMPLETED,
        used_llm=True,
        detail=f"Produced {len(normalized)} manual review item(s).",
    )


def _normalize_item(item: ManualReviewItem) -> ManualReviewItem:
    fingerprint = item.evidence_fingerprint or evidence_fingerprint(
        item.file,
        item.line,
        item.vulnerability_type,
        item.evidence,
    )
    item.evidence_fingerprint = fingerprint
    item.manual_review_id = item.manual_review_id or f"manual-{stable_short_hash(fingerprint)}"
    return item
