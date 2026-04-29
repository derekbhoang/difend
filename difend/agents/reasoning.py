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
    LLMSecurityReasoningItem,
    LLMSecurityReasoningResult,
    ManualReviewItem,
    ScanContext,
)
from difend.agents.utils import evidence_fingerprint, stable_short_hash


def run_security_reasoning(
    scan_context: ScanContext,
    classifier: DiffClassifierResult,
    gates: AutomatedGatesResult,
    expanded_context: ExpandedContext,
    model_client: StructuredModelClient | None,
) -> tuple[list[ManualReviewItem], AgentExecution, LLMSecurityReasoningResult | None]:
    if not classifier.should_run_security_reasoning:
        return [], AgentExecution(
            name="security_reasoning",
            status=AgentStatus.SKIPPED,
            detail="Classifier did not route contextual security reasoning.",
        ), None

    if model_client is None:
        return [], AgentExecution(
            name="security_reasoning",
            status=AgentStatus.SKIPPED,
            detail="No model client was provided.",
        ), None

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
        LLMSecurityReasoningResult,
        node_name="security_reasoning",
    )
    normalized = [_normalize_item(item) for item in result.manual_review]
    return normalized, AgentExecution(
        name="security_reasoning",
        status=AgentStatus.COMPLETED,
        used_llm=True,
        detail=f"Produced {len(normalized)} manual review item(s).",
    ), result


def _normalize_item(item: LLMSecurityReasoningItem) -> ManualReviewItem:
    fingerprint = evidence_fingerprint(
        item.file,
        item.line,
        item.vulnerability_type,
        item.evidence,
    )
    return ManualReviewItem(
        manual_review_id=f"manual-{stable_short_hash(fingerprint)}",
        area=item.area,
        vulnerability_type=item.vulnerability_type,
        risk_level=item.risk_level,
        confidence=item.confidence,
        file=item.file,
        line=item.line,
        reason=item.reason,
        evidence=item.evidence,
        questions=item.questions,
        evidence_fingerprint=fingerprint,
        source="security_reasoning",
    )
