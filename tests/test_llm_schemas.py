import pytest

from difend.agents.reasoning import run_security_reasoning
from difend.agents.schemas import (
    AutomatedGatesResult,
    DiffClassifierResult,
    ExpandedContext,
    LLMGateValidation,
    LLMHandoffResult,
    LLMSecurityReasoningResult,
    LLMSecurityReasoningItem,
    RiskArea,
    ScanContext,
    Severity,
)


def test_llm_schemas_do_not_trust_internal_ids_or_fingerprints():
    reasoning_fields = set(LLMSecurityReasoningItem.model_fields)
    gate_fields = set(LLMGateValidation.model_fields)
    handoff_fields = set(LLMHandoffResult.model_fields)

    assert "finding_id" not in reasoning_fields
    assert "manual_review_id" not in reasoning_fields
    assert "evidence_fingerprint" not in reasoning_fields
    assert "finding_id" not in gate_fields
    assert "evidence_fingerprint" not in gate_fields
    assert "finding_id" not in handoff_fields
    with pytest.raises(ValueError):
        LLMSecurityReasoningItem.model_validate(
            {
                "area": "authorization",
                "vulnerability_type": "authorization",
                "risk_level": "high",
                "confidence": 0.8,
                "file": "routes/admin.py",
                "line": 42,
                "reason": "Authorization logic changed.",
                "evidence": "admin check removed",
                "questions": [],
                "evidence_fingerprint": "model-supplied",
            }
        )


class ReasoningModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMSecurityReasoningResult(
            manual_review=[
                LLMSecurityReasoningItem(
                    area=RiskArea.AUTHORIZATION,
                    vulnerability_type="authorization",
                    risk_level=Severity.HIGH,
                    confidence=0.8,
                    file="routes/admin.py",
                    line=42,
                    reason="Authorization logic changed.",
                    evidence="admin check removed",
                    questions=["Is this protected elsewhere?"],
                )
            ]
        )


def test_reasoning_normalization_generates_internal_ids_and_fingerprints():
    scan_context = ScanContext(
        patch="diff",
        changed_files=[],
        added_lines=[],
        diff_hash="diff-hash",
    )
    classifier = DiffClassifierResult(
        risk_areas=[RiskArea.AUTHORIZATION],
        should_run_security_reasoning=True,
    )

    manual_review, execution, raw = run_security_reasoning(
        scan_context,
        classifier,
        AutomatedGatesResult(),
        ExpandedContext(),
        ReasoningModel(),
    )

    assert execution.used_llm is True
    assert raw is not None
    assert manual_review[0].manual_review_id.startswith("manual-")
    assert manual_review[0].evidence_fingerprint
