from pathlib import Path

from difend.agents.graph import run_agentic_scan
from difend.agents.schemas import (
    LLMDiffClassifierResult,
    LLMGateValidationResult,
    LLMHandoffResult,
    LLMSecurityReasoningResult,
    RiskArea,
)
from difend.diff import CodeDiff


class FakeModel:
    model = "fake-model"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        if schema is LLMDiffClassifierResult:
            return LLMDiffClassifierResult(
                risk_areas=[RiskArea.LOW_RISK],
                reason="Fake low risk.",
                should_run_security_reasoning=False,
            )
        if schema is LLMGateValidationResult:
            return LLMGateValidationResult(validations=[])
        if schema is LLMSecurityReasoningResult:
            return LLMSecurityReasoningResult(manual_review=[])
        if schema is LLMHandoffResult:
            return LLMHandoffResult(
                inspect_next=[],
                codex_tasks=["Review complete."],
                checklist=["Inspect report."],
                safest_next_action="Proceed with normal review.",
            )
        raise AssertionError(f"Unexpected schema: {schema}")


def test_no_diff_scan_skips_llm_and_passes(tmp_path: Path):
    result = run_agentic_scan(
        tmp_path,
        CodeDiff(unstaged="", staged="", untracked=""),
        model_client=None,
        use_cache=False,
    )

    assert result.status == "pass"
    assert result.scan_context.has_changes is False
    assert all(agent.used_llm is False for agent in result.agents)


def test_low_risk_routing_skips_security_reasoning(tmp_path: Path):
    diff = CodeDiff(
        unstaged=(
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,0 +1,1 @@\n"
            "+Docs only.\n"
        ),
        staged="",
    )

    result = run_agentic_scan(
        tmp_path,
        diff,
        model_client=FakeModel(),
        use_cache=False,
    )

    assert result.status == "pass"
    assert result.classifier.risk_areas == [RiskArea.LOW_RISK]
    assert any(
        agent.name == "security_reasoning" and agent.status.value == "skipped"
        for agent in result.agents
    ) is False
    assert result.trace["cache_lookup"]["hit"] is False


def test_cache_hit_after_classifier_and_context_expansion(tmp_path: Path):
    diff = CodeDiff(
        unstaged=(
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,0 +1,1 @@\n"
            "+Docs only.\n"
        ),
        staged="",
    )

    first = run_agentic_scan(tmp_path, diff, model_client=None, use_cache=True)
    second = run_agentic_scan(tmp_path, diff, model_client=None, use_cache=True)

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert second.trace["cache_lookup"]["hit"] is True
    assert [agent.name for agent in second.agents][:5] == [
        "prepare_scan_context",
        "diff_classifier",
        "orchestrator_route",
        "context_expansion",
        "cache_lookup",
    ]
