from pathlib import Path

from difend.agents.graph import run_agentic_scan
from difend.agents.schemas import (
    DiffClassifierResult,
    GateValidationResult,
    HandoffResult,
    RiskArea,
    SecurityReasoningResult,
)
from difend.diff import CodeDiff


class FakeModel:
    model = "fake-model"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        if schema is DiffClassifierResult:
            return DiffClassifierResult(
                risk_areas=[RiskArea.LOW_RISK],
                reason="Fake low risk.",
                should_run_security_reasoning=False,
                used_llm=True,
            )
        if schema is GateValidationResult:
            return GateValidationResult(validations=[])
        if schema is SecurityReasoningResult:
            return SecurityReasoningResult(manual_review=[])
        if schema is HandoffResult:
            return HandoffResult(
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
