from difend.agents.gates import find_gate_candidates, run_automated_gates
from difend.agents.schemas import GateValidation, GateValidationResult
from difend.agents.context import prepare_scan_context
from difend.diff import CodeDiff


class HallucinatingGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return GateValidationResult(
            validations=[
                GateValidation(candidate_id="invented", confirmed=True),
            ]
        )


def _secret_diff():
    return CodeDiff(
        unstaged=(
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+OPENAI_API_KEY = 'sk-this-is-a-secret'\n"
        ),
        staged="",
    )


def test_gate_rules_create_candidates():
    context = prepare_scan_context(_secret_diff())

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].vulnerability_type == "hardcoded_secret"


def test_gate_llm_unknown_candidate_is_rejected():
    context = prepare_scan_context(_secret_diff())

    result, execution = run_automated_gates(context, HallucinatingGateModel())

    assert result.rejected_llm_outputs == ["invented"]
    assert result.findings
    assert execution.used_llm
