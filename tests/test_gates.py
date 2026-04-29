from difend.agents.gates import find_gate_candidates, run_automated_gates
from difend.agents.schemas import LLMGateValidation, LLMGateValidationResult, Severity
from difend.agents.context import prepare_scan_context
from difend.diff import CodeDiff


class HallucinatingGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(
            validations=[
                LLMGateValidation(candidate_id="invented"),
            ]
        )


class EnrichingGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(
            validations=[
                LLMGateValidation(
                    candidate_id=payload["candidates"][0]["candidate_id"],
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    evidence="enriched evidence",
                    recommendation="enriched recommendation",
                )
            ]
        )


class EmptyGateModel:
    model = "fake"

    def invoke_structured(self, system_prompt, payload, schema, node_name):
        return LLMGateValidationResult(validations=[])


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


def test_gate_rules_detect_secret_keyword_inside_long_variable_name():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/model.py b/model.py\n"
                "--- a/model.py\n"
                "+++ b/model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+OPENAI_API_KEY_ENV_VAR = 'placeholder-secret-value'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].rule_id == "secret_scan"


def test_gate_rules_detect_openai_secret_like_value():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/model.py b/model.py\n"
                "--- a/model.py\n"
                "+++ b/model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+CONFIG_VALUE = 'sk-proj-placeholderplaceholderplaceholder'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates
    assert candidates[0].rule_id == "secret_value_scan"


def test_gate_llm_unknown_candidate_is_rejected():
    context = prepare_scan_context(_secret_diff())

    result, execution = run_automated_gates(context, HallucinatingGateModel())

    assert result.rejected_llm_outputs == ["invented"]
    assert result.findings
    assert execution.used_llm


def test_gate_llm_enriches_but_cannot_drop_candidates():
    context = prepare_scan_context(_secret_diff())

    empty_result, _ = run_automated_gates(context, EmptyGateModel())
    enriched_result, _ = run_automated_gates(context, EnrichingGateModel())

    assert len(empty_result.findings) == len(empty_result.candidates)
    assert empty_result.findings[0].gate_name == "secret_scan"
    assert enriched_result.findings[0].severity == Severity.CRITICAL
    assert enriched_result.findings[0].evidence == "enriched evidence"
    assert enriched_result.findings[0].gate_name == "secret_scan"


def test_marked_test_placeholder_secret_is_not_flagged():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/tests/test_model.py b/tests/test_model.py\n"
                "--- a/tests/test_model.py\n"
                "+++ b/tests/test_model.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+FAKE_OPENAI_API_KEY = 'sk-proj-placeholderplaceholderplaceholder'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates == []


def test_real_secret_like_value_in_production_code_is_flagged():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/src/config.py b/src/config.py\n"
                "--- a/src/config.py\n"
                "+++ b/src/config.py\n"
                "@@ -1,0 +1,1 @@\n"
                "+CONFIG_VALUE = 'sk-proj-livevaluewithmanycharacters'\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert [candidate.rule_id for candidate in candidates] == ["secret_value_scan"]


def test_dependency_finding_includes_gate_name():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/requirements.txt b/requirements.txt\n"
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -1,0 +1,1 @@\n"
                "+requests==2.32.0\n"
            ),
            staged="",
        )
    )

    result, _ = run_automated_gates(context, None)

    assert result.findings
    assert result.findings[0].vulnerability_type == "dependency_risk"
    assert result.findings[0].gate_name == "dependency_change"


def test_scanner_regex_definitions_are_not_flagged_as_crypto_or_auth_bypass():
    context = prepare_scan_context(
        CodeDiff(
            unstaged=(
                "diff --git a/difend/agents/gates.py b/difend/agents/gates.py\n"
                "--- a/difend/agents/gates.py\n"
                "+++ b/difend/agents/gates.py\n"
                "@@ -1,0 +1,2 @@\n"
                "+WEAK_CRYPTO_RE = re.compile(r'(?i)\\\\b(md5|sha1|des|rc4)\\\\b')\n"
                "+DISABLED_AUTH_RE = re.compile(r'auth.*(false|skip|bypass)')\n"
            ),
            staged="",
        )
    )

    candidates = find_gate_candidates(context)

    assert candidates == []
