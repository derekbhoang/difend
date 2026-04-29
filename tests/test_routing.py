from pathlib import Path

from difend.agents.graph import AgenticScanError, run_agentic_scan
from difend.diff import CodeDiff


def test_low_risk_diff_does_not_require_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
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

    result = run_agentic_scan(tmp_path, diff, use_cache=False)

    assert result.status == "pass"
    assert all(agent.used_llm is False for agent in result.agents)


def test_sensitive_diff_without_api_key_fails_clearly(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    diff = CodeDiff(
        unstaged=(
            "diff --git a/auth.py b/auth.py\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+is_admin = False  # bypass auth\n"
        ),
        staged="",
    )

    try:
        run_agentic_scan(tmp_path, diff, use_cache=False)
    except AgenticScanError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("Expected AgenticScanError")
