from pathlib import Path

from difend.agents.context import ContextLimits, expand_context, prepare_scan_context
from difend.agents.schemas import DiffClassifierResult, RiskArea
from difend.diff import CodeDiff


def test_prepare_scan_context_parses_added_lines():
    diff = CodeDiff(
        unstaged=(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+print('hello')\n"
            "+token = 'abc'\n"
        ),
        staged="",
    )

    context = prepare_scan_context(diff)

    assert context.has_changes
    assert context.changed_files[0].path == "app.py"
    assert [line.line for line in context.added_lines] == [1, 2]


def test_context_expansion_respects_total_cap(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("\n".join(f"line {index}" for index in range(1000)), encoding="utf-8")
    diff = CodeDiff(
        unstaged=(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -500,0 +500,1 @@\n"
            "+authorize(user)\n"
        ),
        staged="",
    )
    context = prepare_scan_context(diff)
    classifier = DiffClassifierResult(
        risk_areas=[RiskArea.AUTHORIZATION],
        should_run_security_reasoning=True,
    )

    expanded = expand_context(
        tmp_path,
        context,
        classifier,
        ContextLimits(max_files=4, max_bytes_per_file=200, max_total_bytes=250),
    )

    assert expanded.total_bytes <= 250
    assert len(expanded.files) <= 4
