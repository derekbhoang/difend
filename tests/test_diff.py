import subprocess
from pathlib import Path

from difend.diff import GitDiffCapture


def test_git_diff_capture_decodes_non_utf8_output_with_replacement(
    tmp_path: Path,
    monkeypatch,
):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="diff --git a/app.py b/app.py\n+\ufffd\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    diff = GitDiffCapture(tmp_path)._run_git(["diff"])

    assert "\ufffd" in diff
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"
