import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from difend.cli import main
from difend.models import STATUS_FAIL, STATUS_MANUAL_REVIEW, STATUS_PASS
from difend.scanner import scan_repository


class ScannerTest(unittest.TestCase):
    def test_empty_diff_creates_pass_report(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))

            result = scan_repository(repo, run_id="2026-04-29-000001")

            self.assertEqual(result.status, STATUS_PASS)
            self.assertTrue((result.output_path / "summary.md").exists())
            self.assertTrue((result.output_path / "findings.md").exists())
            self.assertTrue((result.output_path / "manual-review.md").exists())
            self.assertTrue((result.output_path / "codex-instructions.md").exists())
            self.assertTrue((result.output_path / "diff.patch").exists())
            self.assertTrue((result.output_path / "report.json").exists())


    def test_scan_captures_staged_and_unstaged_diffs(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))
            tracked = repo / "app.py"
            tracked.write_text("print('base')\nprint('unstaged')\n", encoding="utf-8")
            new_file = repo / "settings.py"
            new_file.write_text('API_KEY = "abc123456789secret"\n', encoding="utf-8")
            git(repo, "add", "settings.py")

            result = scan_repository(repo, run_id="2026-04-29-000002")

            self.assertEqual(result.status, STATUS_FAIL)
            self.assertIn("# Unstaged diff", result.diff)
            self.assertIn("# Staged diff", result.diff)
            self.assertIn("print('unstaged')", result.diff)
            self.assertIn("API_KEY", result.diff)

    def test_scan_captures_untracked_text_files(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))
            untracked = repo / "new_auth.py"
            untracked.write_text(
                "def check_permission(user):\n    return True\n", encoding="utf-8"
            )

            result = scan_repository(repo, run_id="2026-04-29-000005")

            self.assertEqual(result.status, STATUS_MANUAL_REVIEW)
            self.assertIn("# Untracked files diff", result.diff)
            self.assertIn("new_auth.py", result.diff)


    def test_scan_marks_dependency_change_for_manual_review(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))
            pyproject = repo / "pyproject.toml"
            pyproject.write_text("[project]\ndependencies = []\n", encoding="utf-8")
            git(repo, "add", "pyproject.toml")

            result = scan_repository(repo, run_id="2026-04-29-000003")

            self.assertEqual(result.status, STATUS_MANUAL_REVIEW)
            self.assertEqual(result.findings[0].gate, "dependency changes")


    def test_scan_marks_auth_change_for_manual_review(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))
            auth = repo / "auth.py"
            auth.write_text(
                'if user.role == "admin":\n    return True\n', encoding="utf-8"
            )
            git(repo, "add", "auth.py")

            result = scan_repository(repo, run_id="2026-04-29-000004")

            self.assertEqual(result.status, STATUS_MANUAL_REVIEW)
            self.assertTrue(result.manual_review_items)


    def test_cli_scan_returns_manual_review_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = init_repo(Path(temp))
            auth = repo / "auth.py"
            auth.write_text('session["user_id"] = user.id\n', encoding="utf-8")
            git(repo, "add", "auth.py")
            original_cwd = Path.cwd()
            output = io.StringIO()

            try:
                os.chdir(repo)
                with contextlib.redirect_stdout(output):
                    exit_code = main(["scan"])
            finally:
                os.chdir(original_cwd)

            text = output.getvalue()
            self.assertEqual(exit_code, 2)
            self.assertIn("Checking git diff... done", text)
            self.assertIn("Status: manual review required", text)
            self.assertIn(".difend", text)


def init_repo(path: Path) -> Path:
    git(path, "init")
    git(path, "config", "user.email", "difend@example.test")
    git(path, "config", "user.name", "Difend Test")
    base = path / "app.py"
    base.write_text("print('base')\n", encoding="utf-8")
    git(path, "add", "app.py")
    git(path, "commit", "-m", "initial")
    return path


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=path,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


if __name__ == "__main__":
    unittest.main()
