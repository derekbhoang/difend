from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from difend.sdk import ScanStatus, scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ScanCommandTests(unittest.TestCase):
    def test_scan_writes_bundle_with_automated_gate_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            _init_repo(repo)

            (repo / "app.py").write_text("eval(user_input)\n", encoding="utf-8")

            progress: list[tuple[str, str]] = []
            report = scan(
                repository_path=repo,
                progress=lambda label, status: progress.append((label, status)),
            )

            self.assertEqual(report.status, ScanStatus.MANUAL_REVIEW_REQUIRED)
            self.assertEqual(len(report.rule_signals), 1)
            self.assertEqual(report.rule_signals[0].gate, "injection risks")
            self.assertTrue((report.output_folder / "summary.md").exists())
            self.assertTrue((report.output_folder / "context-signals.md").exists())
            self.assertTrue((report.output_folder / "findings.md").exists())
            self.assertTrue((report.output_folder / "manual-review.md").exists())
            self.assertTrue((report.output_folder / "solution-proposals.md").exists())
            self.assertTrue((report.output_folder / "codex-instructions.md").exists())
            self.assertTrue((report.output_folder / "diff.patch").exists())
            self.assertTrue((report.output_folder / "report.json").exists())
            self.assertIn(("Checking git diff", "done"), progress)
            self.assertIn(("Checking injection risks", "warning"), progress)

            report_json = json.loads(
                (report.output_folder / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report_json["status"], "manual review required")
            self.assertEqual(report_json["tool"], "difend")
            self.assertEqual(report_json["rule_signals"][0]["gate"], "injection risks")
            self.assertEqual(report_json["findings"], [])
            self.assertEqual(report_json["diff"]["changed_files"], ["app.py"])
            self.assertEqual(report_json["checks"][2]["signals_count"], 1)

            context_signals = (
                report.output_folder / "context-signals.md"
            ).read_text(encoding="utf-8")
            self.assertIn("Context Signals", context_signals)
            self.assertIn("eval(user_input)", context_signals)

            findings_markdown = (
                report.output_folder / "findings.md"
            ).read_text(encoding="utf-8")
            self.assertIn("No agent-confirmed findings", findings_markdown)

            codex_instructions = (
                report.output_folder / "codex-instructions.md"
            ).read_text(encoding="utf-8")
            self.assertIn("Codex Handoff Prompt", codex_instructions)
            self.assertIn("Read `report.json` first", codex_instructions)

    def test_scan_cli_prints_progress_and_writes_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            _init_repo(repo)

            (repo / "auth.py").write_text(
                "def can_login(user): return user.session is not None\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = (
                f"{PROJECT_ROOT}{os.pathsep}{env['PYTHONPATH']}"
                if env.get("PYTHONPATH")
                else str(PROJECT_ROOT)
            )

            result = subprocess.run(
                [sys.executable, "-m", "difend", "scan"],
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Difend scan started", result.stdout)
            self.assertIn("Checking git diff... done", result.stdout)
            self.assertIn(
                "Checking auth and permission changes... manual review required",
                result.stdout,
            )
            self.assertIn("Status: manual review required", result.stdout)
            self.assertTrue(any((repo / ".difend" / "runs").iterdir()))


def _init_repo(repo: Path) -> None:
    _git(repo, "init")
    (repo / "README.md").write_text("# fixture\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Difend Tests",
        "-c",
        "user.email=difend-tests@example.com",
        "commit",
        "-m",
        "initial",
    )


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)

    return result.stdout


if __name__ == "__main__":
    unittest.main()
