from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from difend.agent import AgentReviewError, review_scan_bundle


class FakeAgentClient:
    def __init__(self, output: dict[str, Any]) -> None:
        self.output = output
        self.prompt = ""

    def review(self, prompt: str) -> dict[str, Any]:
        self.prompt = prompt
        return self.output


class AgentReviewTests(unittest.TestCase):
    def test_review_scan_bundle_writes_agent_findings_and_updates_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_folder = Path(temp)
            _write_scan_bundle(run_folder)
            client = FakeAgentClient(
                {
                    "findings": [
                        {
                            "file": "app.py",
                            "line": 1,
                            "severity": "high",
                            "evidence": "eval(user_input)",
                            "recommendation": "Remove eval and use a safe parser.",
                            "confidence": "high",
                        }
                    ],
                    "solution_proposals": [
                        {
                            "file": "app.py",
                            "proposal": "Return the input or parse with ast.literal_eval.",
                            "suggested_tests": ["Add a test for untrusted input."],
                        }
                    ],
                    "findings_markdown": "# Agent-Confirmed Findings\n\n## app.py:1\n",
                    "solution_proposals_markdown": "# Solution Proposals\n\n## app.py\n",
                }
            )

            result = review_scan_bundle(run_folder, client=client)

            self.assertEqual(result.status, "manual review required")
            self.assertEqual(result.findings_count, 1)
            self.assertIn("report_json", client.prompt)
            self.assertIn("diff_patch", client.prompt)
            self.assertIn("Agent-Confirmed Findings", (run_folder / "findings.md").read_text(encoding="utf-8"))
            self.assertIn("Solution Proposals", (run_folder / "solution-proposals.md").read_text(encoding="utf-8"))

            report = json.loads((run_folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["findings"][0]["file"], "app.py")
            self.assertEqual(report["solution_proposals"][0]["file"], "app.py")
            self.assertEqual(report["agent_review"]["agent"], "codex-api")

    def test_review_scan_bundle_requires_report_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(AgentReviewError):
                review_scan_bundle(Path(temp), client=FakeAgentClient({}))


def _write_scan_bundle(run_folder: Path) -> None:
    (run_folder / "report.json").write_text(
        json.dumps(
            {
                "tool": "difend",
                "status": "manual review required",
                "rule_signals": [
                    {
                        "file": "app.py",
                        "line": 1,
                        "severity": "high",
                        "evidence": "eval(user_input)",
                        "gate": "injection risks",
                        "recommendation": "Review eval usage.",
                    }
                ],
                "findings": [],
                "solution_proposals": [],
            }
        ),
        encoding="utf-8",
    )
    (run_folder / "diff.patch").write_text(
        "diff --git a/app.py b/app.py\n+eval(user_input)\n",
        encoding="utf-8",
    )
    (run_folder / "context-signals.md").write_text(
        "# Context Signals\n\n- eval(user_input)\n",
        encoding="utf-8",
    )
    (run_folder / "manual-review.md").write_text(
        "# Manual Review\n",
        encoding="utf-8",
    )
    (run_folder / "findings.md").write_text("", encoding="utf-8")
    (run_folder / "solution-proposals.md").write_text("", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
