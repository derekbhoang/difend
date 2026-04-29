from __future__ import annotations

import unittest

from difend.diff import parse_diff
from difend.gates import (
    SEVERITY_MANUAL_REVIEW,
    AuthPermissionGate,
    DependencyChangeGate,
    GateRunner,
    InjectionPatternGate,
    SecretsGate,
)


class GateTests(unittest.TestCase):
    def test_secrets_gate_flags_secret_added_lines(self) -> None:
        signals = SecretsGate().run(
            parse_diff(
                """diff --git a/settings.py b/settings.py
--- a/settings.py
+++ b/settings.py
@@ -1,0 +1,1 @@
+API_KEY = "abc123456789secret"
"""
            )
        )

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].gate, "secrets")
        self.assertEqual(signals[0].severity, "critical")
        self.assertEqual(signals[0].file, "settings.py")
        self.assertIn("[redacted]", signals[0].evidence)

    def test_dependency_gate_flags_dependency_file_added_lines(self) -> None:
        signals = DependencyChangeGate().run(
            parse_diff(
                """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1,0 +1,1 @@
+dependencies = ["requests==2.32.0"]
"""
            )
        )

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].gate, "dependency changes")
        self.assertEqual(signals[0].severity, "medium")
        self.assertEqual(signals[0].line, 1)

    def test_injection_gate_flags_simple_injection_patterns(self) -> None:
        signals = InjectionPatternGate().run(
            parse_diff(
                """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +1,1 @@
+eval(user_input)
"""
            )
        )

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].gate, "injection risks")
        self.assertEqual(signals[0].severity, "high")

    def test_auth_gate_marks_security_sensitive_changes_for_manual_review(self) -> None:
        signals = AuthPermissionGate().run(
            parse_diff(
                """diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,0 +1,1 @@
+def allow_admin_role(user): return user.role == "admin"
"""
            )
        )

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].gate, "auth and permission changes")
        self.assertEqual(signals[0].severity, SEVERITY_MANUAL_REVIEW)
        self.assertTrue(signals[0].requires_manual_review)

    def test_gate_runner_combines_results_and_reports_progress(self) -> None:
        progress: list[tuple[str, str]] = []
        parsed = parse_diff(
            """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +1,1 @@
+eval(user_input)
"""
        )

        report = GateRunner().run(parsed, progress=lambda label, status: progress.append((label, status)))

        self.assertTrue(report.rule_signals)
        self.assertEqual(len(report.gate_results), 4)
        self.assertEqual(report.gate_results[2].signals_count, 1)
        self.assertIn(("Checking injection risks", "warning"), progress)
        self.assertIn(("Checking auth and permission changes", "done"), progress)


if __name__ == "__main__":
    unittest.main()
