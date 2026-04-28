import unittest

from difend.diff import parse_diff
from difend.gates import (
    check_auth_permission_changes,
    check_dependency_changes,
    check_injection_risks,
    check_secrets,
)


class GatesTest(unittest.TestCase):
    def test_secret_gate_finds_added_secret(self):
        parsed = parse_diff(
            """diff --git a/settings.py b/settings.py
--- a/settings.py
+++ b/settings.py
@@ -0,0 +1 @@
+API_KEY = "abc123456789secret"
"""
        )

        findings = check_secrets(parsed)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].gate, "secrets")
        self.assertEqual(findings[0].severity, "critical")


    def test_dependency_gate_flags_manifest_change(self):
        parsed = parse_diff(
            """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -0,0 +1 @@
+dependencies = []
"""
        )

        findings = check_dependency_changes(parsed)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "pyproject.toml")


    def test_injection_gate_flags_risky_added_line(self):
        parsed = parse_diff(
            """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+eval(user_input)
"""
        )

        findings = check_injection_risks(parsed)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].gate, "injection risks")


    def test_auth_gate_requires_manual_review(self):
        parsed = parse_diff(
            """diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -0,0 +1 @@
+if user.role == "admin":
"""
        )

        items = check_auth_permission_changes(parsed)

        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(items[0].gate, "auth and permission changes")


if __name__ == "__main__":
    unittest.main()
