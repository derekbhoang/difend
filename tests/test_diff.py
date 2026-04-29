from __future__ import annotations

import unittest

from difend.diff import CodeDiff, parse_code_diff, parse_diff


class DiffParsingTests(unittest.TestCase):
    def test_parse_diff_tracks_changed_files_and_added_lines(self) -> None:
        parsed = parse_diff(
            """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,0 +1,2 @@
+print("hello")
+eval(user_input)
"""
        )

        self.assertEqual(parsed.changed_files, ("app.py",))
        self.assertEqual(len(parsed.added_lines), 2)
        self.assertEqual(parsed.added_lines[0].file, "app.py")
        self.assertEqual(parsed.added_lines[0].line, 1)
        self.assertEqual(parsed.added_lines[0].content, 'print("hello")')
        self.assertEqual(parsed.added_lines[1].line, 2)

    def test_parse_code_diff_combines_staged_and_unstaged_content(self) -> None:
        parsed = parse_code_diff(
            CodeDiff(
                unstaged="""diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,0 +1,1 @@
+print("unstaged")
""",
                staged="""diff --git a/settings.py b/settings.py
--- a/settings.py
+++ b/settings.py
@@ -1,0 +1,1 @@
+TOKEN = "abc123456789secret"
""",
            )
        )

        self.assertEqual(parsed.changed_files, ("app.py", "settings.py"))
        self.assertEqual(len(parsed.added_lines), 2)


if __name__ == "__main__":
    unittest.main()
