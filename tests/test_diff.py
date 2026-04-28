import unittest

from difend.diff import parse_diff


class DiffParserTest(unittest.TestCase):
    def test_parse_diff_tracks_changed_files_and_added_lines(self):
        parsed = parse_diff(
            """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,0 +2,2 @@
+API_KEY = "abc123456789secret"
+print("hello")
"""
        )

        self.assertEqual(parsed.changed_files, ("app.py",))
        self.assertEqual(parsed.added_lines[0].file, "app.py")
        self.assertEqual(parsed.added_lines[0].line, 2)
        self.assertEqual(
            parsed.added_lines[0].content, 'API_KEY = "abc123456789secret"'
        )


if __name__ == "__main__":
    unittest.main()
