from __future__ import annotations

import re

from difend.models import DiffLine, ParsedDiff

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(diff_text: str) -> ParsedDiff:
    changed_files: list[str] = []
    added_lines: list[DiffLine] = []
    current_file: str | None = None
    new_line: int | None = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            current_file = _parse_diff_file(raw_line)
            new_line = None
            if current_file and current_file not in changed_files:
                changed_files.append(current_file)
            continue

        hunk_match = HUNK_RE.match(raw_line)
        if hunk_match:
            new_line = int(hunk_match.group(1))
            continue

        if current_file is None or new_line is None:
            continue

        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue

        if raw_line.startswith("+"):
            added_lines.append(
                DiffLine(
                    file=current_file,
                    line=new_line,
                    content=raw_line[1:],
                )
            )
            new_line += 1
            continue

        if raw_line.startswith(" "):
            new_line += 1

    return ParsedDiff(
        changed_files=tuple(changed_files),
        added_lines=tuple(added_lines),
    )


def _parse_diff_file(line: str) -> str | None:
    parts = line.split()
    if len(parts) < 4:
        return None
    path = parts[3]
    if path.startswith("b/"):
        return path[2:]
    return path
