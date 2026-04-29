"""Parse Git unified diffs into structured file and hunk data."""

from __future__ import annotations

import re
from typing import Any

from difend.diff import CodeDiff


HUNK_HEADER_RE = re.compile(
    r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


def parse_code_diff(diff: CodeDiff) -> dict[str, Any]:
    """Parse staged and unstaged diff text into structured sections."""

    unstaged = parse_unified_diff(diff.unstaged)
    staged = parse_unified_diff(diff.staged)

    return {
        "unstaged": {
            "files": unstaged,
            "summary": summarize_files(unstaged),
        },
        "staged": {
            "files": staged,
            "summary": summarize_files(staged),
        },
        "summary": summarize_sections(unstaged, staged),
    }


def parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    """Parse a unified diff into files, hunks, and grouped line blocks."""

    files = []
    current_file = None
    current_hunk = None
    old_line = None
    new_line = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_file:
                files.append(current_file)
            current_file = make_file_diff()
            current_hunk = None
            old_line = None
            new_line = None
            continue

        if current_file is None:
            continue

        if line.startswith("--- "):
            current_file["old_path"] = clean_diff_path(line[4:])
            continue

        if line.startswith("+++ "):
            current_file["new_path"] = clean_diff_path(line[4:])
            continue

        if line.startswith("@@ "):
            current_hunk = make_hunk(line)
            current_file["hunks"].append(current_hunk)
            old_line = current_hunk["old_start"]
            new_line = current_hunk["new_start"]
            continue

        if current_hunk is None or old_line is None or new_line is None:
            continue

        if line.startswith("+"):
            current_hunk["added"].append(
                {
                    "line": new_line,
                    "content": line[1:],
                }
            )
            new_line += 1
            continue

        if line.startswith("-"):
            current_hunk["removed"].append(
                {
                    "line": old_line,
                    "content": line[1:],
                }
            )
            old_line += 1
            continue

        if line.startswith(" "):
            current_hunk["context"].append(
                {
                    "old_line": old_line,
                    "new_line": new_line,
                    "content": line[1:],
                }
            )
            old_line += 1
            new_line += 1

    if current_file:
        files.append(current_file)

    return group_parsed_diff(files)


def clean_diff_path(path: str) -> str:
    path = path.strip()
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def make_file_diff(old_path: str | None = None, new_path: str | None = None) -> dict[str, Any]:
    return {
        "old_path": old_path,
        "new_path": new_path,
        "path": new_path or old_path,
        "hunks": [],
    }


def make_hunk(header: str) -> dict[str, Any]:
    match = HUNK_HEADER_RE.search(header)
    if not match:
        raise ValueError(f"Unsupported hunk header: {header}")

    old_start = int(match.group(1))
    old_count = int(match.group(2) or "1")
    new_start = int(match.group(3))
    new_count = int(match.group(4) or "1")

    return {
        "header": header,
        "old_start": old_start,
        "old_count": old_count,
        "new_start": new_start,
        "new_count": new_count,
        "added": [],
        "removed": [],
        "context": [],
    }


def group_parsed_diff(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for file_diff in files:
        file_diff["path"] = file_diff["new_path"] or file_diff["old_path"]
        for hunk in file_diff["hunks"]:
            hunk["added"] = group_changed_line_blocks(hunk["added"])
            hunk["removed"] = group_changed_line_blocks(hunk["removed"])
            hunk["context"] = group_context_blocks(hunk["context"])
    return files


def group_changed_line_blocks(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = []
    current_block = None
    previous_line = None

    for item in lines:
        content = item["content"]
        if not content.strip():
            continue

        line_number = item["line"]
        if current_block and previous_line is not None and line_number == previous_line + 1:
            current_block["end_line"] = line_number
            current_block["line_range"] = make_line_range(current_block["start_line"], line_number)
            current_block["content"].append(content)
        else:
            current_block = {
                "line_range": str(line_number),
                "start_line": line_number,
                "end_line": line_number,
                "content": [content],
            }
            blocks.append(current_block)

        previous_line = line_number

    return blocks


def group_context_blocks(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = []
    current_block = None
    previous_old_line = None
    previous_new_line = None

    for item in lines:
        content = item["content"]
        if not content.strip():
            continue

        old_line = item["old_line"]
        new_line = item["new_line"]
        is_adjacent = (
            current_block
            and previous_old_line is not None
            and previous_new_line is not None
            and old_line == previous_old_line + 1
            and new_line == previous_new_line + 1
        )

        if is_adjacent:
            current_block["old_end_line"] = old_line
            current_block["new_end_line"] = new_line
            current_block["old_line_range"] = make_line_range(current_block["old_start_line"], old_line)
            current_block["new_line_range"] = make_line_range(current_block["new_start_line"], new_line)
            current_block["content"].append(content)
        else:
            current_block = {
                "old_line_range": str(old_line),
                "new_line_range": str(new_line),
                "old_start_line": old_line,
                "old_end_line": old_line,
                "new_start_line": new_line,
                "new_end_line": new_line,
                "content": [content],
            }
            blocks.append(current_block)

        previous_old_line = old_line
        previous_new_line = new_line

    return blocks


def make_line_range(start_line: int, end_line: int) -> str:
    if start_line == end_line:
        return str(start_line)
    return f"{start_line}-{end_line}"


def summarize_sections(
    unstaged_files: list[dict[str, Any]],
    staged_files: list[dict[str, Any]],
) -> dict[str, Any]:
    unstaged = summarize_files(unstaged_files)
    staged = summarize_files(staged_files)
    paths = sorted(set(unstaged["paths"] + staged["paths"]))

    return {
        "file_count": len(paths),
        "hunk_count": unstaged["hunk_count"] + staged["hunk_count"],
        "added_lines": unstaged["added_lines"] + staged["added_lines"],
        "removed_lines": unstaged["removed_lines"] + staged["removed_lines"],
        "context_lines": unstaged["context_lines"] + staged["context_lines"],
        "paths": paths,
    }


def summarize_files(files: list[dict[str, Any]]) -> dict[str, Any]:
    paths = [file_diff["path"] for file_diff in files if file_diff.get("path")]

    return {
        "file_count": len(files),
        "hunk_count": sum(len(file_diff["hunks"]) for file_diff in files),
        "added_lines": sum(count_block_lines(hunk["added"]) for file_diff in files for hunk in file_diff["hunks"]),
        "removed_lines": sum(count_block_lines(hunk["removed"]) for file_diff in files for hunk in file_diff["hunks"]),
        "context_lines": sum(count_block_lines(hunk["context"]) for file_diff in files for hunk in file_diff["hunks"]),
        "paths": paths,
    }


def count_block_lines(blocks: list[dict[str, Any]]) -> int:
    return sum(len(block["content"]) for block in blocks)
