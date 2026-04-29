import re


HUNK_HEADER_RE = re.compile(
    r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


def clean_diff_path(path):
    path = path.strip()
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def make_line_range(start_line, end_line):
    if start_line == end_line:
        return str(start_line)
    return f"{start_line}-{end_line}"


def make_file_diff(old_path=None, new_path=None):
    return {
        "old_path": old_path,
        "new_path": new_path,
        "hunks": [],
    }


def make_hunk(header):
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


def group_changed_line_blocks(lines):
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


def group_context_blocks(lines):
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


def group_hunk_lines(hunk):
    hunk["added"] = group_changed_line_blocks(hunk["added"])
    hunk["removed"] = group_changed_line_blocks(hunk["removed"])
    hunk["context"] = group_context_blocks(hunk["context"])
    return hunk


def group_parsed_diff(files):
    for file_diff in files:
        for hunk in file_diff["hunks"]:
            group_hunk_lines(hunk)
    return files


def parse_unified_diff(diff_text):
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
