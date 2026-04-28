import datetime as dt
import json
import re
import subprocess
from pathlib import Path


REPO_PATH = Path(__file__).resolve().parent
DEFAULT_CONTEXT_LINES = 3
RUNS_ROOT = REPO_PATH / ".difend" / "runs"


HUNK_HEADER_RE = re.compile(
    r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
)


def run_git_command(args):
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_PATH,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def has_head_commit():
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=REPO_PATH,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def capture_unstaged_diff(context_lines=DEFAULT_CONTEXT_LINES):
    return run_git_command(["diff", "--no-ext-diff", f"--unified={context_lines}"])


def capture_staged_diff(context_lines=DEFAULT_CONTEXT_LINES):
    return run_git_command(["diff", "--cached", "--no-ext-diff", f"--unified={context_lines}"])


def capture_full_diff(context_lines=DEFAULT_CONTEXT_LINES):
    if has_head_commit():
        return run_git_command(["diff", "HEAD", "--no-ext-diff", f"--unified={context_lines}"])

    return "\n".join(
        part for part in [capture_staged_diff(context_lines), capture_unstaged_diff(context_lines)] if part
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


def next_run_id(runs_root=RUNS_ROOT):
    today = dt.date.today().isoformat()
    runs_root.mkdir(parents=True, exist_ok=True)

    highest = 0
    for path in runs_root.iterdir():
        if not path.is_dir() or not path.name.startswith(f"{today}-"):
            continue

        suffix = path.name.removeprefix(f"{today}-")
        if suffix.isdigit():
            highest = max(highest, int(suffix))

    return f"{today}-{highest + 1:03d}"


def create_scan_output_folder(runs_root=RUNS_ROOT):
    output_folder = runs_root / next_run_id(runs_root)
    output_folder.mkdir(parents=True, exist_ok=False)
    return output_folder


def save_raw_diff(raw_diff, output_folder):
    diff_path = output_folder / "diff.patch"
    diff_path.write_text(raw_diff, encoding="utf-8")
    return diff_path


def capture_code_diff(context_lines=DEFAULT_CONTEXT_LINES):
    raw_diff = capture_full_diff(context_lines)

    return {
        "raw": raw_diff,
        "files": parse_unified_diff(raw_diff),
        "staged_raw": capture_staged_diff(context_lines),
        "unstaged_raw": capture_unstaged_diff(context_lines),
    }


def count_block_lines(blocks):
    return sum(len(block["content"]) for block in blocks)


def print_file_summary(files):
    if not files:
        print("No changed files.")
        return

    for file_diff in files:
        path = file_diff["new_path"] or file_diff["old_path"]
        added = sum(count_block_lines(hunk["added"]) for hunk in file_diff["hunks"])
        removed = sum(count_block_lines(hunk["removed"]) for hunk in file_diff["hunks"])
        context = sum(count_block_lines(hunk["context"]) for hunk in file_diff["hunks"])

        print(f"- {path}: +{added} -{removed} context={context}")


def main():
    diff = capture_code_diff()
    output_folder = create_scan_output_folder()
    diff_path = save_raw_diff(diff["raw"], output_folder)

    print("=== Full raw diff ===")
    print(diff["raw"] or "No code changes.")

    print("=== Parsed file summary ===")
    print_file_summary(diff["files"])

    print("=== Parsed diff JSON ===")
    print(json.dumps(diff["files"], indent=2))

    print("=== Scan output ===")
    print(f"Report folder: {output_folder}")
    print(f"Raw diff saved to: {diff_path}")


if __name__ == "__main__":
    main()
