import argparse
import json
from pathlib import Path

from .config import DEFAULT_CONTEXT_LINES
from .git_diff import capture_code_diff
from .output import create_scan_output_folder, save_raw_diff


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


def run_scan(repo_path, context_lines=DEFAULT_CONTEXT_LINES):
    repo_path = Path(repo_path).resolve()
    diff = capture_code_diff(repo_path, context_lines)
    output_folder = create_scan_output_folder(repo_path)
    diff_path = save_raw_diff(diff["raw"], output_folder)
    return diff, output_folder, diff_path


def build_parser(default_repo_path):
    parser = argparse.ArgumentParser(description="Capture and parse the current Git diff.")
    parser.add_argument("--repo", default=str(default_repo_path), help="Repository path to scan.")
    parser.add_argument("--context", type=int, default=DEFAULT_CONTEXT_LINES, help="Git diff context lines.")
    return parser


def main(argv=None, default_repo_path=None):
    default_repo_path = Path(default_repo_path or Path.cwd())
    args = build_parser(default_repo_path).parse_args(argv)

    diff, output_folder, diff_path = run_scan(args.repo, args.context)

    print("=== Full raw diff ===")
    print(diff["raw"] or "No code changes.")

    print("=== Parsed file summary ===")
    print_file_summary(diff["files"])

    print("=== Parsed diff JSON ===")
    print(json.dumps(diff["files"], indent=2))

    print("=== Scan output ===")
    print(f"Report folder: {output_folder}")
    print(f"Raw diff saved to: {diff_path}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
