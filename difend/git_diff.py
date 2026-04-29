import subprocess
from pathlib import Path

from .config import DEFAULT_CONTEXT_LINES
from .parser import parse_unified_diff


def run_git_command(repo_path, args):
    repo_path = Path(repo_path)
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def has_head_commit(repo_path):
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def capture_unstaged_diff(repo_path, context_lines=DEFAULT_CONTEXT_LINES):
    return run_git_command(repo_path, ["diff", "--no-ext-diff", f"--unified={context_lines}"])


def capture_staged_diff(repo_path, context_lines=DEFAULT_CONTEXT_LINES):
    return run_git_command(repo_path, ["diff", "--cached", "--no-ext-diff", f"--unified={context_lines}"])


def capture_full_diff(repo_path, context_lines=DEFAULT_CONTEXT_LINES):
    if has_head_commit(repo_path):
        return run_git_command(repo_path, ["diff", "HEAD", "--no-ext-diff", f"--unified={context_lines}"])

    return "\n".join(
        part
        for part in [
            capture_staged_diff(repo_path, context_lines),
            capture_unstaged_diff(repo_path, context_lines),
        ]
        if part
    )


def capture_code_diff(repo_path, context_lines=DEFAULT_CONTEXT_LINES):
    raw_diff = capture_full_diff(repo_path, context_lines)

    return {
        "raw": raw_diff,
        "files": parse_unified_diff(raw_diff),
        "staged_raw": capture_staged_diff(repo_path, context_lines),
        "unstaged_raw": capture_unstaged_diff(repo_path, context_lines),
    }
