from __future__ import annotations

import subprocess
from pathlib import Path

from difend.models import DiffBundle


def run_git_command(repo_path: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(message or "Git command failed.")
    return result.stdout


def resolve_repo_root(repo_path: Path) -> Path:
    output = run_git_command(repo_path, ["rev-parse", "--show-toplevel"])
    return Path(output.strip()).resolve()


def capture_diff(repo_path: Path) -> DiffBundle:
    unstaged = run_git_command(
        repo_path, ["diff", "--no-ext-diff", "--unified=0"]
    )
    staged = run_git_command(
        repo_path, ["diff", "--cached", "--no-ext-diff", "--unified=0"]
    )
    untracked = capture_untracked_diff(repo_path)
    return DiffBundle(staged=staged, unstaged=unstaged, untracked=untracked)


def capture_untracked_diff(repo_path: Path) -> str:
    output = run_git_command(repo_path, ["ls-files", "--others", "--exclude-standard"])
    diffs: list[str] = []
    for relative_path in output.splitlines():
        path = repo_path / relative_path
        if not path.is_file() or path.stat().st_size > 1_000_000:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        diffs.append(_render_new_file_diff(relative_path, content))
    return "\n".join(diffs)


def _render_new_file_diff(relative_path: str, content: str) -> str:
    lines = content.splitlines()
    rendered = [
        f"diff --git a/{relative_path} b/{relative_path}",
        "new file mode 100644",
        "index 0000000..0000000",
        "--- /dev/null",
        f"+++ b/{relative_path}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    rendered.extend(f"+{line}" for line in lines)
    return "\n".join(rendered) + "\n"
