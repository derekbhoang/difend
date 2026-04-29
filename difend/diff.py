"""Git diff capture and parsing for Difend."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class DiffCaptureError(RuntimeError):
    """Raised when Difend cannot capture a Git diff."""


@dataclass(frozen=True)
class CodeDiff:
    """Git diff content captured for a scan."""

    unstaged: str
    staged: str
    untracked: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(
            self.unstaged.strip()
            or self.staged.strip()
            or self.untracked.strip()
        )

    @property
    def patch_text(self) -> str:
        return self.unstaged + self.staged + self.untracked


@dataclass(frozen=True)
class DiffLine:
    """A line added by the current Git diff."""

    file: str
    line: int | None
    content: str


@dataclass(frozen=True)
class ParsedDiff:
    """Structured view of a Git diff for rule-based gates."""

    changed_files: tuple[str, ...]
    added_lines: tuple[DiffLine, ...]

    def added_lines_for_file(self, file_path: str) -> tuple[DiffLine, ...]:
        return tuple(line for line in self.added_lines if line.file == file_path)


class GitDiffCapture:
    """Capture staged and unstaged changes from a Git repository."""

    def __init__(self, repository_path: str | Path) -> None:
        self.repository_path = Path(repository_path)

    def capture(
        self,
        include_staged: bool = True,
        include_unstaged: bool = True,
        include_untracked: bool = True,
    ) -> CodeDiff:
        return CodeDiff(
            unstaged=(
                self._run_git(["diff", "--no-ext-diff", "--unified=0"])
                if include_unstaged
                else ""
            ),
            staged=(
                self._run_git(["diff", "--cached", "--no-ext-diff", "--unified=0"])
                if include_staged
                else ""
            ),
            untracked=(
                self._capture_untracked_diff()
                if include_untracked
                else ""
            ),
        )

    def _run_git(self, args: list[str]) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repository_path,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            message = result.stderr.strip() or "Git command failed."
            raise DiffCaptureError(message)

        return result.stdout

    def _capture_untracked_diff(self) -> str:
        output = self._run_git(["ls-files", "--others", "--exclude-standard"])
        diffs: list[str] = []

        for relative_path in output.splitlines():
            path = self.repository_path / relative_path
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue

            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            diffs.append(_render_new_file_diff(relative_path, content))

        return "".join(diffs)


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_code_diff(diff: CodeDiff) -> ParsedDiff:
    """Parse captured staged and unstaged diff content."""

    return parse_diff(diff.patch_text)


def parse_diff(diff_text: str) -> ParsedDiff:
    """Parse a unified Git diff and keep only changed files and added lines."""

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
