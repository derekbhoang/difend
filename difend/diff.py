"""Git diff capture for Difend."""

from __future__ import annotations

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

    @property
    def has_changes(self) -> bool:
        return bool(self.unstaged.strip() or self.staged.strip())


class GitDiffCapture:
    """Capture staged and unstaged changes from a Git repository."""

    def __init__(self, repository_path: str | Path) -> None:
        self.repository_path = Path(repository_path)

    def capture(
        self,
        include_staged: bool = True,
        include_unstaged: bool = True,
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
