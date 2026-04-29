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
    untracked: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(
            self.unstaged.strip()
            or self.staged.strip()
            or self.untracked.strip()
        )


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

    def _capture_untracked_diff(self) -> str:
        files = self._run_git(
            ["ls-files", "--others", "--exclude-standard", "-z"],
        ).split("\0")
        patches = [
            self._run_git(
                [
                    "diff",
                    "--no-index",
                    "--no-ext-diff",
                    "--unified=0",
                    "--",
                    "/dev/null",
                    path,
                ],
                allowed_return_codes=(0, 1),
            )
            for path in files
            if path
        ]
        return "".join(patches)

    def _run_git(
        self,
        args: list[str],
        allowed_return_codes: tuple[int, ...] = (0,),
    ) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repository_path,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode not in allowed_return_codes:
            message = result.stderr.strip() or "Git command failed."
            raise DiffCaptureError(message)

        return result.stdout
