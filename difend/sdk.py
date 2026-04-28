"""Public SDK interface for Difend scans."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from difend.diff import CodeDiff, GitDiffCapture


@dataclass(frozen=True)
class ScanRequest:
    """Input needed to start a Difend scan."""

    repository_path: Path

    @classmethod
    def from_path(cls, repository_path: str | Path = ".") -> "ScanRequest":
        return cls(repository_path=Path(repository_path))


@dataclass(frozen=True)
class ScanReport:
    """Structured result returned by a Difend scan."""

    name: str
    repository_path: Path
    status: str
    diff: CodeDiff


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        diff = GitDiffCapture(request.repository_path).capture()

        return ScanReport(
            name="difend scan",
            repository_path=request.repository_path,
            status="pass",
            diff=diff,
        )


def scan(repository_path: str | Path = ".") -> ScanReport:
    """Run a Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(repository_path)
    return DifendSDK().scan(request)
