"""Public SDK interface for Difend scans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from difend.bundle import ScanBundleWriter, ScanBundleRequest
from difend.diff import CodeDiff, GitDiffCapture


class ScanStatus(str, Enum):
    """Final status values returned by a scan."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual review required"


@dataclass(frozen=True)
class ScanRequest:
    """Input contract for a Difend scan.

    repository_path:
        Git repository to scan.
    output_root:
        Directory where future scan bundles will be written.
    include_staged:
        Capture staged changes from the Git index.
    include_unstaged:
        Capture unstaged working tree changes.
    include_untracked:
        Capture new files that have not been added to the Git index.
    """

    repository_path: Path
    output_root: Path = Path(".difend/runs")
    include_staged: bool = True
    include_unstaged: bool = True
    include_untracked: bool = True

    @classmethod
    def from_path(
        cls,
        repository_path: str | Path = ".",
        output_root: str | Path = ".difend/runs",
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
        )


@dataclass(frozen=True)
class ScanReport:
    """Output contract returned by a Difend scan.

    name:
        Human-readable workflow name.
    scan_id:
        Stable identifier for this run.
    repository_path:
        Git repository that was scanned.
    output_folder:
        Future bundle location for this run.
    status:
        Final scan status.
    diff:
        Exact staged and unstaged diff content captured for the scan.
    """

    name: str
    scan_id: str
    repository_path: Path
    output_folder: Path
    status: ScanStatus
    diff: CodeDiff


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        diff = GitDiffCapture(request.repository_path).capture(
            include_staged=request.include_staged,
            include_unstaged=request.include_unstaged,
            include_untracked=request.include_untracked,
        )
        status = ScanStatus.PASS
        bundle = ScanBundleWriter().write(
            ScanBundleRequest(
                repository_path=request.repository_path,
                output_root=request.output_root,
                status=status.value,
                diff=diff,
            )
        )

        return ScanReport(
            name="difend scan",
            scan_id=bundle.scan_id,
            repository_path=request.repository_path,
            output_folder=bundle.output_folder,
            status=status,
            diff=diff,
        )


def scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
) -> ScanReport:
    """Run a Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
    )
    return DifendSDK().scan(request)
