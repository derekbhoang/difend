"""Public SDK interface for Difend scans."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from difend.bundle import ScanBundleWriter, ScanBundleRequest
from difend.diff import CodeDiff, GitDiffCapture, ParsedDiff, parse_code_diff
from difend.gates import Finding, GateResult, GateRunner


class ScanStatus(str, Enum):
    """Final status values returned by a scan."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual review required"


ProgressCallback = Callable[[str, str], None]


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
        Render Git-reported untracked text files as new-file diffs.
    """

    repository_path: Path
    output_root: Path = Path(".difend/runs")
    include_staged: bool = True
    include_unstaged: bool = True
    include_untracked: bool = True
    progress: ProgressCallback | None = None

    @classmethod
    def from_path(
        cls,
        repository_path: str | Path = ".",
        output_root: str | Path = ".difend/runs",
        progress: ProgressCallback | None = None,
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
            progress=progress,
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
    parsed_diff:
        Structured view of changed files and added lines.
    findings:
        Combined automated gate findings.
    """

    name: str
    scan_id: str
    repository_path: Path
    output_folder: Path
    status: ScanStatus
    diff: CodeDiff
    parsed_diff: ParsedDiff
    findings: tuple[Finding, ...]
    gate_results: tuple[GateResult, ...]


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        _progress(request.progress, "Checking git diff", "in progress")
        diff = GitDiffCapture(request.repository_path).capture(
            include_staged=request.include_staged,
            include_unstaged=request.include_unstaged,
            include_untracked=request.include_untracked,
        )
        parsed_diff = parse_code_diff(diff)
        _progress(request.progress, "Checking git diff", "done")

        gate_report = GateRunner().run(
            parsed_diff,
            progress=request.progress,
        )
        status = _status_from_findings(gate_report.findings)
        bundle = ScanBundleWriter().write(
            ScanBundleRequest(
                repository_path=request.repository_path,
                output_root=request.output_root,
                status=status.value,
                diff=diff,
                parsed_diff=parsed_diff,
                findings=gate_report.findings,
                gate_results=gate_report.gate_results,
            )
        )

        return ScanReport(
            name="difend scan",
            scan_id=bundle.scan_id,
            repository_path=request.repository_path,
            output_folder=bundle.output_folder,
            status=status,
            diff=diff,
            parsed_diff=parsed_diff,
            findings=gate_report.findings,
            gate_results=gate_report.gate_results,
        )


def scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    progress: ProgressCallback | None = None,
) -> ScanReport:
    """Run a Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        progress=progress,
    )
    return DifendSDK().scan(request)


def _status_from_findings(findings: tuple[Finding, ...]) -> ScanStatus:
    if any(finding.severity == "critical" for finding in findings):
        return ScanStatus.FAIL

    if findings:
        return ScanStatus.MANUAL_REVIEW_REQUIRED

    return ScanStatus.PASS


def _progress(
    progress: ProgressCallback | None,
    label: str,
    status: str,
) -> None:
    if progress is not None:
        progress(label, status)
