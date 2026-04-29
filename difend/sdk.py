"""Public SDK interface for Difend scans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from difend.bundle import ScanBundleRequest, ScanBundleWriter
from difend.diff import CodeDiff, DEFAULT_CONTEXT_LINES, GitDiffCapture
from difend.gates import run_automated_gates
from difend.parser import parse_code_diff


class ScanStatus(str, Enum):
    """Final status values returned by a scan."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual review required"


@dataclass(frozen=True)
class ScanRequest:
    """Input contract for a Difend scan."""

    repository_path: Path
    output_root: Path = Path(".difend/runs")
    include_staged: bool = True
    include_unstaged: bool = True
    context_lines: int = DEFAULT_CONTEXT_LINES

    @classmethod
    def from_path(
        cls,
        repository_path: str | Path = ".",
        output_root: str | Path = ".difend/runs",
        include_staged: bool = True,
        include_unstaged: bool = True,
        context_lines: int = DEFAULT_CONTEXT_LINES,
    ) -> "ScanRequest":
        return cls(
            repository_path=Path(repository_path),
            output_root=Path(output_root),
            include_staged=include_staged,
            include_unstaged=include_unstaged,
            context_lines=context_lines,
        )


@dataclass(frozen=True)
class ScanReport:
    """Output contract returned by a Difend scan."""

    name: str
    scan_id: str
    repository_path: Path
    output_folder: Path
    status: ScanStatus
    diff: CodeDiff
    parsed_diff: dict[str, Any]
    gates: dict[str, Any]


class DifendSDK:
    """Reusable SDK entry point for running Difend workflows."""

    def scan(self, request: ScanRequest) -> ScanReport:
        diff = GitDiffCapture(request.repository_path).capture(
            include_staged=request.include_staged,
            include_unstaged=request.include_unstaged,
            context_lines=request.context_lines,
        )
        parsed_diff = parse_code_diff(diff)
        gates = run_automated_gates(parsed_diff)
        status = ScanStatus(gates["summary"]["status"])
        bundle = ScanBundleWriter().write(
            ScanBundleRequest(
                repository_path=request.repository_path,
                output_root=request.output_root,
                status=status.value,
                diff=diff,
                parsed_diff=parsed_diff,
                gates=gates,
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
            gates=gates,
        )


def scan(
    repository_path: str | Path = ".",
    output_root: str | Path = ".difend/runs",
    include_staged: bool = True,
    include_unstaged: bool = True,
    context_lines: int = DEFAULT_CONTEXT_LINES,
) -> ScanReport:
    """Run a Difend scan through the default SDK instance."""

    request = ScanRequest.from_path(
        repository_path=repository_path,
        output_root=output_root,
        include_staged=include_staged,
        include_unstaged=include_unstaged,
        context_lines=context_lines,
    )
    return DifendSDK().scan(request)
