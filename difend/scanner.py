from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from difend.diff import parse_diff
from difend.gates import (
    check_auth_permission_changes,
    check_dependency_changes,
    check_injection_risks,
    check_secrets,
)
from difend.git import capture_diff, resolve_repo_root
from difend.models import (
    STATUS_FAIL,
    STATUS_MANUAL_REVIEW,
    STATUS_PASS,
    Finding,
    ManualReviewItem,
    ScanResult,
)
from difend.reports import write_scan_bundle

ProgressCallback = Callable[[str, str], None]


def scan_repository(
    repo_path: Path,
    *,
    run_id: str | None = None,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    repo_root = resolve_repo_root(repo_path)
    current_run_id = run_id or _make_run_id()

    _progress(progress, "Checking git diff", "in progress")
    diff_bundle = capture_diff(repo_root)
    parsed_diff = parse_diff(diff_bundle.combined)
    _progress(progress, "Checking git diff", "done")

    findings: list[Finding] = []
    manual_review_items: list[ManualReviewItem] = []

    _progress(progress, "Checking secrets", "in progress")
    findings.extend(check_secrets(parsed_diff))
    _progress(progress, "Checking secrets", _gate_status(findings, "secrets"))

    _progress(progress, "Checking dependency changes", "in progress")
    dependency_findings = check_dependency_changes(parsed_diff)
    findings.extend(dependency_findings)
    _progress(
        progress,
        "Checking dependency changes",
        "warning" if dependency_findings else "done",
    )

    _progress(progress, "Checking injection risks", "in progress")
    injection_findings = check_injection_risks(parsed_diff)
    findings.extend(injection_findings)
    _progress(
        progress,
        "Checking injection risks",
        "warning" if injection_findings else "done",
    )

    _progress(progress, "Checking auth and permission changes", "in progress")
    auth_items = check_auth_permission_changes(parsed_diff)
    manual_review_items.extend(auth_items)
    _progress(
        progress,
        "Checking auth and permission changes",
        "manual review required" if auth_items else "done",
    )

    result = ScanResult(
        status=_calculate_status(tuple(findings), tuple(manual_review_items)),
        run_id=current_run_id,
        repo_path=repo_root,
        output_path=repo_root / ".difend" / "runs" / current_run_id,
        diff=diff_bundle.combined,
        findings=tuple(findings),
        manual_review_items=tuple(manual_review_items),
    )
    write_scan_bundle(result)
    return result


def _calculate_status(
    findings: tuple[Finding, ...],
    manual_review_items: tuple[ManualReviewItem, ...],
) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return STATUS_FAIL
    if findings or manual_review_items:
        return STATUS_MANUAL_REVIEW
    return STATUS_PASS


def _make_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%d-%H%M%S")


def _progress(progress: ProgressCallback | None, label: str, status: str) -> None:
    if progress is not None:
        progress(label, status)


def _gate_status(findings: list[Finding], gate: str) -> str:
    return "warning" if any(finding.gate == gate for finding in findings) else "done"
