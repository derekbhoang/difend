"""Deterministic scoring, dedupe, and status logic."""

from __future__ import annotations

from difend.agents.schemas import Finding, ManualReviewItem, Severity


SEVERITY_SCORE = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}


def merge_results(
    findings: list[Finding],
    manual_review: list[ManualReviewItem],
) -> tuple[list[Finding], list[ManualReviewItem], list[ManualReviewItem]]:
    unique_findings = _dedupe_findings(findings)
    gate_keys = {_dedupe_key(finding) for finding in unique_findings}
    filtered_review: list[ManualReviewItem] = []
    covered_review: list[ManualReviewItem] = []
    for item in _dedupe_manual_review(manual_review):
        if _dedupe_key(item) in gate_keys:
            covered_review.append(item)
        else:
            filtered_review.append(item)

    return (
        sorted(unique_findings, key=lambda item: _sort_score(item), reverse=True),
        sorted(filtered_review, key=lambda item: _sort_score(item), reverse=True),
        sorted(covered_review, key=lambda item: _sort_score(item), reverse=True),
    )


def decide_status(findings: list[Finding], manual_review: list[ManualReviewItem]) -> str:
    active_findings = [finding for finding in findings if not finding.suppressed]
    if active_findings:
        return "fail"
    if manual_review:
        return "manual review required"
    return "pass"


def risk_score(findings: list[Finding], manual_review: list[ManualReviewItem]) -> int:
    score = 0
    for finding in findings:
        if not finding.suppressed:
            score += SEVERITY_SCORE.get(finding.severity, 0) * 10
    for item in manual_review:
        score += SEVERITY_SCORE.get(item.risk_level, 0) * 5
    return score


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple[str, int | None, str, str], Finding] = {}
    for finding in findings:
        key = _dedupe_key(finding)
        existing = by_key.get(key)
        if existing is None or _sort_score(finding) > _sort_score(existing):
            by_key[key] = finding
    return list(by_key.values())


def _dedupe_manual_review(items: list[ManualReviewItem]) -> list[ManualReviewItem]:
    by_key: dict[tuple[str, int | None, str, str], ManualReviewItem] = {}
    for item in items:
        key = _dedupe_key(item)
        existing = by_key.get(key)
        if existing is None or _sort_score(item) > _sort_score(existing):
            by_key[key] = item
    return list(by_key.values())


def _dedupe_key(item: Finding | ManualReviewItem) -> tuple[str, int | None, str, str]:
    return (
        item.file,
        item.line,
        item.vulnerability_type,
        item.evidence_fingerprint,
    )


def _sort_score(item: Finding | ManualReviewItem) -> int:
    severity = item.severity if isinstance(item, Finding) else item.risk_level
    return SEVERITY_SCORE.get(severity, 0)
