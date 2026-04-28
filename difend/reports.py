from __future__ import annotations

import json
from pathlib import Path

from difend.models import STATUS_FAIL, STATUS_MANUAL_REVIEW, STATUS_PASS, ScanResult


def write_scan_bundle(result: ScanResult) -> None:
    result.output_path.mkdir(parents=True, exist_ok=True)
    _write_text(result.output_path / "summary.md", render_summary(result))
    _write_text(result.output_path / "findings.md", render_findings(result))
    _write_text(result.output_path / "manual-review.md", render_manual_review(result))
    _write_text(
        result.output_path / "codex-instructions.md",
        render_codex_instructions(result),
    )
    _write_text(result.output_path / "diff.patch", result.diff or "")
    _write_text(
        result.output_path / "report.json",
        json.dumps(result.to_dict(), indent=2) + "\n",
    )


def render_summary(result: ScanResult) -> str:
    lines = [
        "# Difend Scan Summary",
        "",
        f"- Status: `{result.status}`",
        f"- Run ID: `{result.run_id}`",
        f"- Repository: `{result.repo_path}`",
        f"- Report folder: `{result.output_path}`",
        f"- Findings: {len(result.findings)}",
        f"- Manual review items: {len(result.manual_review_items)}",
        "",
        "## Next Steps",
        "",
    ]
    if result.status == STATUS_PASS:
        lines.append("No security findings were detected in the current diff.")
    elif result.status == STATUS_FAIL:
        lines.append(
            "Fix the failing findings before merging or continuing with the change."
        )
    elif result.status == STATUS_MANUAL_REVIEW:
        lines.append(
            "Review the flagged security-sensitive changes before treating this diff as safe."
        )
    return "\n".join(lines) + "\n"


def render_findings(result: ScanResult) -> str:
    lines = ["# Automated Findings", ""]
    if not result.findings:
        lines.append("No automated gate findings.")
        return "\n".join(lines) + "\n"

    for finding in result.findings:
        location = _format_location(finding.file, finding.line)
        lines.extend(
            [
                f"## {finding.gate} - {finding.severity}",
                "",
                f"- Location: `{location}`",
                f"- Evidence: `{finding.evidence}`",
                f"- Recommendation: {finding.recommendation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_manual_review(result: ScanResult) -> str:
    lines = ["# Manual Review", ""]
    if not result.manual_review_items:
        lines.append("No manual review items.")
        return "\n".join(lines) + "\n"

    for item in result.manual_review_items:
        location = _format_location(item.file, item.line)
        lines.extend(
            [
                f"## {item.gate}",
                "",
                f"- Location: `{location}`",
                f"- Reason: {item.reason}",
                f"- Evidence: `{item.evidence}`",
                f"- Recommendation: {item.recommendation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_codex_instructions(result: ScanResult) -> str:
    lines = [
        "# Codex Follow-Up Instructions",
        "",
        "Please review this Difend scan bundle for security issues in the current Git diff.",
        "",
        "Read these files in this folder:",
        "",
        "1. `summary.md`",
        "2. `findings.md`",
        "3. `manual-review.md`",
        "4. `diff.patch`",
        "5. `report.json`",
        "",
        "Focus on whether the changed lines introduce security risk. Do not review unrelated old code unless it is needed to understand the changed lines.",
        "",
        f"Current Difend status: `{result.status}`",
        "",
    ]
    if result.findings:
        lines.append("Start by fixing or explaining each automated finding.")
    if result.manual_review_items:
        lines.append(
            "Then inspect each manual review item for authentication, authorization, data exposure, injection, dependency, or sensitive boundary risk."
        )
    if not result.findings and not result.manual_review_items:
        lines.append(
            "Confirm that the diff is low risk and identify any missed context if needed."
        )
    return "\n".join(lines) + "\n"


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _format_location(file: str, line: int | None) -> str:
    if line is None:
        return file
    return f"{file}:{line}"
