"""Agent review layer for Difend scan bundles."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


DEFAULT_MODEL = "gpt-5.1-codex"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"


class AgentReviewError(RuntimeError):
    """Raised when the agent review step cannot complete."""


class AgentClient(Protocol):
    def review(self, prompt: str) -> dict[str, Any]:
        """Return parsed JSON review output."""


@dataclass(frozen=True)
class AgentReviewResult:
    """Files updated by an agent review."""

    run_folder: Path
    findings_path: Path
    solution_proposals_path: Path
    report_path: Path
    status: str
    findings_count: int
    solution_proposals_count: int


class OpenAICodexClient:
    """Call an OpenAI Codex model through the Responses API."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        max_output_tokens: int = 4000,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise AgentReviewError(
                "OPENAI_API_KEY is required to run the Codex agent review."
            )
        self.model = model or os.environ.get("DIFEND_AGENT_MODEL") or DEFAULT_MODEL
        self.max_output_tokens = max_output_tokens

    def review(self, prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "instructions": _agent_instructions(),
            "input": prompt,
            "max_output_tokens": self.max_output_tokens,
        }
        request = urllib.request.Request(
            OPENAI_RESPONSES_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise AgentReviewError(f"OpenAI API request failed: {body}") from error
        except urllib.error.URLError as error:
            raise AgentReviewError(f"OpenAI API request failed: {error}") from error

        output_text = _extract_response_text(response_data)
        return _parse_agent_json(output_text)


def review_scan_bundle(
    run_folder: str | Path | None = None,
    *,
    repository_path: str | Path = ".",
    client: AgentClient | None = None,
    model: str | None = None,
) -> AgentReviewResult:
    """Run the agent review step for a scan bundle."""

    repo_path = Path(repository_path)
    resolved_run_folder = _resolve_run_folder(repo_path, run_folder)
    report_path = resolved_run_folder / "report.json"
    diff_path = resolved_run_folder / "diff.patch"
    context_signals_path = resolved_run_folder / "context-signals.md"
    manual_review_path = resolved_run_folder / "manual-review.md"
    findings_path = resolved_run_folder / "findings.md"
    solution_proposals_path = resolved_run_folder / "solution-proposals.md"

    report = _read_json(report_path)
    diff_text = _read_optional_text(diff_path)
    context_signals = _read_optional_text(context_signals_path)
    manual_review = _read_optional_text(manual_review_path)

    prompt = _build_agent_prompt(
        report=report,
        diff_text=diff_text,
        context_signals=context_signals,
        manual_review=manual_review,
    )
    agent_client = client or OpenAICodexClient(model=model)
    agent_output = agent_client.review(prompt)

    findings = _normalize_list(agent_output.get("findings"))
    solution_proposals = _normalize_list(agent_output.get("solution_proposals"))
    updated_status = _status_from_agent_output(
        findings=findings,
        manual_review=agent_output.get("manual_review"),
    )

    findings_markdown = agent_output.get("findings_markdown")
    if not isinstance(findings_markdown, str) or not findings_markdown.strip():
        findings_markdown = _render_findings_markdown(findings)

    solution_markdown = agent_output.get("solution_proposals_markdown")
    if not isinstance(solution_markdown, str) or not solution_markdown.strip():
        solution_markdown = _render_solution_proposals_markdown(solution_proposals)

    findings_path.write_text(findings_markdown.rstrip() + "\n", encoding="utf-8")
    solution_proposals_path.write_text(
        solution_markdown.rstrip() + "\n",
        encoding="utf-8",
    )

    report["status"] = updated_status
    report["findings"] = findings
    report["solution_proposals"] = solution_proposals
    report["agent_review"] = {
        "agent": "codex-api",
        "model": model or os.environ.get("DIFEND_AGENT_MODEL") or DEFAULT_MODEL,
        "status": updated_status,
        "findings_count": len(findings),
        "solution_proposals_count": len(solution_proposals),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return AgentReviewResult(
        run_folder=resolved_run_folder,
        findings_path=findings_path,
        solution_proposals_path=solution_proposals_path,
        report_path=report_path,
        status=updated_status,
        findings_count=len(findings),
        solution_proposals_count=len(solution_proposals),
    )


def _resolve_run_folder(repo_path: Path, run_folder: str | Path | None) -> Path:
    if run_folder is not None:
        path = Path(run_folder)
        return path if path.is_absolute() else repo_path / path

    runs_root = repo_path / ".difend" / "runs"
    if not runs_root.exists():
        raise AgentReviewError("No .difend/runs folder found. Run `difend scan` first.")

    runs = sorted(
        (path for path in runs_root.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not runs:
        raise AgentReviewError("No scan runs found. Run `difend scan` first.")

    return runs[0]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise AgentReviewError(f"Missing required file: {path}")

    return json.loads(path.read_text(encoding="utf-8"))


def _read_optional_text(path: Path) -> str:
    if not path.exists():
        return ""

    return path.read_text(encoding="utf-8")


def _build_agent_prompt(
    *,
    report: dict[str, Any],
    diff_text: str,
    context_signals: str,
    manual_review: str,
) -> str:
    return "\n".join(
        [
            "Review this Difend scan bundle.",
            "",
            "The automated gates are rule-based. Treat report_json.rule_signals "
            "as context, not final findings.",
            "",
            "Your job:",
            "- Confirm which rule signals are real security issues.",
            "- Mark false positives or test fixtures as not findings.",
            "- Produce concise confirmed findings.",
            "- Produce non-mutating solution proposals.",
            "- Do not edit source code.",
            "",
            "Return only JSON with this shape:",
            "{",
            '  "findings": [',
            "    {",
            '      "file": "path",',
            '      "line": 1,',
            '      "severity": "critical|high|medium|low",',
            '      "evidence": "short evidence",',
            '      "recommendation": "specific recommendation",',
            '      "confidence": "high|medium|low"',
            "    }",
            "  ],",
            '  "solution_proposals": [',
            "    {",
            '      "file": "path",',
            '      "proposal": "non-mutating fix proposal",',
            '      "suggested_tests": ["test idea"]',
            "    }",
            "  ],",
            '  "findings_markdown": "# Agent-Confirmed Findings\\n...",',
            '  "solution_proposals_markdown": "# Solution Proposals\\n..."',
            "}",
            "",
            "report_json:",
            json.dumps(report, indent=2),
            "",
            "context_signals_md:",
            context_signals,
            "",
            "manual_review_md:",
            manual_review,
            "",
            "diff_patch:",
            diff_text,
        ]
    )


def _agent_instructions() -> str:
    return (
        "You are a security review agent for Difend. You confirm or reject "
        "rule-based security signals from Git diffs. You must return valid JSON "
        "only. Do not wrap the JSON in Markdown."
    )


def _extract_response_text(response_data: dict[str, Any]) -> str:
    output_text = response_data.get("output_text")
    if isinstance(output_text, str):
        return output_text

    parts: list[str] = []
    for item in response_data.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            if content.get("type") == "output_text" and isinstance(
                content.get("text"),
                str,
            ):
                parts.append(content["text"])

    if not parts:
        raise AgentReviewError("OpenAI response did not contain output text.")

    return "\n".join(parts)


def _parse_agent_json(output_text: str) -> dict[str, Any]:
    stripped = output_text.strip()
    fenced_match = re.search(r"```(?:json)?\s*(.*?)```", stripped, re.DOTALL)
    if fenced_match:
        stripped = fenced_match.group(1).strip()

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise AgentReviewError("Agent response was not valid JSON.") from error

    if not isinstance(parsed, dict):
        raise AgentReviewError("Agent response JSON must be an object.")

    return parsed


def _normalize_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


def _status_from_agent_output(
    *,
    findings: list[dict[str, Any]],
    manual_review: object,
) -> str:
    if any(finding.get("severity") == "critical" for finding in findings):
        return "fail"

    if findings or manual_review:
        return "manual review required"

    return "pass"


def _render_findings_markdown(findings: list[dict[str, Any]]) -> str:
    lines = ["# Agent-Confirmed Findings", ""]
    if not findings:
        lines.extend(["No agent-confirmed findings were detected.", ""])
        return "\n".join(lines)

    for finding in findings:
        location = _format_location(finding.get("file"), finding.get("line"))
        lines.extend(
            [
                f"## {location}",
                "",
                f"- Severity: {finding.get('severity', 'unknown')}",
                f"- Evidence: `{finding.get('evidence', '')}`",
                f"- Recommendation: {finding.get('recommendation', '')}",
                f"- Confidence: {finding.get('confidence', 'unknown')}",
                "",
            ]
        )

    return "\n".join(lines)


def _render_solution_proposals_markdown(
    solution_proposals: list[dict[str, Any]],
) -> str:
    lines = ["# Solution Proposals", ""]
    if not solution_proposals:
        lines.extend(["No solution proposals were generated.", ""])
        return "\n".join(lines)

    for proposal in solution_proposals:
        lines.extend(
            [
                f"## {proposal.get('file', 'Unknown file')}",
                "",
                f"- Proposal: {proposal.get('proposal', '')}",
                f"- Suggested tests: {_format_suggested_tests(proposal)}",
                "",
            ]
        )

    return "\n".join(lines)


def _format_location(file_value: object, line_value: object) -> str:
    file_path = file_value if isinstance(file_value, str) else "Unknown file"
    if isinstance(line_value, int):
        return f"{file_path}:{line_value}"

    return file_path


def _format_suggested_tests(proposal: dict[str, Any]) -> str:
    tests = proposal.get("suggested_tests")
    if not isinstance(tests, list) or not tests:
        return "None"

    return "; ".join(str(test) for test in tests)
