"""Rule-based automated security gates for parsed Difend diffs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Protocol


PASS = "pass"
FAIL = "fail"
MANUAL_REVIEW_REQUIRED = "manual review required"

DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "composer.lock",
}

AUTH_TERMS = re.compile(
    r"\b(auth|authenticate|authorization|authorisation|authorize|permission|privilege|role|admin|"
    r"is_staff|is_superuser|session|cookie|jwt|token|login|logout|csrf|acl|policy)\b",
    re.IGNORECASE,
)

FINDING_TITLES = {
    "secrets": "Possible hardcoded secret",
    "injection risks": "Possible injection risk",
    "auth and permission changes": "Possible unsafe auth or permission change",
}


class GateFunction(Protocol):
    """Callable contract shared by all rule-based gates."""

    def __call__(self, parsed_diff: dict[str, Any], context: "GateContext") -> dict[str, Any]:
        """Run one gate and return one gate output."""


class AutomatedGatesAgent:
    """Aggregate rule-based gate outputs into one automated gates result."""

    name = "automated_gates"
    kind = "rule-based"
    schema_version = "automated-gates.v1"

    def __init__(self, gates: list[GateFunction] | None = None) -> None:
        self.gates = gates or [
            check_secrets,
            check_dependency_changes,
            check_injection_risks,
            check_auth_permission_changes,
        ]

    def run(self, parsed_diff: dict[str, Any]) -> dict[str, Any]:
        context = GateContext()
        gate_outputs = [gate(parsed_diff, context) for gate in self.gates]
        findings = [finding for output in gate_outputs for finding in output["findings"]]
        manual_review = [item for output in gate_outputs for item in output["manual_review"]]
        status = determine_final_status(findings, manual_review)

        return {
            "schema_version": self.schema_version,
            "agent": self.name,
            "agent_metadata": {
                "kind": self.kind,
            },
            "status": status,
            "gate_outputs": gate_outputs,
            "checks": gate_outputs,
            "findings": findings,
            "manual_review": manual_review,
            "summary": {
                "check_count": len(gate_outputs),
                "finding_count": len(findings),
                "manual_review_count": len(manual_review),
                "status": status,
            },
        }


def run_automated_gates(parsed_diff: dict[str, Any]) -> dict[str, Any]:
    """Run the default automated gates agent."""

    return AutomatedGatesAgent().run(parsed_diff)


def determine_final_status(findings: list[dict[str, Any]], manual_review: list[dict[str, Any]]) -> str:
    if findings:
        return FAIL
    if manual_review:
        return MANUAL_REVIEW_REQUIRED
    return PASS


class GateContext:
    """Small counter holder for stable finding IDs."""

    def __init__(self) -> None:
        self.finding_number = 1
        self.manual_review_number = 1

    def next_finding_id(self) -> str:
        value = f"F{self.finding_number:03d}"
        self.finding_number += 1
        return value

    def next_manual_review_id(self) -> str:
        value = f"M{self.manual_review_number:03d}"
        self.manual_review_number += 1
        return value


def check_secrets(parsed_diff: dict[str, Any], context: GateContext) -> dict[str, Any]:
    patterns = [
        (
            "critical",
            re.compile(r"AKIA[0-9A-Z]{16}"),
            "Remove the AWS access key, rotate it immediately, and load credentials from a secret manager or environment variable.",
        ),
        (
            "critical",
            re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
            "Remove the GitHub token, revoke it, and inject it through a secret manager.",
        ),
        (
            "high",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
            "Do not commit private keys. Revoke the key and replace it with managed secret storage.",
        ),
        (
            "high",
            re.compile(
                r"\b(api[_-]?key|secret|token|password|passwd|client_secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                re.IGNORECASE,
            ),
            "Remove the hardcoded secret and read it from a protected runtime secret source.",
        ),
    ]

    findings = []
    for line in iter_added_lines(parsed_diff):
        for severity, pattern, recommendation in patterns:
            if pattern.search(line["content"]):
                findings.append(
                    make_finding(
                        context,
                        gate="secrets",
                        severity=severity,
                        line=line,
                        evidence=line["content"],
                        recommendation=recommendation,
                    )
                )
                break

    return make_gate_output("secrets", findings=findings)


def check_dependency_changes(parsed_diff: dict[str, Any], context: GateContext) -> dict[str, Any]:
    reviews = []
    seen_paths = set()

    for file_diff in iter_files(parsed_diff):
        path = file_diff.get("path") or "unknown"
        if path in seen_paths:
            continue
        if Path(path).name.lower() not in DEPENDENCY_FILES:
            continue

        seen_paths.add(path)
        reviews.append(
            make_manual_review(
                context,
                gate="dependency changes",
                category="dependency manifest changed",
                file=path,
                line_range="file",
                evidence=path,
                reason="A dependency manifest or lockfile changed. Difend does not query vulnerability databases yet.",
                checklist=[
                    "Run the package manager audit command for this ecosystem.",
                    "Check whether new packages are necessary and maintained.",
                    "Confirm version ranges do not unexpectedly widen the supply-chain attack surface.",
                ],
                recommendation="Review the dependency change and run an ecosystem-specific vulnerability audit before merging.",
            )
        )

    return make_gate_output("dependency changes", manual_review=reviews)


def check_injection_risks(parsed_diff: dict[str, Any], context: GateContext) -> dict[str, Any]:
    patterns = [
        (
            "high",
            re.compile(
                r"\bexecute\s*\(\s*f?['\"].*(select|insert|update|delete|drop|alter)\b.*(\{|%s|\+|\.format\()",
                re.IGNORECASE,
            ),
            "Use parameterized queries or the framework query builder instead of building SQL with string interpolation.",
        ),
        (
            "high",
            re.compile(r"\b(raw|query|exec|execute)\s*\(.*(request\.|req\.|params|query|body|input).*\+", re.IGNORECASE),
            "Do not concatenate request-controlled values into database or command strings.",
        ),
        (
            "high",
            re.compile(r"(os\.system|popen\(|subprocess\.[a-z_]+\().*shell\s*=\s*True", re.IGNORECASE),
            "Avoid shell=True with dynamic input. Pass arguments as a list and validate allowlisted values.",
        ),
        (
            "medium",
            re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
            "Avoid dynamic code execution, or strictly constrain and sandbox the evaluated input.",
        ),
        (
            "medium",
            re.compile(r"(innerHTML|dangerouslySetInnerHTML|document\.write)\s*[=:]", re.IGNORECASE),
            "Render untrusted content through safe templating or sanitize it before insertion into the DOM.",
        ),
    ]

    findings = []
    for line in iter_added_lines(parsed_diff):
        for severity, pattern, recommendation in patterns:
            if pattern.search(line["content"]):
                findings.append(
                    make_finding(
                        context,
                        gate="injection risks",
                        severity=severity,
                        line=line,
                        evidence=line["content"],
                        recommendation=recommendation,
                    )
                )
                break

    return make_gate_output("injection risks", findings=findings)


def check_auth_permission_changes(parsed_diff: dict[str, Any], context: GateContext) -> dict[str, Any]:
    concrete_patterns = [
        (
            "high",
            re.compile(r"@csrf_exempt|csrf\s*[:=]\s*false|csrf_protect\s*=\s*False", re.IGNORECASE),
            "Keep CSRF protection enabled unless there is a documented compensating control.",
        ),
        (
            "high",
            re.compile(r"allow_any|allowall|permit_all|public_access|skip_authorization|skip_before_action", re.IGNORECASE),
            "Confirm this route or action is intended to be public and add tests for unauthenticated and unauthorized users.",
        ),
        (
            "high",
            re.compile(r"(is_admin|is_staff|is_superuser|has_permission|authorized|authenticated).*return\s+True", re.IGNORECASE),
            "Do not replace authorization decisions with unconditional success. Enforce the intended role or policy check.",
        ),
        (
            "medium",
            re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false", re.IGNORECASE),
            "Do not disable TLS verification in production paths.",
        ),
    ]

    findings = []
    reviews = []
    concrete_locations = set()

    for line in iter_added_lines(parsed_diff):
        for severity, pattern, recommendation in concrete_patterns:
            if pattern.search(line["content"]):
                concrete_locations.add((line["file"], line["line_range"], line["content"]))
                findings.append(
                    make_finding(
                        context,
                        gate="auth and permission changes",
                        severity=severity,
                        line=line,
                        evidence=line["content"],
                        recommendation=recommendation,
                    )
                )
                break

    for line in iter_added_lines(parsed_diff):
        location = (line["file"], line["line_range"], line["content"])
        if location in concrete_locations:
            continue
        if AUTH_TERMS.search(line["file"]) or AUTH_TERMS.search(line["content"]):
            reviews.append(
                make_manual_review(
                    context,
                    gate="auth and permission changes",
                    category="auth or privilege boundary touched",
                    file=line["file"],
                    line_range=line["line_range"],
                    evidence=line["content"],
                    reason="The changed line appears to affect authentication, authorization, sessions, roles, or privilege checks.",
                    checklist=[
                        "Identify who can reach this code path before and after the change.",
                        "Check unauthenticated, low-privilege, and cross-tenant cases.",
                        "Trace the nearest route handler, middleware, policy, or guard that enforces access.",
                    ],
                    recommendation="Ask a reviewer or Codex to inspect the surrounding auth flow before merging.",
                )
            )

    return make_gate_output("auth and permission changes", findings=findings, manual_review=reviews)


def make_gate_output(
    name: str,
    findings: list[dict[str, Any]] | None = None,
    manual_review: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    findings = findings or []
    manual_review = manual_review or []

    if findings:
        status = "fail"
    elif manual_review:
        status = MANUAL_REVIEW_REQUIRED
    else:
        status = "done"

    return {
        "schema_version": "gate-output.v1",
        "name": name,
        "type": "rule-based",
        "status": status,
        "findings": findings,
        "manual_review": manual_review,
    }


def make_finding(
    context: GateContext,
    gate: str,
    severity: str,
    line: dict[str, Any],
    evidence: str,
    recommendation: str,
    title: str | None = None,
) -> dict[str, Any]:
    return {
        "id": context.next_finding_id(),
        "gate": gate,
        "severity": severity,
        "file": line["file"],
        "line": line["line"],
        "line_range": line["line_range"],
        "title": title or FINDING_TITLES.get(gate, "Possible security issue"),
        "evidence": evidence.strip(),
        "recommendation": recommendation,
    }


def make_manual_review(
    context: GateContext,
    gate: str,
    category: str,
    file: str,
    line_range: str,
    evidence: str,
    reason: str,
    checklist: list[str],
    recommendation: str,
) -> dict[str, Any]:
    return {
        "id": context.next_manual_review_id(),
        "gate": gate,
        "category": category,
        "file": file,
        "line_range": line_range,
        "evidence": evidence.strip(),
        "reason": reason,
        "checklist": checklist,
        "recommendation": recommendation,
    }


def iter_files(parsed_diff: dict[str, Any]):
    for section_name in ("unstaged", "staged"):
        for file_diff in parsed_diff.get(section_name, {}).get("files", []):
            yield file_diff


def iter_added_lines(parsed_diff: dict[str, Any]):
    for section_name in ("unstaged", "staged"):
        for file_diff in parsed_diff.get(section_name, {}).get("files", []):
            path = file_diff.get("path") or "unknown"
            for hunk in file_diff.get("hunks", []):
                for block in hunk.get("added", []):
                    for offset, content in enumerate(block.get("content", [])):
                        line_number = block.get("start_line", 0) + offset
                        yield {
                            "section": section_name,
                            "file": path,
                            "line": line_number,
                            "line_range": str(line_number),
                            "block_line_range": block.get("line_range", str(line_number)),
                            "content": content,
                        }
