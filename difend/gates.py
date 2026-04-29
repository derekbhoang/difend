"""Rule-based automated gates for Difend scans."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import ClassVar

from difend.diff import DiffLine, ParsedDiff


SEVERITY_MANUAL_REVIEW = "manual review required"
ProgressFn = Callable[[str, str], None]


@dataclass(frozen=True)
class Finding:
    """Shared finding format returned by every automated gate."""

    file: str
    line: int | None
    severity: str
    evidence: str
    gate: str
    recommendation: str
    requires_manual_review: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class GateResult:
    """Summary of one gate execution."""

    gate: str
    status: str
    findings_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class GateRunReport:
    """Combined partial report from all automated gates."""

    findings: tuple[Finding, ...]
    gate_results: tuple[GateResult, ...]

    @property
    def manual_review_findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.requires_manual_review
            or finding.severity == SEVERITY_MANUAL_REVIEW
        )


class Gate(ABC):
    """Base interface for automated gates."""

    name: ClassVar[str]
    progress_label: ClassVar[str]

    @abstractmethod
    def run(self, parsed_diff: ParsedDiff) -> list[Finding]:
        """Return findings for the parsed diff."""


class GateRunner:
    """Run all configured gates and combine their findings."""

    def __init__(self, gates: list[Gate] | None = None) -> None:
        self.gates = gates or default_gates()

    def run(
        self,
        parsed_diff: ParsedDiff,
        progress: ProgressFn | None = None,
    ) -> GateRunReport:
        findings: list[Finding] = []
        gate_results: list[GateResult] = []

        for gate in self.gates:
            _progress(progress, gate.progress_label, "in progress")
            gate_findings = gate.run(parsed_diff)
            findings.extend(gate_findings)
            status = _gate_status(gate_findings)
            gate_results.append(
                GateResult(
                    gate=gate.name,
                    status=status,
                    findings_count=len(gate_findings),
                )
            )
            _progress(progress, gate.progress_label, status)

        return GateRunReport(
            findings=tuple(findings),
            gate_results=tuple(gate_results),
        )


class SecretsGate(Gate):
    name = "secrets"
    progress_label = "Checking secrets"

    SECRET_PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"
        ),
        re.compile(r"\b(sk-[A-Za-z0-9_-]{20,})\b"),
        re.compile(r"\b(ghp_[A-Za-z0-9_]{20,})\b"),
    )

    def run(self, parsed_diff: ParsedDiff) -> list[Finding]:
        findings: list[Finding] = []
        for line in parsed_diff.added_lines:
            if any(pattern.search(line.content) for pattern in self.SECRET_PATTERNS):
                findings.append(
                    Finding(
                        gate=self.name,
                        severity="critical",
                        file=line.file,
                        line=line.line,
                        evidence=_redact(line.content),
                        recommendation=(
                            "Remove the secret from the diff, rotate the exposed "
                            "value, and load it from a secure secret manager or "
                            "environment variable."
                        ),
                    )
                )

        return findings


class DependencyChangeGate(Gate):
    name = "dependency changes"
    progress_label = "Checking dependency changes"

    DEPENDENCY_FILES: ClassVar[set[str]] = {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Gemfile",
        "Gemfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
    }

    def run(self, parsed_diff: ParsedDiff) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in parsed_diff.changed_files:
            if PurePosixPath(file_path).name not in self.DEPENDENCY_FILES:
                continue

            first_added_line = _first_added_line(parsed_diff, file_path)
            if first_added_line is None:
                continue

            findings.append(
                Finding(
                    gate=self.name,
                    severity="medium",
                    file=file_path,
                    line=first_added_line.line,
                    evidence=f"Added dependency file line: {first_added_line.content.strip()}",
                    recommendation=(
                        "Review added, removed, or upgraded dependencies for known "
                        "vulnerabilities, typosquatting, and unexpected transitive risk."
                    ),
                )
            )

        return findings


class InjectionPatternGate(Gate):
    name = "injection risks"
    progress_label = "Checking injection risks"

    INJECTION_PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"\bshell\s*=\s*True\b"),
        re.compile(r"\bsubprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True"),
        re.compile(r"\bexecute\s*\(\s*f[\"']"),
        re.compile(r"\bexecute\s*\([^)]*%[^)]*\)"),
        re.compile(r"\bSELECT\b.+\+.+\bFROM\b", re.IGNORECASE),
    )

    def run(self, parsed_diff: ParsedDiff) -> list[Finding]:
        findings: list[Finding] = []

        for line in parsed_diff.added_lines:
            if any(pattern.search(line.content) for pattern in self.INJECTION_PATTERNS):
                findings.append(
                    Finding(
                        gate=self.name,
                        severity="high",
                        file=line.file,
                        line=line.line,
                        evidence=line.content.strip(),
                        recommendation=(
                            "Verify user input is not executed or interpolated into "
                            "commands or queries. Prefer parameterized queries and "
                            "shell-free process APIs."
                        ),
                    )
                )

        return findings


class AuthPermissionGate(Gate):
    name = "auth and permission changes"
    progress_label = "Checking auth and permission changes"

    AUTH_KEYWORDS: ClassVar[set[str]] = {
        "auth",
        "authorization",
        "authorisation",
        "permission",
        "permissions",
        "privilege",
        "role",
        "roles",
        "session",
        "sessions",
        "jwt",
        "policy",
        "middleware",
        "csrf",
        "oauth",
        "login",
        "logout",
    }

    def run(self, parsed_diff: ParsedDiff) -> list[Finding]:
        findings: list[Finding] = []
        seen_locations: set[str] = set()

        for line in parsed_diff.added_lines:
            file_lower = line.file.lower()
            content_lower = line.content.lower()
            if not self._is_security_sensitive(file_lower, content_lower):
                continue

            key = f"{line.file}:{line.line}:{line.content}"
            if key in seen_locations:
                continue
            seen_locations.add(key)

            findings.append(
                Finding(
                    gate=self.name,
                    severity=SEVERITY_MANUAL_REVIEW,
                    file=line.file,
                    line=line.line,
                    evidence=line.content.strip(),
                    recommendation=(
                        "Manually review whether this change affects authentication, "
                        "authorization, permission checks, session handling, roles, or "
                        "another security boundary."
                    ),
                    requires_manual_review=True,
                )
            )

        return findings

    def _is_security_sensitive(self, file_lower: str, content_lower: str) -> bool:
        return any(
            keyword in file_lower or keyword in content_lower
            for keyword in self.AUTH_KEYWORDS
        )


def default_gates() -> list[Gate]:
    return [
        SecretsGate(),
        DependencyChangeGate(),
        InjectionPatternGate(),
        AuthPermissionGate(),
    ]


def _first_added_line(parsed_diff: ParsedDiff, file_path: str) -> DiffLine | None:
    for line in parsed_diff.added_lines:
        if line.file == file_path:
            return line

    return None


def _gate_status(findings: list[Finding]) -> str:
    if not findings:
        return "done"

    if any(
        finding.requires_manual_review
        or finding.severity == SEVERITY_MANUAL_REVIEW
        for finding in findings
    ):
        return SEVERITY_MANUAL_REVIEW

    return "warning"


def _progress(progress: "ProgressFn | None", label: str, status: str) -> None:
    if progress is not None:
        progress(label, status)


def _redact(value: str) -> str:
    stripped = value.strip()
    if len(stripped) <= 24:
        return "[redacted secret-like value]"

    return stripped[:12] + "...[redacted]..." + stripped[-4:]
