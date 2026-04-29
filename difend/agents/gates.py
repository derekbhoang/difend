"""Rule-led Automated Gates Agent."""

from __future__ import annotations

import re

from difend.agents.model import StructuredModelClient
from difend.agents.prompts import GATES_VALIDATION_PROMPT, PROMPT_VERSION
from difend.agents.schemas import (
    AgentExecution,
    AgentStatus,
    AutomatedGatesResult,
    Finding,
    GateCandidate,
    LLMGateValidationResult,
    ScanContext,
    Severity,
)
from difend.agents.utils import evidence_fingerprint, stable_short_hash


GATES_VERSION = "2026-04-29.2"

SECRET_RE = re.compile(
    r"(?i)\b[\w-]*(api[_-]?key|secret|token|password|private[_-]?key)[\w-]*\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)['\"](?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})['\"]"
)
SHELL_RE = re.compile(r"\b(os\.system|subprocess\.(?:run|call|Popen)|exec\(|eval\()")
SQL_RE = re.compile(
    r"(?i)(select|insert|update|delete).*(\+|f['\"]|\.format\(|%\s*\()"
)
WEAK_CRYPTO_RE = re.compile(r"(?i)\b(md5|sha1|des|rc4)\b")
SENSITIVE_LOG_RE = re.compile(
    r"(?i)(log|logger|print)\s*\(.*(password|token|secret|api[_-]?key)"
)
DISABLED_AUTH_RE = re.compile(
    r"(?i)(auth|permission|csrf|verify|validate).*(false|none|disabled|skip|bypass)"
)
DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pipfile.lock",
}


def run_automated_gates(
    scan_context: ScanContext,
    model_client: StructuredModelClient | None,
) -> tuple[AutomatedGatesResult, AgentExecution]:
    candidates = find_gate_candidates(scan_context)
    if not candidates:
        return AutomatedGatesResult(), AgentExecution(
            name="automated_gates",
            status=AgentStatus.COMPLETED,
            detail="No rule candidates were detected.",
        )

    result = AutomatedGatesResult(candidates=candidates)
    if model_client is not None:
        validation = model_client.invoke_structured(
            GATES_VALIDATION_PROMPT,
            {
                "prompt_version": PROMPT_VERSION,
                "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
                "patch": scan_context.patch,
            },
            LLMGateValidationResult,
            node_name="automated_gates_validation",
        )
        result = _apply_validation(candidates, validation)
        result.used_llm_validation = True
    else:
        result.findings = [_candidate_to_finding(candidate) for candidate in candidates]

    return result, AgentExecution(
        name="automated_gates",
        status=AgentStatus.COMPLETED,
        used_llm=result.used_llm_validation,
        detail=f"Detected {len(result.findings)} concrete finding(s).",
    )


def find_gate_candidates(scan_context: ScanContext) -> list[GateCandidate]:
    candidates: list[GateCandidate] = []
    for added in scan_context.added_lines:
        checks = [
            ("hardcoded_secret", "secret_scan", SECRET_RE, Severity.HIGH, "Move secret to an environment variable or secret manager."),
            ("hardcoded_secret", "secret_value_scan", SECRET_VALUE_RE, Severity.HIGH, "Remove the secret-like literal from source and load it from a secret store or environment variable."),
            ("dangerous_shell_execution", "shell_execution", SHELL_RE, Severity.HIGH, "Avoid shell execution or pass explicit argv with strict validation."),
            ("sql_injection", "sql_injection", SQL_RE, Severity.HIGH, "Use parameterized queries instead of string-built SQL."),
            ("weak_crypto", "weak_crypto", WEAK_CRYPTO_RE, Severity.MEDIUM, "Use a modern approved cryptographic primitive."),
            ("sensitive_logging", "sensitive_logging", SENSITIVE_LOG_RE, Severity.MEDIUM, "Remove sensitive values from logs."),
            ("disabled_auth_check", "disabled_auth", DISABLED_AUTH_RE, Severity.HIGH, "Keep authentication and authorization checks enforced."),
        ]
        for vulnerability_type, rule_id, pattern, severity, recommendation in checks:
            if _is_noise_controlled(vulnerability_type, added.file, added.content):
                continue
            if pattern.search(added.content):
                candidates.append(
                    _candidate(
                        vulnerability_type=vulnerability_type,
                        rule_id=rule_id,
                        severity=severity,
                        file=added.file,
                        line=added.line,
                        evidence=added.content.strip(),
                        recommendation=recommendation,
                    )
                )

    for changed_file in scan_context.changed_files:
        name = changed_file.path.lower().replace("\\", "/").split("/")[-1]
        if name in DEPENDENCY_FILES and changed_file.added_lines:
            candidates.append(
                _candidate(
                    vulnerability_type="dependency_risk",
                    rule_id="dependency_change",
                    severity=Severity.LOW,
                    file=changed_file.path,
                    line=changed_file.added_lines[0].line,
                    evidence="Dependency manifest changed.",
                    recommendation="Review new or changed dependencies for security posture.",
                )
            )

    return candidates


def _candidate(
    vulnerability_type: str,
    rule_id: str,
    severity: Severity,
    file: str,
    line: int | None,
    evidence: str,
    recommendation: str,
) -> GateCandidate:
    candidate_id = stable_short_hash(
        f"{file}:{line}:{vulnerability_type}:{rule_id}:{evidence}"
    )
    return GateCandidate(
        candidate_id=candidate_id,
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=0.85,
        file=file,
        line=line,
        evidence=evidence,
        recommendation=recommendation,
        rule_id=rule_id,
    )


def _apply_validation(
    candidates: list[GateCandidate],
    validation: LLMGateValidationResult,
) -> AutomatedGatesResult:
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    validation_by_id = {}
    rejected: list[str] = []

    for item in validation.validations:
        candidate = by_id.get(item.candidate_id)
        if candidate is None:
            rejected.append(item.candidate_id)
            continue
        validation_by_id[candidate.candidate_id] = item

    findings = []
    for candidate in candidates:
        item = validation_by_id.get(candidate.candidate_id)
        findings.append(
            _candidate_to_finding(
                candidate,
                severity=item.severity if item else None,
                confidence=item.confidence if item else None,
                evidence=item.evidence if item else None,
                recommendation=item.recommendation if item else None,
            )
        )

    return AutomatedGatesResult(
        candidates=candidates,
        findings=findings,
        rejected_llm_outputs=rejected,
        llm_validation=validation,
    )


def _candidate_to_finding(
    candidate: GateCandidate,
    severity: Severity | None = None,
    confidence: float | None = None,
    evidence: str | None = None,
    recommendation: str | None = None,
) -> Finding:
    evidence_value = evidence or candidate.evidence
    fingerprint = evidence_fingerprint(
        candidate.file,
        candidate.line,
        candidate.vulnerability_type,
        evidence_value,
    )
    return Finding(
        finding_id=f"finding-{fingerprint}",
        vulnerability_type=candidate.vulnerability_type,
        severity=severity or candidate.severity,
        confidence=confidence if confidence is not None else candidate.confidence,
        file=candidate.file,
        line=candidate.line,
        evidence=evidence_value,
        recommendation=recommendation or candidate.recommendation,
        evidence_fingerprint=fingerprint,
    )


def _is_noise_controlled(vulnerability_type: str, file: str, content: str) -> bool:
    if vulnerability_type == "hardcoded_secret" and _is_marked_test_placeholder(
        file,
        content,
    ):
        return True
    if vulnerability_type in {
        "weak_crypto",
        "disabled_auth_check",
    } and _is_scanner_rule_definition(file, content):
        return True
    return False


def _is_marked_test_placeholder(file: str, content: str) -> bool:
    normalized = file.replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    is_test_file = (
        "test" in parts
        or "tests" in parts
        or normalized.startswith("test_")
        or "/test_" in normalized
        or normalized.endswith("_test.py")
        or ".spec." in normalized
        or ".test." in normalized
    )
    if not is_test_file:
        return False

    lower = content.lower()
    markers = {
        "fake",
        "placeholder",
        "dummy",
        "example",
        "mock",
        "not-a-real-secret",
        "not real",
        "test data",
        "fixture",
    }
    return any(marker in lower for marker in markers)


def _is_scanner_rule_definition(file: str, content: str) -> bool:
    normalized = file.replace("\\", "/").lower()
    if not normalized.startswith("difend/agents/"):
        return False

    lower = content.lower()
    rule_markers = {
        "re.compile",
        "_re =",
        "riskarea.",
        "risk_keywords",
        "weak_crypto_re",
        "disabled_auth_re",
        "secret_re",
    }
    return any(marker in lower for marker in rule_markers)
