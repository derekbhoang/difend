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


GATES_VERSION = "2026-04-30.1"

SECRET_RE = re.compile(
    r"(?i)\b[\w-]*(api[_-]?key|secret|token|password|private[_-]?key)[\w-]*\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:['\"])?(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})(?:['\"])?|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
SHELL_RE = re.compile(
    r"\b(os\.system|os\.popen|exec\(|eval\()|"
    r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True\b|"
    r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*(?:cmd|command|user_input|request\.)"
)
SQL_RE = re.compile(
    r"(?i)(select|insert|update|delete).*(\+|f['\"]|\.format\(|%\s*\()"
)
WEAK_CRYPTO_RE = re.compile(
    r"(?i)\b(hashlib\.)?(md5|sha1)\s*\(|\b(des|rc4)\b|\bverify\s*=\s*False\b|\bssl\._create_unverified_context\s*\(|\brandom\.(?:random|randint|randrange|choice|choices)\s*\(.*\b(token|secret|password|passwd|pwd|session|key)\b|\b(token|secret|password|passwd|pwd|session|key)\b.*\brandom\.(?:random|randint|randrange|choice|choices)\s*\("
)
SENSITIVE_LOG_RE = re.compile(
    r"(?i)(log|logger|print)\s*\(.*(password|token|secret|api[_-]?key|authorization|cookie|session|ssn|credit[_-]?card|card[_-]?number)"
)
DISABLED_AUTH_RE = re.compile(
    r"(?i)(auth|permission|csrf|validate).*(false|none|disabled|skip|bypass)"
)
PLAINTEXT_PASSWORD_COLUMN_RE = re.compile(
    r"(?i)\b(pass(?:word)?|passwd|pwd)\b\s+(?:text|varchar|char|string|nvarchar)\b|"
    r"\b(pass(?:word)?|passwd|pwd)\b\s*=\s*(?:db\.)?Column\s*\([^)]*(?:String|Text)"
)
PLAINTEXT_PASSWORD_INSERT_RE = re.compile(
    r"(?i)\binsert\s+into\s+\w*(?:user|account|credential)\w*\s*\([^)]*\b(pass(?:word)?|passwd|pwd)\b"
)
PLAINTEXT_PASSWORD_COMPARISON_RE = re.compile(
    r"(?i)\bselect\b.*\bwhere\b.*\b(pass(?:word)?|passwd|pwd)\b\s*="
)
SAFE_PASSWORD_HASHING_RE = re.compile(
    r"(?i)(generate_password_hash|check_password_hash|bcrypt|argon2|passlib|pbkdf2_hmac|hash_password|verify_password)"
)
DEBUG_MODE_RE = re.compile(
    r"(?i)\b(?:app|application)\.run\s*\([^)]*debug\s*=\s*True\b|"
    r"\b(?:DEBUG|FLASK_DEBUG)\b\s*[:=]\s*True\b|"
    r"\bapp\.config\[[\"']DEBUG[\"']\]\s*=\s*True\b"
)
UNSAFE_DESERIALIZATION_RE = re.compile(
    r"(?i)\b(?:pickle|cPickle)\.(?:loads|load)\s*\(|"
    r"\bmarshal\.loads\s*\(|"
    r"\bjsonpickle\.decode\s*\(|"
    r"\byaml\.load\s*\((?![^)]*(?:SafeLoader|safe_load))"
)
TEMPLATE_INJECTION_RE = re.compile(
    r"(?i)\b(?:render_template_string|Template\s*\(|template\.render)\s*\([^)]*(?:request\.|input\s*\()"
)
NOSQL_INJECTION_RE = re.compile(
    r"(?i)\b(?:find|find_one|update_one|delete_one|aggregate)\s*\([^)]*['\"]\$(?:where|ne|gt|gte|lt|lte|regex)['\"][^)]*(?:request\.|input\s*\()"
)
OPEN_REDIRECT_RE = re.compile(
    r"(?i)\bredirect\s*\([^)]*(?:request\.(?:args|form|values|json)|request\.get_json|input\s*\()"
)
UNSAFE_FILE_ACCESS_RE = re.compile(
    r"(?i)\b(?:open|send_file|send_from_directory|FileResponse)\s*\([^)]*(?:request\.(?:args|form|values|json)|request\.get_json|input\s*\()"
)
UNSAFE_ARCHIVE_RE = re.compile(
    r"(?i)\b(?:tar|zip_ref|archive|zipfile)\.(?:extract|extractall)\s*\("
)
INSECURE_COOKIE_RE = re.compile(
    r"(?i)\bset_cookie\s*\([^)]*(?:session|token|auth|jwt|sid|cookie)[^)]*(?:secure\s*=\s*False|httponly\s*=\s*False)|"
    r"\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\b\s*=\s*False\b"
)
CRYPTO_SECRET_RE = re.compile(
    r"(?i)\b(?:aes|hmac|jwt|fernet|encryption|signing|cipher)[\w-]*(?:key|secret|iv|salt|nonce)[\w-]*\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)
DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "yarn.lock",
}
RISKY_DEPENDENCY_RE = re.compile(
    r"(?i)\bhttps?://[^\s'\",)]+|\bgit\+(?:https?|ssh|git)://[^\s'\",)]+|\bgit://[^\s'\",)]+|\bfile:[^\s'\",)]+|(^|[=:\s'\"])\.\.?[/\\][^\s'\",)]+|\b[^\s'\",)]+\.(?:zip|tar|tar\.gz|tgz|whl)\b"
)
RISKY_INSTALL_COMMAND_RE = re.compile(
    r"(?i)\b(?:pip|npm|yarn|pnpm)\s+install\b.*(?:https?://|git\+|git://|file:|\.\.?[/\\]|\.zip|\.tar|\.tgz|\.whl)"
)


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
            ("plaintext_password_storage", "plaintext_password_storage", PLAINTEXT_PASSWORD_COLUMN_RE, Severity.HIGH, "Store only salted password hashes, not raw passwords."),
            ("plaintext_password_insert", "plaintext_password_insert", PLAINTEXT_PASSWORD_INSERT_RE, Severity.HIGH, "Hash passwords before storing them and insert only the password hash."),
            ("plaintext_password_comparison", "plaintext_password_comparison", PLAINTEXT_PASSWORD_COMPARISON_RE, Severity.HIGH, "Verify submitted passwords with a password hashing verifier instead of comparing raw values."),
            ("debug_mode_enabled", "debug_mode", DEBUG_MODE_RE, Severity.HIGH, "Disable framework debug mode outside local development."),
            ("unsafe_deserialization", "unsafe_deserialization", UNSAFE_DESERIALIZATION_RE, Severity.HIGH, "Use a safe parser and never deserialize untrusted input."),
            ("template_injection", "template_injection", TEMPLATE_INJECTION_RE, Severity.HIGH, "Do not render user-controlled strings as templates."),
            ("nosql_injection", "nosql_injection", NOSQL_INJECTION_RE, Severity.HIGH, "Validate query operators and avoid passing user-controlled objects directly into NoSQL queries."),
            ("open_redirect", "open_redirect", OPEN_REDIRECT_RE, Severity.MEDIUM, "Validate redirect targets against an allowlist or use internal route names."),
            ("path_traversal", "path_traversal", UNSAFE_FILE_ACCESS_RE, Severity.HIGH, "Normalize and validate user-controlled paths before reading or sending files."),
            ("unsafe_archive_extraction", "unsafe_archive_extraction", UNSAFE_ARCHIVE_RE, Severity.HIGH, "Validate archive members before extraction to prevent path traversal."),
            ("insecure_cookie", "insecure_cookie", INSECURE_COOKIE_RE, Severity.HIGH, "Set Secure and HttpOnly flags for authentication/session cookies."),
            ("hardcoded_crypto_key", "crypto_secret", CRYPTO_SECRET_RE, Severity.HIGH, "Move cryptographic keys and signing secrets to a secret manager."),
            ("dependency_risk", "dependency_install_command", RISKY_INSTALL_COMMAND_RE, Severity.MEDIUM, "Avoid installing dependencies directly from mutable URLs, archives, or local paths."),
        ]
        for vulnerability_type, rule_id, pattern, severity, recommendation in checks:
            if _is_noise_controlled(vulnerability_type, added.file, added.content):
                continue
            if _is_safe_password_handling(vulnerability_type, added.content):
                continue
            if vulnerability_type == "path_traversal" and _has_path_validation(added.content):
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
        if _is_permissive_cors(added.content) and not _is_noise_controlled(
            "permissive_cors",
            added.file,
            added.content,
        ):
            candidates.append(
                _candidate(
                    vulnerability_type="permissive_cors",
                    rule_id="permissive_cors",
                    severity=Severity.HIGH,
                    file=added.file,
                    line=added.line,
                    evidence=added.content.strip(),
                    recommendation="Do not combine wildcard CORS origins with credentialed requests.",
                )
            )

    risky_dependency_files: set[str] = set()
    for changed_file in scan_context.changed_files:
        name = changed_file.path.lower().replace("\\", "/").split("/")[-1]
        if name not in DEPENDENCY_FILES:
            continue
        for added in changed_file.added_lines:
            if RISKY_DEPENDENCY_RE.search(added.content):
                risky_dependency_files.add(changed_file.path)
                candidates.append(
                    _candidate(
                        vulnerability_type="dependency_risk",
                        rule_id="dependency_direct_source",
                        severity=Severity.MEDIUM,
                        file=added.file,
                        line=added.line,
                        evidence=added.content.strip(),
                        recommendation=(
                            "Prefer pinned packages from trusted registries. "
                            "Verify direct dependency sources before merging."
                        ),
                    )
                )
        if changed_file.path not in risky_dependency_files and changed_file.added_lines:
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
        gate_name=candidate.rule_id,
        severity=severity or candidate.severity,
        confidence=confidence if confidence is not None else candidate.confidence,
        file=candidate.file,
        line=candidate.line,
        evidence=evidence_value,
        recommendation=recommendation or candidate.recommendation,
        evidence_fingerprint=fingerprint,
    )


def _is_noise_controlled(vulnerability_type: str, file: str, content: str) -> bool:
    if _is_scanner_rule_definition(file, content):
        return True
    if _is_test_fixture_line(file, content):
        return True
    if vulnerability_type == "hardcoded_secret" and _is_marked_test_placeholder(
        file,
        content,
    ):
        return True
    return False


def _is_safe_password_handling(vulnerability_type: str, content: str) -> bool:
    if vulnerability_type not in {
        "plaintext_password_storage",
        "plaintext_password_insert",
        "plaintext_password_comparison",
    }:
        return False
    return bool(SAFE_PASSWORD_HASHING_RE.search(content))


def _has_path_validation(content: str) -> bool:
    lower = content.lower()
    validation_markers = {
        "resolve()",
        "realpath",
        "normpath",
        "safe_join",
        "secure_filename",
        "commonpath",
    }
    return any(marker in lower for marker in validation_markers)


def _is_permissive_cors(content: str) -> bool:
    lower = content.lower().replace(" ", "")
    has_cors = "cors(" in lower or "allow_origins" in lower or "origins" in lower
    has_wildcard = '"*"' in lower or "'*'" in lower or "[*]" in lower
    has_credentials = (
        "supports_credentials=true" in lower
        or "allow_credentials=true" in lower
        or "credentials:true" in lower
    )
    return has_cors and has_wildcard and has_credentials


def _is_marked_test_placeholder(file: str, content: str) -> bool:
    normalized = file.replace("\\", "/").lower()
    if not _is_test_path(normalized):
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


def _is_test_fixture_line(file: str, content: str) -> bool:
    normalized = file.replace("\\", "/").lower()
    if not _is_test_path(normalized):
        return False

    stripped = content.strip()
    if not (
        stripped.startswith(('"', "'"))
        or stripped.startswith(("+", "f\"", "f'"))
        or "\\n" in stripped
    ):
        return False

    fixture_markers = {
        "codediff(",
        "unstaged=(",
        "staged=",
        "diff --git",
        "@@ -",
        "candidate",
        "finding",
    }
    lower = content.lower()
    return (
        any(marker in lower for marker in fixture_markers)
        or stripped.startswith(('"+"', "'+", '"+', "'+"))
        or stripped.endswith(("\",", "',", "\\n\"", "\\n'"))
    )


def _is_test_path(normalized_path: str) -> bool:
    parts = set(normalized_path.split("/"))
    return (
        "test" in parts
        or "tests" in parts
        or normalized_path.startswith("test_")
        or "/test_" in normalized_path
        or normalized_path.endswith("_test.py")
        or ".spec." in normalized_path
        or ".test." in normalized_path
    )


def _is_scanner_rule_definition(file: str, content: str) -> bool:
    normalized = file.replace("\\", "/").lower()
    if not normalized.startswith("difend/agents/"):
        return False

    lower = content.lower()
    stripped = content.strip()
    rule_markers = {
        "re.compile",
        "_re =",
        "riskarea.",
        "risk_keywords",
        "weak_crypto_re",
        "disabled_auth_re",
        "secret_re",
    }
    return any(marker in lower for marker in rule_markers) or stripped.startswith(
        ("r\"", "r'")
    )
