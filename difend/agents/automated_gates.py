"""Automated gate helpers for diff-only security checks."""

from __future__ import annotations

import re

from difend.diff import CodeDiff
from difend.models import AddedLine, AutomatedGatesResult, Finding, GateResult, Severity


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
SECRETS_GATE = "secrets"
UNSAFE_SHELL_EXECUTION_GATE = "unsafe shell execution"
INJECTION_PATTERNS_GATE = "injection patterns"
WEAK_CRYPTO_GATE = "weak crypto"
DEPENDENCY_CHANGES_GATE = "dependency changes"
DEPENDENCY_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "yarn.lock",
    }
)
SECRET_PATTERNS = (
    re.compile(
        r"\b(api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key)"
        r"\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        re.IGNORECASE,
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
UNSAFE_SHELL_EXECUTION_PATTERNS = (
    re.compile(r"\bshell\s*=\s*True\b"),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bos\.popen\s*\("),
    re.compile(r"\bsubprocess\.(run|call|check_call|check_output|Popen)\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
)
INJECTION_PATTERNS = (
    re.compile(
        r"\b(cursor|db|conn|connection|session|query)\."
        r"(execute|executemany|raw|query)\s*\(\s*f['\"]",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(cursor|db|conn|connection|session|query)\."
        r"(execute|executemany|raw|query)\s*\([^)]*['\"][^'\"]*['\"]\s*%",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(cursor|db|conn|connection|session|query)\."
        r"(execute|executemany|raw|query)\s*\([^)]*['\"][^'\"]*['\"]\s*\+",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(cursor|db|conn|connection|session|query)\."
        r"(execute|executemany|raw|query)\s*\([^)]*\.format\s*\(",
        re.IGNORECASE,
    ),
)
WEAK_CRYPTO_PATTERNS = (
    re.compile(r"\bhashlib\.(md5|sha1)\s*\(", re.IGNORECASE),
    re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE),
    re.compile(r"\bverify\s*=\s*False\b"),
    re.compile(r"\bssl\._create_unverified_context\s*\("),
    re.compile(r"\bDES\b"),
    re.compile(
        r"\brandom\.(random|randint|randrange|choice|choices)\s*\("
        r".*\b(token|secret|password|passwd|pwd|session|key)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(token|secret|password|passwd|pwd|session|key)\b"
        r".*\brandom\.(random|randint|randrange|choice|choices)\s*\(",
        re.IGNORECASE,
    ),
)
RISKY_DEPENDENCY_PATTERNS = (
    re.compile(r"\bhttps?://[^\s'\",)]+", re.IGNORECASE),
    re.compile(r"\bgit\+(https?|ssh|git)://[^\s'\",)]+", re.IGNORECASE),
    re.compile(r"\bgit://[^\s'\",)]+", re.IGNORECASE),
    re.compile(r"\bfile:[^\s'\",)]+", re.IGNORECASE),
    re.compile(r"(^|[=:\s'\"])\.\.?[/\\][^\s'\",)]+"),
    re.compile(r"\b[^\s'\",)]+\.(zip|tar|tar\.gz|tgz|whl)\b", re.IGNORECASE),
)


class AutomatedGatesAgent:
    """Run deterministic automated security gates over added diff lines."""

    def run(self, diff: CodeDiff) -> AutomatedGatesResult:
        added_lines = parse_added_lines(diff)

        return AutomatedGatesResult(
            gate_results=(
                check_secrets(added_lines),
                check_unsafe_shell_execution(added_lines),
                check_injection_patterns(added_lines),
                check_weak_crypto(added_lines),
                check_dependency_changes(added_lines),
            )
        )


def parse_added_lines(diff: CodeDiff) -> tuple[AddedLine, ...]:
    """Extract added source lines from all captured diff sections."""

    return tuple(
        added_line
        for patch in (diff.unstaged, diff.staged, diff.untracked)
        for added_line in parse_patch_added_lines(patch)
    )


def parse_patch_added_lines(patch: str) -> tuple[AddedLine, ...]:
    """Extract added source lines from a unified diff patch."""

    added_lines: list[AddedLine] = []
    current_file: str | None = None
    new_line_number: int | None = None

    for line in patch.splitlines():
        if line.startswith("+++ "):
            current_file = _normalize_diff_path(line[4:].strip())
            new_line_number = None
            continue

        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            new_line_number = int(hunk_match.group(1))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if current_file is not None and current_file != "/dev/null":
                added_lines.append(
                    AddedLine(
                        file=current_file,
                        line=new_line_number,
                        text=line[1:],
                    )
                )
            if new_line_number is not None:
                new_line_number += 1
            continue

        if _is_context_line(line) and new_line_number is not None:
            new_line_number += 1

    return tuple(added_lines)


def check_secrets(added_lines: tuple[AddedLine, ...]) -> GateResult:
    """Detect likely hardcoded secrets in added lines."""

    findings = [
        Finding(
            gate=SECRETS_GATE,
            severity=Severity.CRITICAL,
            file=line.file,
            line=line.line,
            evidence="Added line appears to contain a hardcoded secret.",
            recommendation=(
                "Move the secret to environment configuration, remove it from "
                "the diff, and rotate the exposed value."
            ),
        )
        for line in added_lines
        if _matches_any(line.text, SECRET_PATTERNS)
    ]

    return GateResult(gate=SECRETS_GATE, findings=tuple(findings))


def check_unsafe_shell_execution(added_lines: tuple[AddedLine, ...]) -> GateResult:
    """Detect dangerous shell execution patterns in added lines."""

    findings = [
        Finding(
            gate=UNSAFE_SHELL_EXECUTION_GATE,
            severity=Severity.HIGH,
            file=line.file,
            line=line.line,
            evidence="Added line appears to execute dynamic code or shell commands.",
            recommendation=(
                "Avoid shell execution and dynamic evaluation. Use argument lists "
                "for subprocess calls, validate inputs, and remove eval or exec."
            ),
        )
        for line in added_lines
        if _matches_any(line.text, UNSAFE_SHELL_EXECUTION_PATTERNS)
    ]

    return GateResult(
        gate=UNSAFE_SHELL_EXECUTION_GATE,
        findings=tuple(findings),
    )


def check_injection_patterns(added_lines: tuple[AddedLine, ...]) -> GateResult:
    """Detect obvious injection-prone query construction in added lines."""

    findings = [
        Finding(
            gate=INJECTION_PATTERNS_GATE,
            severity=Severity.HIGH,
            file=line.file,
            line=line.line,
            evidence="Added line appears to build a query with string interpolation.",
            recommendation=(
                "Use parameterized queries or the framework query builder instead "
                "of formatting user-controlled values into query strings."
            ),
        )
        for line in added_lines
        if _matches_any(line.text, INJECTION_PATTERNS)
    ]

    return GateResult(
        gate=INJECTION_PATTERNS_GATE,
        findings=tuple(findings),
    )


def check_weak_crypto(added_lines: tuple[AddedLine, ...]) -> GateResult:
    """Detect weak cryptography and disabled transport verification."""

    findings = [
        Finding(
            gate=WEAK_CRYPTO_GATE,
            severity=Severity.HIGH,
            file=line.file,
            line=line.line,
            evidence=(
                "Added line appears to use weak cryptography, insecure "
                "randomness, or disabled TLS verification."
            ),
            recommendation=(
                "Use modern cryptographic primitives, keep TLS verification "
                "enabled, and use secrets or os.urandom for security tokens."
            ),
        )
        for line in added_lines
        if _matches_any(line.text, WEAK_CRYPTO_PATTERNS)
    ]

    return GateResult(
        gate=WEAK_CRYPTO_GATE,
        findings=tuple(findings),
    )


def check_dependency_changes(added_lines: tuple[AddedLine, ...]) -> GateResult:
    """Detect risky dependency sources in dependency manifest changes."""

    findings = [
        Finding(
            gate=DEPENDENCY_CHANGES_GATE,
            severity=Severity.MEDIUM,
            file=line.file,
            line=line.line,
            evidence=(
                "Added dependency line appears to use a direct URL, Git source, "
                "archive, file reference, or local path."
            ),
            recommendation=(
                "Prefer pinned packages from trusted registries. Verify direct "
                "dependency sources before merging and pin immutable versions."
            ),
        )
        for line in added_lines
        if _is_dependency_file(line.file)
        and _matches_any(line.text, RISKY_DEPENDENCY_PATTERNS)
    ]

    return GateResult(
        gate=DEPENDENCY_CHANGES_GATE,
        findings=tuple(findings),
    )


def _normalize_diff_path(path: str) -> str:
    if path.startswith("b/"):
        return path[2:]

    return path


def _is_context_line(line: str) -> bool:
    return bool(line) and not line.startswith(("-", "\\", "diff ", "index "))


def _matches_any(text: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _is_dependency_file(path: str) -> bool:
    normalized_path = path.replace("\\", "/")
    return normalized_path.rsplit("/", maxsplit=1)[-1] in DEPENDENCY_FILES


__all__ = [
    "AutomatedGatesAgent",
    "check_dependency_changes",
    "check_secrets",
    "check_injection_patterns",
    "check_unsafe_shell_execution",
    "check_weak_crypto",
    "parse_added_lines",
    "parse_patch_added_lines",
]
