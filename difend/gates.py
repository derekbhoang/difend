from __future__ import annotations

import re
from pathlib import PurePosixPath

from difend.models import Finding, ManualReviewItem, ParsedDiff

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"
    ),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9_]{20,})\b"),
]

DEPENDENCY_FILES = {
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

INJECTION_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bshell\s*=\s*True\b"),
    re.compile(r"\bsubprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True"),
    re.compile(r"\bexecute\s*\(\s*f[\"']"),
    re.compile(r"\bexecute\s*\([^)]*%[^)]*\)"),
    re.compile(r"\bSELECT\b.+\+.+\bFROM\b", re.IGNORECASE),
]

AUTH_KEYWORDS = {
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


def run_gates(parsed_diff: ParsedDiff) -> tuple[tuple[Finding, ...], tuple[ManualReviewItem, ...]]:
    findings: list[Finding] = []
    manual_review_items: list[ManualReviewItem] = []

    findings.extend(check_secrets(parsed_diff))
    findings.extend(check_dependency_changes(parsed_diff))
    findings.extend(check_injection_risks(parsed_diff))
    manual_review_items.extend(check_auth_permission_changes(parsed_diff))

    return tuple(findings), tuple(manual_review_items)


def check_secrets(parsed_diff: ParsedDiff) -> list[Finding]:
    findings: list[Finding] = []
    for line in parsed_diff.added_lines:
        if any(pattern.search(line.content) for pattern in SECRET_PATTERNS):
            findings.append(
                Finding(
                    gate="secrets",
                    severity="critical",
                    file=line.file,
                    line=line.line,
                    evidence=_redact(line.content),
                    recommendation=(
                        "Remove the secret from the diff, rotate the exposed value, "
                        "and load it from a secure secret manager or environment variable."
                    ),
                )
            )
    return findings


def check_dependency_changes(parsed_diff: ParsedDiff) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in parsed_diff.changed_files:
        if PurePosixPath(file_path).name in DEPENDENCY_FILES:
            findings.append(
                Finding(
                    gate="dependency changes",
                    severity="medium",
                    file=file_path,
                    line=None,
                    evidence=f"Dependency manifest or lockfile changed: {file_path}",
                    recommendation=(
                        "Review added, removed, or upgraded dependencies for known "
                        "vulnerabilities, typosquatting, and unexpected transitive risk."
                    ),
                )
            )
    return findings


def check_injection_risks(parsed_diff: ParsedDiff) -> list[Finding]:
    findings: list[Finding] = []
    for line in parsed_diff.added_lines:
        if any(pattern.search(line.content) for pattern in INJECTION_PATTERNS):
            findings.append(
                Finding(
                    gate="injection risks",
                    severity="high",
                    file=line.file,
                    line=line.line,
                    evidence=line.content.strip(),
                    recommendation=(
                        "Verify user input is not executed or interpolated into commands "
                        "or queries. Prefer parameterized queries and shell-free process APIs."
                    ),
                )
            )
    return findings


def check_auth_permission_changes(parsed_diff: ParsedDiff) -> list[ManualReviewItem]:
    items: list[ManualReviewItem] = []
    seen_locations: set[str] = set()
    seen_paths: set[str] = set()

    for line in parsed_diff.added_lines:
        file_lower = line.file.lower()
        content_lower = line.content.lower()
        if not _contains_auth_keyword(file_lower, content_lower):
            continue
        key = f"{line.file}:{line.line}"
        if key in seen_locations:
            continue
        seen_locations.add(key)
        seen_paths.add(line.file)
        items.append(
            ManualReviewItem(
                gate="auth and permission changes",
                file=line.file,
                line=line.line,
                reason=(
                    "Changed code appears to touch authentication, authorization, "
                    "permissions, sessions, roles, or related security boundaries."
                ),
                evidence=line.content.strip(),
                recommendation=(
                    "Ask a reviewer or Codex to inspect the changed control flow, "
                    "caller permissions, bypass conditions, and related tests."
                ),
            )
        )

    for file_path in parsed_diff.changed_files:
        file_lower = file_path.lower()
        if file_path in seen_paths:
            continue
        if any(keyword in file_lower for keyword in AUTH_KEYWORDS):
            items.append(
                ManualReviewItem(
                    gate="auth and permission changes",
                    file=file_path,
                    line=None,
                    reason="Changed file path appears security-sensitive.",
                    evidence=f"Security-sensitive path: {file_path}",
                    recommendation=(
                        "Review whether the diff changes access control, session handling, "
                        "role checks, or authentication behavior."
                    ),
                )
            )

    return items


def _contains_auth_keyword(file_lower: str, content_lower: str) -> bool:
    return any(
        keyword in file_lower or keyword in content_lower for keyword in AUTH_KEYWORDS
    )


def _redact(value: str) -> str:
    stripped = value.strip()
    if len(stripped) <= 24:
        return "[redacted secret-like value]"
    return stripped[:12] + "...[redacted]..." + stripped[-4:]
