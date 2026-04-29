"""Diff parsing and bounded security-aware context expansion."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from difend.diff import CodeDiff
from difend.agents.schemas import (
    AddedLine,
    ChangedFile,
    DiffClassifierResult,
    ExpandedContext,
    ContextFile,
    RiskArea,
    ScanContext,
)
from difend.agents.utils import normalize_path, stable_hash


HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([a-zA-Z_][\w.]*)\s+import|import\s+([a-zA-Z_][\w.]*))"
)
REFERENCE_RE = re.compile(r"['\"]([^'\"]+\.(?:py|ts|tsx|js|jsx|json|yaml|yml))['\"]")
SECURITY_HINTS = {
    "auth",
    "permission",
    "authorize",
    "session",
    "token",
    "payment",
    "crypto",
    "secret",
    "password",
    "database",
    "query",
    "route",
    "middleware",
}
SKIP_PARTS = {
    ".git",
    ".difend",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
}
SECRET_FILE_NAMES = {".env", ".env.local", ".npmrc", ".pypirc"}


@dataclass(frozen=True)
class ContextLimits:
    max_files: int = 8
    max_bytes_per_file: int = 6000
    max_total_bytes: int = 20000
    snippet_radius: int = 20


def combined_patch(diff: CodeDiff) -> str:
    return diff.unstaged + diff.staged + diff.untracked


def prepare_scan_context(diff: CodeDiff) -> ScanContext:
    patch = combined_patch(diff)
    changed_files: dict[str, list[AddedLine]] = {}
    current_file: str | None = None
    current_line: int | None = None

    for raw_line in patch.splitlines():
        if raw_line.startswith("+++ "):
            current_file = _parse_new_file(raw_line)
            if current_file and current_file != "/dev/null":
                changed_files.setdefault(current_file, [])
            continue

        match = HUNK_RE.match(raw_line)
        if match:
            current_line = int(match.group(1))
            continue

        if current_file is None or current_line is None:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added = AddedLine(
                file=current_file,
                line=current_line,
                content=raw_line[1:],
            )
            changed_files.setdefault(current_file, []).append(added)
            current_line += 1
        elif raw_line.startswith(" ") or raw_line == "":
            current_line += 1

    changed = [
        ChangedFile(path=path, added_lines=lines)
        for path, lines in sorted(changed_files.items())
    ]
    added_lines = [line for file in changed for line in file.added_lines]
    return ScanContext(
        patch=patch,
        changed_files=changed,
        added_lines=added_lines,
        diff_hash=stable_hash(patch),
    )


def expand_context(
    repository_path: Path,
    scan_context: ScanContext,
    classifier: DiffClassifierResult,
    limits: ContextLimits | None = None,
) -> ExpandedContext:
    limits = limits or ContextLimits()
    if not _needs_context(classifier):
        return ExpandedContext()

    selected: list[tuple[str, str, set[int]]] = []
    seen: set[str] = set()

    for changed_file in scan_context.changed_files:
        path = normalize_path(changed_file.path)
        if path not in seen:
            line_numbers = {line.line for line in changed_file.added_lines}
            selected.append((path, "changed file around edited lines", line_numbers))
            seen.add(path)

        for imported in _discover_direct_references(
            repository_path,
            path,
            changed_file.added_lines,
        ):
            if imported not in seen:
                selected.append((imported, "directly referenced security context", set()))
                seen.add(imported)

    files: list[ContextFile] = []
    total_bytes = 0
    truncated = False

    for relative_path, reason, line_numbers in selected:
        if len(files) >= limits.max_files:
            truncated = True
            break

        path = repository_path / relative_path
        if not _safe_to_read(repository_path, path):
            continue

        content = _read_context_file(path, line_numbers, limits)
        content_bytes = len(content.encode("utf-8"))
        if total_bytes + content_bytes > limits.max_total_bytes:
            remaining = limits.max_total_bytes - total_bytes
            if remaining <= 0:
                truncated = True
                break
            content = content.encode("utf-8")[:remaining].decode("utf-8", errors="ignore")
            content_bytes = len(content.encode("utf-8"))
            truncated = True

        files.append(
            ContextFile(
                path=relative_path,
                reason=reason,
                content=content,
                truncated=content_bytes >= limits.max_bytes_per_file,
            )
        )
        total_bytes += content_bytes

    return ExpandedContext(files=files, total_bytes=total_bytes, truncated=truncated)


def _parse_new_file(line: str) -> str:
    path = line[4:].strip()
    if path.startswith("b/"):
        path = path[2:]
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return normalize_path(path)


def _needs_context(classifier: DiffClassifierResult) -> bool:
    sensitive = {
        RiskArea.AUTH,
        RiskArea.AUTHORIZATION,
        RiskArea.DATABASE,
        RiskArea.PAYMENT,
        RiskArea.SESSION,
        RiskArea.FILE_ACCESS,
        RiskArea.BUSINESS_LOGIC,
        RiskArea.CRYPTO,
    }
    return classifier.should_run_security_reasoning or bool(
        set(classifier.risk_areas) & sensitive
    )


def _discover_direct_references(
    repository_path: Path,
    changed_file: str,
    added_lines: list[AddedLine],
) -> list[str]:
    references: list[str] = []
    path = repository_path / changed_file
    suffix = path.suffix.lower()

    if suffix == ".py" and path.exists():
        references.extend(_python_import_references(repository_path, path))

    for line in added_lines:
        lower = line.content.lower()
        if not any(hint in lower for hint in SECURITY_HINTS):
            continue
        for match in REFERENCE_RE.finditer(line.content):
            candidate = normalize_path(match.group(1))
            if _is_safe_relative(candidate):
                references.append(candidate)

    return _unique_existing(repository_path, references)


def _python_import_references(repository_path: Path, path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []

    references: list[str] = []
    for node in ast.walk(tree):
        module: str | None = None
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                references.extend(_module_to_paths(module))
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            references.extend(_module_to_paths(module))

    return _unique_existing(repository_path, references)


def _module_to_paths(module: str) -> list[str]:
    base = normalize_path(module.replace(".", "/"))
    return [f"{base}.py", f"{base}/__init__.py"]


def _unique_existing(repository_path: Path, paths: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in paths:
        normalized = normalize_path(item)
        if normalized in seen:
            continue
        if _safe_to_read(repository_path, repository_path / normalized):
            result.append(normalized)
            seen.add(normalized)
    return result


def _read_context_file(path: Path, line_numbers: set[int], limits: ContextLimits) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""

    if line_numbers:
        selected: list[str] = []
        for line_no in sorted(line_numbers):
            start = max(1, line_no - limits.snippet_radius)
            end = min(len(lines), line_no + limits.snippet_radius)
            selected.append(f"# lines {start}-{end}")
            selected.extend(lines[start - 1 : end])
        content = "\n".join(selected)
    else:
        content = "\n".join(lines)

    raw = content.encode("utf-8")
    if len(raw) <= limits.max_bytes_per_file:
        return content
    return raw[: limits.max_bytes_per_file].decode("utf-8", errors="ignore")


def _safe_to_read(repository_path: Path, path: Path) -> bool:
    try:
        resolved_repo = repository_path.resolve()
        resolved_path = path.resolve()
    except OSError:
        return False

    if not resolved_path.exists() or not resolved_path.is_file():
        return False
    if resolved_repo not in resolved_path.parents and resolved_path != resolved_repo:
        return False
    if path.name in SECRET_FILE_NAMES:
        return False

    parts = {part.lower() for part in resolved_path.relative_to(resolved_repo).parts}
    if parts & SKIP_PARTS:
        return False
    if _looks_binary(resolved_path):
        return False
    return True


def _is_safe_relative(path: str) -> bool:
    return bool(path) and not Path(path).is_absolute() and ".." not in Path(path).parts


def _looks_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:1024]
    except OSError:
        return True
    return b"\0" in sample
