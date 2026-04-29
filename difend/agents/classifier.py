"""Diff Classifier Agent."""

from __future__ import annotations

from difend.agents.model import ModelConfigurationError, StructuredModelClient
from difend.agents.prompts import CLASSIFIER_PROMPT, PROMPT_VERSION
from difend.agents.schemas import (
    AddedLine,
    AgentExecution,
    AgentStatus,
    DiffClassifierResult,
    LLMDiffClassifierResult,
    RiskArea,
    ScanContext,
)


LOW_RISK_EXTENSIONS = {".md", ".txt", ".rst", ".png", ".jpg", ".jpeg", ".gif"}
RISK_KEYWORDS: dict[RiskArea, tuple[str, ...]] = {
    RiskArea.AUTH: ("auth", "login", "logout", "jwt", "token", "password"),
    RiskArea.AUTHORIZATION: ("permission", "role", "admin", "authorize", "policy"),
    RiskArea.DATABASE: ("sql", "query", "cursor", "execute", "select ", "insert "),
    RiskArea.SECRETS: ("secret", "api_key", "apikey", "private_key", "token"),
    RiskArea.CRYPTO: ("md5", "sha1", "cipher", "crypto", "encrypt", "decrypt"),
    RiskArea.DEPENDENCY: ("requirements", "package.json", "pyproject", "lock"),
    RiskArea.LOGGING: ("log", "logger", "print("),
    RiskArea.PAYMENT: ("payment", "stripe", "invoice", "billing", "checkout"),
    RiskArea.SESSION: ("session", "cookie", "csrf"),
    RiskArea.FILE_ACCESS: ("open(", "path", "file", "upload", "download"),
    RiskArea.BUSINESS_LOGIC: ("discount", "price", "limit", "quota", "workflow"),
}


def classify_diff(
    scan_context: ScanContext,
    model_client: StructuredModelClient | None,
) -> tuple[DiffClassifierResult, AgentExecution]:
    heuristic = classify_with_heuristics(scan_context)
    if not scan_context.has_changes:
        return heuristic, AgentExecution(
            name="diff_classifier",
            status=AgentStatus.SKIPPED,
            detail="No diff to classify.",
        )

    if _confidently_low_risk(scan_context, heuristic):
        return heuristic, AgentExecution(
            name="diff_classifier",
            status=AgentStatus.COMPLETED,
            detail="Classified as low risk from heuristics.",
        )

    if model_client is None:
        raise ModelConfigurationError(
            "OPENAI_API_KEY is required because the diff is not confidently low risk."
        )

    payload = {
        "prompt_version": PROMPT_VERSION,
        "patch": scan_context.patch,
        "changed_files": [file.path for file in scan_context.changed_files],
        "heuristic_risk_areas": [area.value for area in heuristic.risk_areas],
    }
    result = model_client.invoke_structured(
        CLASSIFIER_PROMPT,
        payload,
        LLMDiffClassifierResult,
        node_name="diff_classifier",
    )
    result = _normalize_llm_classifier(result)
    if RiskArea.LOW_RISK not in result.risk_areas and result.risk_areas:
        result.should_run_security_reasoning = (
            result.should_run_security_reasoning
            or _has_sensitive_area(result.risk_areas)
        )
    return result, AgentExecution(
        name="diff_classifier",
        status=AgentStatus.COMPLETED,
        used_llm=True,
        detail="Classified diff with LLM structured output.",
    )


def classify_with_heuristics(scan_context: ScanContext) -> DiffClassifierResult:
    if not scan_context.has_changes:
        return DiffClassifierResult(
            risk_areas=[RiskArea.LOW_RISK],
            reason="No diff was captured.",
        )

    areas: set[RiskArea] = set()
    sensitive_files: set[str] = set()

    for changed_file in scan_context.changed_files:
        path_lower = changed_file.path.lower()
        for area, keywords in RISK_KEYWORDS.items():
            if any(keyword in path_lower for keyword in keywords):
                areas.add(area)
                sensitive_files.add(changed_file.path)

        for added in changed_file.added_lines:
            _classify_line(added, areas, sensitive_files)

    if not areas:
        areas.add(RiskArea.LOW_RISK)

    return DiffClassifierResult(
        risk_areas=sorted(areas, key=lambda area: area.value),
        sensitive_files=sorted(sensitive_files),
        reason="Heuristic classification from changed paths and added lines.",
        should_run_security_reasoning=_has_sensitive_area(areas),
    )


def _classify_line(
    line: AddedLine,
    areas: set[RiskArea],
    sensitive_files: set[str],
) -> None:
    lower = line.content.lower()
    for area, keywords in RISK_KEYWORDS.items():
        if any(keyword in lower for keyword in keywords):
            areas.add(area)
            sensitive_files.add(line.file)


def _confidently_low_risk(
    scan_context: ScanContext,
    classifier: DiffClassifierResult,
) -> bool:
    if classifier.risk_areas != [RiskArea.LOW_RISK]:
        return False
    return all(
        any(file.path.lower().endswith(extension) for extension in LOW_RISK_EXTENSIONS)
        for file in scan_context.changed_files
    )


def _has_sensitive_area(areas: set[RiskArea] | list[RiskArea]) -> bool:
    sensitive = {
        RiskArea.AUTH,
        RiskArea.AUTHORIZATION,
        RiskArea.DATABASE,
        RiskArea.CRYPTO,
        RiskArea.PAYMENT,
        RiskArea.SESSION,
        RiskArea.FILE_ACCESS,
        RiskArea.BUSINESS_LOGIC,
    }
    return bool(set(areas) & sensitive)


def _normalize_llm_classifier(result: LLMDiffClassifierResult) -> DiffClassifierResult:
    return DiffClassifierResult(
        risk_areas=result.risk_areas or [RiskArea.LOW_RISK],
        sensitive_files=sorted(set(result.sensitive_files)),
        reason=result.reason,
        should_run_security_reasoning=result.should_run_security_reasoning,
        used_llm=True,
    )
