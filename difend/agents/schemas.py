"""Structured contracts shared by the agentic scan graph."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, NotRequired, TypedDict

from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = "2026-04-29.3"


class RiskArea(str, Enum):
    AUTH = "auth"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    SECRETS = "secrets"
    CRYPTO = "crypto"
    DEPENDENCY = "dependency"
    LOGGING = "logging"
    PAYMENT = "payment"
    SESSION = "session"
    FILE_ACCESS = "file_access"
    BUSINESS_LOGIC = "business_logic"
    LOW_RISK = "low_risk"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentStatus(str, Enum):
    SKIPPED = "skipped"
    COMPLETED = "completed"
    FAILED = "failed"


class AddedLine(BaseModel):
    file: str
    line: int
    content: str


class ChangedFile(BaseModel):
    path: str
    added_lines: list[AddedLine] = Field(default_factory=list)


class ScanContext(BaseModel):
    patch: str
    changed_files: list[ChangedFile] = Field(default_factory=list)
    added_lines: list[AddedLine] = Field(default_factory=list)
    diff_hash: str

    @property
    def has_changes(self) -> bool:
        return bool(self.patch.strip())


class ContextFile(BaseModel):
    path: str
    reason: str
    content: str
    truncated: bool = False


class ExpandedContext(BaseModel):
    files: list[ContextFile] = Field(default_factory=list)
    total_bytes: int = 0
    truncated: bool = False


class DiffClassifierResult(BaseModel):
    risk_areas: list[RiskArea] = Field(default_factory=list)
    sensitive_files: list[str] = Field(default_factory=list)
    reason: str = ""
    should_run_security_reasoning: bool = False
    used_llm: bool = False

    @field_validator("risk_areas")
    @classmethod
    def default_low_risk(cls, value: list[RiskArea]) -> list[RiskArea]:
        return value or [RiskArea.LOW_RISK]


class LLMDiffClassifierResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_areas: list[RiskArea] = Field(default_factory=list)
    sensitive_files: list[str] = Field(default_factory=list)
    reason: str = ""
    should_run_security_reasoning: bool = False


class GateCandidate(BaseModel):
    candidate_id: str
    vulnerability_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file: str
    line: int | None = None
    evidence: str
    recommendation: str
    rule_id: str


class LLMGateValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    severity: Severity | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: str | None = None
    recommendation: str | None = None


class LLMGateValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validations: list[LLMGateValidation] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    vulnerability_type: str
    gate_name: str = "automated_gates"
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file: str
    line: int | None = None
    evidence: str
    recommendation: str
    source: str = "automated_gates"
    suppressed: bool = False
    suppression_reason: str | None = None
    evidence_fingerprint: str


class AutomatedGatesResult(BaseModel):
    candidates: list[GateCandidate] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    rejected_llm_outputs: list[str] = Field(default_factory=list)
    llm_validation: LLMGateValidationResult | None = None
    used_llm_validation: bool = False


class ManualReviewItem(BaseModel):
    manual_review_id: str
    area: RiskArea
    vulnerability_type: str
    risk_level: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file: str
    line: int | None = None
    reason: str
    evidence: str
    questions: list[str] = Field(default_factory=list)
    evidence_fingerprint: str
    source: str = "security_reasoning"
    suppressed: bool = False
    suppression_reason: str | None = None


class LLMSecurityReasoningItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    area: RiskArea
    vulnerability_type: str
    risk_level: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file: str
    line: int | None = None
    reason: str
    evidence: str
    questions: list[str] = Field(default_factory=list)


class LLMSecurityReasoningResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manual_review: list[LLMSecurityReasoningItem] = Field(default_factory=list)


class HandoffResult(BaseModel):
    inspect_next: list[str] = Field(default_factory=list)
    codex_tasks: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    safest_next_action: str = "No risky changes were detected."


class LLMHandoffResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inspect_next: list[str] = Field(default_factory=list)
    codex_tasks: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    safest_next_action: str = "No risky changes were detected."


class AgentExecution(BaseModel):
    name: str
    status: AgentStatus
    used_llm: bool = False
    detail: str = ""


class FeedbackRecord(BaseModel):
    item_id: str
    item_type: str = "finding"
    label: str
    evidence_fingerprint: str
    reason: str
    run_id: str = ""
    created_at: str = ""
    file: str = ""
    line: int | None = None
    severity: Severity | None = None
    force: bool = False


class AgenticScanResult(BaseModel):
    status: str
    scan_context: ScanContext
    classifier: DiffClassifierResult
    expanded_context: ExpandedContext
    gates: AutomatedGatesResult
    manual_review: list[ManualReviewItem] = Field(default_factory=list)
    covered_manual_review: list[ManualReviewItem] = Field(default_factory=list)
    suppressed_findings: list[Finding] = Field(default_factory=list)
    suppressed_manual_review: list[ManualReviewItem] = Field(default_factory=list)
    handoff: HandoffResult
    risk_score: int = 0
    agents: list[AgentExecution] = Field(default_factory=list)
    model: str
    cache_hit: bool = False
    cache_key: str = ""
    context_hash: str = ""
    feedback_digest: str = ""
    trace: dict[str, Any] = Field(default_factory=dict)


class AgentGraphState(TypedDict):
    repository_path: Path
    model: str
    patch: str
    scan_context: NotRequired[ScanContext]
    classifier: NotRequired[DiffClassifierResult]
    expanded_context: NotRequired[ExpandedContext]
    gates: NotRequired[AutomatedGatesResult]
    manual_review: NotRequired[list[ManualReviewItem]]
    covered_manual_review: NotRequired[list[ManualReviewItem]]
    suppressed_findings: NotRequired[list[Finding]]
    suppressed_manual_review: NotRequired[list[ManualReviewItem]]
    handoff: NotRequired[HandoffResult]
    risk_score: NotRequired[int]
    status: NotRequired[str]
    agents: NotRequired[list[AgentExecution]]
    cache_hit: NotRequired[bool]
    cache_key: NotRequired[str]
    context_hash: NotRequired[str]
    feedback_digest: NotRequired[str]
    cached_result: NotRequired[AgenticScanResult]
    trace: NotRequired[dict[str, Any]]
    errors: NotRequired[list[str]]
    metadata: NotRequired[dict[str, Any]]
