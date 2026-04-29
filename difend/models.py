"""Shared report models for Difend agents."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Security severity levels for automated findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GateStatus(str, Enum):
    """Outcome for one automated gate or an aggregate gate run."""

    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True)
class AddedLine:
    """One added line extracted from a unified diff."""

    file: str
    line: int | None
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "text": self.text,
        }


@dataclass(frozen=True)
class Finding:
    """Concrete security issue detected by an automated gate."""

    gate: str
    severity: Severity
    file: str
    line: int | None
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class GateResult:
    """Findings produced by one automated gate."""

    gate: str
    findings: tuple[Finding, ...] = ()

    @property
    def status(self) -> GateStatus:
        if self.findings:
            return GateStatus.FAIL

        return GateStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class AutomatedGatesResult:
    """Aggregate result returned by the Automated Gates Agent."""

    gate_results: tuple[GateResult, ...] = ()

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for gate_result in self.gate_results
            for finding in gate_result.findings
        )

    @property
    def status(self) -> GateStatus:
        if self.findings:
            return GateStatus.FAIL

        return GateStatus.PASS

    @property
    def passed(self) -> bool:
        return self.status is GateStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "gates": [gate_result.to_dict() for gate_result in self.gate_results],
        }
