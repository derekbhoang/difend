"""Difend package."""

from difend.agent import (
    AgentReviewError,
    AgentReviewResult,
    OpenAICodexClient,
    review_scan_bundle,
)
from difend.bundle import ScanBundle, ScanBundleRequest, ScanBundleWriter
from difend.diff import (
    CodeDiff,
    DiffCaptureError,
    DiffLine,
    GitDiffCapture,
    ParsedDiff,
    parse_code_diff,
    parse_diff,
)
from difend.gates import (
    Finding,
    Gate,
    GateResult,
    GateRunner,
    GateRunReport,
    RuleSignal,
)
from difend.sdk import DifendSDK, ScanReport, ScanRequest, ScanStatus, scan

__version__ = "0.1.0"

__all__ = [
    "CodeDiff",
    "DiffCaptureError",
    "DiffLine",
    "DifendSDK",
    "AgentReviewError",
    "AgentReviewResult",
    "Finding",
    "Gate",
    "GateResult",
    "GateRunReport",
    "GateRunner",
    "GitDiffCapture",
    "ParsedDiff",
    "OpenAICodexClient",
    "ScanBundle",
    "ScanBundleRequest",
    "ScanBundleWriter",
    "ScanReport",
    "ScanRequest",
    "ScanStatus",
    "RuleSignal",
    "__version__",
    "parse_code_diff",
    "parse_diff",
    "review_scan_bundle",
    "scan",
]
