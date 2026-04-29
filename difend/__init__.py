"""Difend package."""

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
from difend.gates import Finding, Gate, GateResult, GateRunner, GateRunReport
from difend.sdk import DifendSDK, ScanReport, ScanRequest, ScanStatus, scan

__version__ = "0.1.0"

__all__ = [
    "CodeDiff",
    "DiffCaptureError",
    "DiffLine",
    "DifendSDK",
    "Finding",
    "Gate",
    "GateResult",
    "GateRunReport",
    "GateRunner",
    "GitDiffCapture",
    "ParsedDiff",
    "ScanBundle",
    "ScanBundleRequest",
    "ScanBundleWriter",
    "ScanReport",
    "ScanRequest",
    "ScanStatus",
    "__version__",
    "parse_code_diff",
    "parse_diff",
    "scan",
]
