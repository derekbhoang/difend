"""Difend package."""

from difend.bundle import ScanBundle, ScanBundleRequest, ScanBundleWriter
from difend.diff import CodeDiff, DiffCaptureError, GitDiffCapture
from difend.models import (
    AddedLine,
    AutomatedGatesResult,
    Finding,
    GateResult,
    GateStatus,
    Severity,
)
from difend.sdk import DifendSDK, ScanReport, ScanRequest, ScanStatus, scan

__version__ = "0.1.0"

__all__ = [
    "CodeDiff",
    "DiffCaptureError",
    "DifendSDK",
    "AddedLine",
    "AutomatedGatesResult",
    "Finding",
    "GateResult",
    "GateStatus",
    "GitDiffCapture",
    "ScanBundle",
    "ScanBundleRequest",
    "ScanBundleWriter",
    "ScanReport",
    "ScanRequest",
    "ScanStatus",
    "Severity",
    "__version__",
    "scan",
]
