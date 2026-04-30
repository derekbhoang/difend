"""Difend package."""

from difend.agents import AgenticScanError, AgenticScanResult
from difend.bundle import ScanBundle, ScanBundleRequest, ScanBundleWriter
from difend.diff import CodeDiff, DiffCaptureError, GitDiffCapture
from difend.sdk import DifendSDK, ScanReport, ScanRequest, ScanStatus, agent_scan, scan

__version__ = "0.1.0"

__all__ = [
    "AgenticScanError",
    "AgenticScanResult",
    "CodeDiff",
    "DiffCaptureError",
    "DifendSDK",
    "GitDiffCapture",
    "ScanBundle",
    "ScanBundleRequest",
    "ScanBundleWriter",
    "ScanReport",
    "ScanRequest",
    "ScanStatus",
    "__version__",
    "agent_scan",
    "scan",
]
