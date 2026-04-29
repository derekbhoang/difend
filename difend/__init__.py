"""Difend package."""

from difend.bundle import ScanBundle, ScanBundleRequest, ScanBundleWriter
from difend.diff import CodeDiff, DiffCaptureError, GitDiffCapture
from difend.gates import AutomatedGatesAgent, run_automated_gates
from difend.parser import parse_code_diff, parse_unified_diff
from difend.sdk import DifendSDK, ScanReport, ScanRequest, ScanStatus, scan

__version__ = "0.1.0"

__all__ = [
    "AutomatedGatesAgent",
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
    "parse_code_diff",
    "parse_unified_diff",
    "run_automated_gates",
    "scan",
]
