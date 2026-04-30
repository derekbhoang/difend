import json
from pathlib import Path

from difend.agents.schemas import Finding, Severity
from difend.bundle import ScanBundleRequest, ScanBundleWriter
from difend.diff import CodeDiff


def test_bundle_writes_gate_name_to_markdown_and_report_json(tmp_path: Path):
    finding = Finding(
        finding_id="finding-1",
        vulnerability_type="hardcoded_secret",
        gate_name="secret_scan",
        severity=Severity.HIGH,
        confidence=0.9,
        file="config.py",
        line=12,
        evidence="API_KEY = 'secret'",
        recommendation="Move secret to an environment variable.",
        evidence_fingerprint="fingerprint",
    )

    bundle = ScanBundleWriter().write(
        ScanBundleRequest(
            repository_path=tmp_path,
            output_root=Path(".difend/runs"),
            status="fail",
            diff=CodeDiff(unstaged="", staged="", untracked=""),
            findings=[finding],
        )
    )

    findings_markdown = bundle.findings_path.read_text(encoding="utf-8")
    report = json.loads(bundle.report_path.read_text(encoding="utf-8"))

    assert "- Gate: secret_scan" in findings_markdown
    assert report["findings"][0]["gate_name"] == "secret_scan"
    assert report["log_path"].endswith("scan-log.jsonl")
    assert bundle.scan_log_path.exists()
