import os
import subprocess
import json
from pathlib import Path

from difend.sdk import DifendSDK, ScanRequest, ScanStatus


def test_sdk_no_diff_writes_bundle_without_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)

    report = DifendSDK().scan(ScanRequest(repository_path=tmp_path))

    assert report.status == ScanStatus.PASS
    assert report.output_folder.exists()
    assert (report.output_folder / "report.json").exists()
    assert (report.output_folder / "agent-trace.json").exists()
    report_json = json.loads(
        (report.output_folder / "report.json").read_text(encoding="utf-8")
    )
    trace_json = json.loads(
        (report.output_folder / "agent-trace.json").read_text(encoding="utf-8")
    )
    assert report_json["trace_path"].endswith("agent-trace.json")
    assert "prepare_scan_context" in trace_json["trace"]
    assert "cache_lookup" in trace_json["trace"]
    assert "OPENAI_API_KEY" not in os.environ
