import os
import subprocess
from pathlib import Path

from difend.sdk import DifendSDK, ScanRequest, ScanStatus


def test_sdk_no_diff_writes_bundle_without_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)

    report = DifendSDK().scan(ScanRequest(repository_path=tmp_path))

    assert report.status == ScanStatus.PASS
    assert report.output_folder.exists()
    assert (report.output_folder / "report.json").exists()
    assert "OPENAI_API_KEY" not in os.environ
