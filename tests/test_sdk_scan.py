import os
import subprocess
import json
from pathlib import Path

import difend.sdk as sdk_module
from difend.sdk import DifendSDK, ScanRequest, ScanStatus


def test_sdk_no_diff_writes_bundle_without_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)

    report = DifendSDK().scan(ScanRequest(repository_path=tmp_path))

    assert report.status == ScanStatus.PASS
    assert report.name == "difend scan"
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
    assert "automated_gates" in trace_json["trace"]
    assert "OPENAI_API_KEY" not in os.environ


def test_sdk_agent_scan_no_diff_writes_bundle_without_api_key(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)

    report = DifendSDK().agent_scan(ScanRequest(repository_path=tmp_path))

    assert report.status == ScanStatus.PASS
    assert report.name == "difend agent-scan"
    assert report.output_folder.exists()
    trace_json = json.loads(
        (report.output_folder / "agent-trace.json").read_text(encoding="utf-8")
    )
    assert "cache_lookup" in trace_json["trace"]
    assert "OPENAI_API_KEY" not in os.environ


def test_sdk_scan_detects_gates_findings_without_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    source = tmp_path / "src"
    source.mkdir()
    (source / "config.py").write_text(
        "OPENAI_API_KEY = 'sk-proj-livevaluewithmanycharacters'\n",
        encoding="utf-8",
    )

    report = DifendSDK().scan(ScanRequest(repository_path=tmp_path))

    assert report.status == ScanStatus.FAIL
    assert report.name == "difend scan"
    assert report.findings
    assert all(agent.used_llm is False for agent in report.agents)
    assert "OPENAI_API_KEY" not in os.environ


def test_sdk_scan_detects_sample_flask_security_bugs_without_api_key(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "test.py").write_text(
        "\n".join(
            [
                "from flask import Flask, request",
                "import sqlite3",
                "app = Flask(__name__)",
                "def init_db():",
                "    conn = sqlite3.connect('users.db')",
                "    cur = conn.cursor()",
                "    cur.execute('''",
                "        CREATE TABLE IF NOT EXISTS users (",
                "            id INTEGER PRIMARY KEY AUTOINCREMENT,",
                "            username TEXT UNIQUE,",
                "            password TEXT",
                "        )",
                "    ''')",
                "def register():",
                "    username = request.form['username']",
                "    password = request.form['password']",
                "    cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))",
                "def login():",
                "    username = request.form['username']",
                "    password = request.form['password']",
                "    cur.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))",
                "if __name__ == '__main__':",
                "    app.run(debug=True)",
            ]
        ),
        encoding="utf-8",
    )

    report = DifendSDK().scan(ScanRequest(repository_path=tmp_path))

    finding_types = {finding.vulnerability_type for finding in report.findings}
    assert report.status == ScanStatus.FAIL
    assert {
        "plaintext_password_storage",
        "plaintext_password_insert",
        "plaintext_password_comparison",
        "debug_mode_enabled",
    } <= finding_types
    assert all(agent.used_llm is False for agent in report.agents)
    assert "OPENAI_API_KEY" not in os.environ


def test_scan_request_from_path_keeps_model_and_cache_options():
    request = ScanRequest.from_path(
        repository_path=".",
        model="custom-model",
        use_cache=False,
    )

    assert request.model == "custom-model"
    assert request.use_cache is False


def test_scan_convenience_function_passes_model_and_cache_options(monkeypatch, tmp_path):
    captured = {}
    sentinel = object()

    def fake_scan(self, request):
        captured["request"] = request
        return sentinel

    monkeypatch.setattr(sdk_module.DifendSDK, "scan", fake_scan)

    result = sdk_module.scan(
        repository_path=tmp_path,
        model="custom-model",
        use_cache=False,
    )

    assert result is sentinel
    assert captured["request"].repository_path == tmp_path
    assert captured["request"].model == "custom-model"
    assert captured["request"].use_cache is False


def test_agent_scan_convenience_function_passes_model_and_cache_options(
    monkeypatch,
    tmp_path,
):
    captured = {}
    sentinel = object()

    def fake_agent_scan(self, request):
        captured["request"] = request
        return sentinel

    monkeypatch.setattr(sdk_module.DifendSDK, "agent_scan", fake_agent_scan)

    result = sdk_module.agent_scan(
        repository_path=tmp_path,
        model="custom-model",
        use_cache=False,
    )

    assert result is sentinel
    assert captured["request"].repository_path == tmp_path
    assert captured["request"].model == "custom-model"
    assert captured["request"].use_cache is False
