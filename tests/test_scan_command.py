from argparse import Namespace
from pathlib import Path

from difend.agents import AgenticScanError
from difend.agents.schemas import AgentExecution, AgentStatus
from difend.commands import scan as scan_command
from difend.diff import CodeDiff
from difend.observability import ScanObserver
from difend.sdk import ScanReport, ScanStatus


def test_scan_command_uses_gates_only_sdk_scan(monkeypatch):
    captured = {}

    def fake_scan(**kwargs):
        captured.update(kwargs)
        return _report(ScanStatus.PASS)

    monkeypatch.setattr(scan_command, "scan", fake_scan)

    exit_code = scan_command.run_scan(Namespace())

    observer = captured.pop("observer")
    assert exit_code == 0
    assert isinstance(observer, ScanObserver)
    assert captured == {}


def test_agent_scan_command_passes_model_and_cache_options(monkeypatch):
    captured = {}

    def fake_agent_scan(**kwargs):
        captured.update(kwargs)
        return _report(ScanStatus.PASS)

    monkeypatch.setattr(scan_command, "agent_scan", fake_agent_scan)

    exit_code = scan_command.run_agent_scan(
        Namespace(
            model="custom-model",
            no_cache=True,
            strict=False,
            agents=False,
        )
    )

    observer = captured.pop("observer")
    assert exit_code == 0
    assert isinstance(observer, ScanObserver)
    assert captured == {"model": "custom-model", "use_cache": False}


def test_manual_review_exits_zero_by_default(monkeypatch):
    monkeypatch.setattr(
        scan_command,
        "agent_scan",
        lambda **kwargs: _report(ScanStatus.MANUAL_REVIEW_REQUIRED),
    )

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=False, agents=False)
    )

    assert exit_code == 0


def test_manual_review_exits_one_in_strict_mode(monkeypatch):
    monkeypatch.setattr(
        scan_command,
        "agent_scan",
        lambda **kwargs: _report(ScanStatus.MANUAL_REVIEW_REQUIRED),
    )

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=True, agents=False)
    )

    assert exit_code == 1


def test_fail_exits_one(monkeypatch):
    monkeypatch.setattr(
        scan_command,
        "agent_scan",
        lambda **kwargs: _report(ScanStatus.FAIL),
    )

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=False, agents=False)
    )

    assert exit_code == 1


def test_agentic_scan_error_exits_two(monkeypatch):
    def fake_scan(**kwargs):
        raise AgenticScanError("boom")

    monkeypatch.setattr(scan_command, "agent_scan", fake_scan)

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=False, agents=False)
    )

    assert exit_code == 2


def test_agents_flag_prints_expanded_agent_details(monkeypatch, capsys):
    monkeypatch.setattr(
        scan_command,
        "agent_scan",
        lambda **kwargs: _report(ScanStatus.PASS),
    )

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=False, agents=True)
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Agent execution:" in output
    assert "diff_classifier: completed  used_llm=true" in output
    assert "Cache hit: false" in output
    assert "Trace: .difend\\runs\\run-1\\agent-trace.json" in output
    assert "Log: .difend\\runs\\run-1\\scan-log.jsonl" in output


def test_scan_command_prints_progress_percentages(monkeypatch, capsys):
    def fake_scan(**kwargs):
        observer = kwargs["observer"]
        for phase in scan_command.SCAN_PHASES:
            observer.complete(phase, f"{phase} done.")
        return _report(ScanStatus.PASS, name="difend scan")

    monkeypatch.setattr(scan_command, "scan", fake_scan)

    exit_code = scan_command.run_scan(Namespace())

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "0% scan started" in output
    assert "100% bundle_write completed" in output


def test_agent_scan_command_prints_progress_percentages(monkeypatch, capsys):
    def fake_agent_scan(**kwargs):
        observer = kwargs["observer"]
        for phase in scan_command.AGENT_SCAN_PHASES:
            observer.complete(phase, f"{phase} done.")
        return _report(ScanStatus.PASS)

    monkeypatch.setattr(scan_command, "agent_scan", fake_agent_scan)

    exit_code = scan_command.run_agent_scan(
        Namespace(model=None, no_cache=False, strict=False, agents=False)
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "0% scan started" in output
    assert "100% bundle_write completed" in output


def _report(status: ScanStatus, name: str = "difend agent-scan") -> ScanReport:
    return ScanReport(
        name=name,
        scan_id="run-1",
        repository_path=Path("."),
        output_folder=Path(".difend") / "runs" / "run-1",
        status=status,
        diff=CodeDiff(unstaged="", staged="", untracked=""),
        agents=[
            AgentExecution(
                name="diff_classifier",
                status=AgentStatus.COMPLETED,
                used_llm=True,
                detail="Classified diff.",
            )
        ],
        cache_hit=False,
        trace_path=Path(".difend") / "runs" / "run-1" / "agent-trace.json",
        log_path=Path(".difend") / "runs" / "run-1" / "scan-log.jsonl",
    )
