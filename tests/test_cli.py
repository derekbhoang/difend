import pytest

from difend.cli import build_parser
from difend.commands.scan import run_agent_scan, run_scan


def test_agent_scan_command_parses_all_flags():
    parser = build_parser()

    args = parser.parse_args(
        [
            "agent-scan",
            "--no-cache",
            "--model",
            "gpt-5.4-mini",
            "--strict",
            "--agents",
        ]
    )

    assert args.command == "agent-scan"
    assert args.no_cache is True
    assert args.model == "gpt-5.4-mini"
    assert args.strict is True
    assert args.agents is True
    assert args.handler is run_agent_scan


def test_scan_command_parses_as_gates_only_command():
    parser = build_parser()

    args = parser.parse_args(["scan"])

    assert args.command == "scan"
    assert args.handler is run_scan


def test_scan_command_rejects_agentic_flags():
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["scan", "--model", "gpt-5.4-mini"])

    assert exc.value.code == 2
