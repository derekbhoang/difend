from argparse import Namespace
import json

from difend.commands.feedback import run_feedback
from difend.agents.feedback import apply_manual_review_feedback
from difend.agents.feedback import apply_feedback
from difend.agents.schemas import FeedbackRecord, Finding, ManualReviewItem, RiskArea, Severity


def test_manual_review_feedback_suppresses_exact_fingerprint():
    item = ManualReviewItem(
        manual_review_id="manual-1",
        area=RiskArea.AUTH,
        vulnerability_type="auth",
        risk_level=Severity.MEDIUM,
        confidence=0.5,
        file="auth.py",
        line=10,
        reason="Needs review.",
        evidence="auth change",
        questions=[],
        evidence_fingerprint="fingerprint",
    )
    record = FeedbackRecord(
        item_id="manual-1",
        item_type="manual_review",
        label="false_positive",
        evidence_fingerprint="fingerprint",
        reason="Reviewed and confirmed as test-only.",
    )

    active, suppressed = apply_manual_review_feedback([item], [record])

    assert active == []
    assert suppressed[0].manual_review_id == item.manual_review_id
    assert suppressed[0].suppressed is True


def test_feedback_without_reason_does_not_suppress():
    item = Finding(
        finding_id="finding-1",
        vulnerability_type="hardcoded_secret",
        severity=Severity.HIGH,
        confidence=0.9,
        file="config.py",
        line=1,
        evidence="secret",
        recommendation="Remove secret.",
        evidence_fingerprint="fingerprint",
    )
    record = FeedbackRecord(
        item_id="finding-1",
        item_type="finding",
        label="false_positive",
        evidence_fingerprint="fingerprint",
        reason="",
    )

    active, suppressed = apply_feedback([item], [record])

    assert active == [item]
    assert suppressed == []


def test_critical_feedback_requires_force_to_suppress():
    item = Finding(
        finding_id="finding-1",
        vulnerability_type="hardcoded_secret",
        severity=Severity.CRITICAL,
        confidence=0.9,
        file="config.py",
        line=1,
        evidence="secret",
        recommendation="Remove secret.",
        evidence_fingerprint="fingerprint",
    )
    record = FeedbackRecord(
        item_id="finding-1",
        item_type="finding",
        label="false_positive",
        evidence_fingerprint="fingerprint",
        reason="Confirmed false positive.",
    )

    active, suppressed = apply_feedback([item], [record])

    assert active == [item]
    assert suppressed == []


def test_feedback_command_requires_reason(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_report(tmp_path, severity="high")

    exit_code = run_feedback(
        Namespace(
            run_id="run-1",
            finding_id="finding-1",
            label="false_positive",
            reason="",
        )
    )

    assert exit_code == 2


def test_feedback_command_records_audit_metadata(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_report(tmp_path, severity="high")

    exit_code = run_feedback(
        Namespace(
            run_id="run-1",
            finding_id="finding-1",
            label="false_positive",
            reason="Reviewed fixture.",
        )
    )

    record = json.loads(
        (tmp_path / ".difend" / "feedback" / "finding-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert exit_code == 0
    assert record["run_id"] == "run-1"
    assert record["item_type"] == "finding"
    assert record["file"] == "config.py"
    assert record["line"] == 10
    assert record["created_at"]


def test_feedback_command_rejects_critical_suppression(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_report(tmp_path, severity="critical")

    exit_code = run_feedback(
        Namespace(
            run_id="run-1",
            finding_id="finding-1",
            label="false_positive",
            reason="Reviewed fixture.",
        )
    )

    assert exit_code == 2


def _write_report(tmp_path, severity: str) -> None:
    run_dir = tmp_path / ".difend" / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    report = {
        "findings": [
            {
                "finding_id": "finding-1",
                "severity": severity,
                "file": "config.py",
                "line": 10,
                "evidence_fingerprint": "fingerprint",
            }
        ],
        "manual_review": [],
    }
    (run_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
