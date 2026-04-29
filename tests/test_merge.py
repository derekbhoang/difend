from difend.agents.schemas import Finding, ManualReviewItem, RiskArea, Severity
from difend.agents.scoring import decide_status, merge_results


def test_gates_finding_wins_over_reasoning_overlap():
    finding = Finding(
        finding_id="finding-1",
        vulnerability_type="authorization",
        severity=Severity.HIGH,
        confidence=0.9,
        file="src/routes/admin.py",
        line=55,
        evidence="admin check removed",
        recommendation="Restore admin-only check.",
        evidence_fingerprint="same",
    )
    manual = ManualReviewItem(
        manual_review_id="manual-1",
        area=RiskArea.AUTHORIZATION,
        vulnerability_type="authorization",
        risk_level=Severity.LOW,
        confidence=0.6,
        file="src/routes/admin.py",
        line=55,
        reason="May weaken admin access.",
        evidence="admin check removed",
        questions=["Is this route protected elsewhere?"],
        evidence_fingerprint="same",
    )

    findings, manual_review, covered_review = merge_results([finding], [manual])

    assert findings == [finding]
    assert manual_review == []
    assert covered_review == [manual]
    assert findings[0].severity == Severity.HIGH


def test_status_rules():
    assert decide_status([], []) == "pass"
    manual = ManualReviewItem(
        manual_review_id="manual-1",
        area=RiskArea.AUTH,
        vulnerability_type="auth",
        risk_level=Severity.MEDIUM,
        confidence=0.5,
        file="auth.py",
        line=1,
        reason="Needs review.",
        evidence="auth change",
        questions=[],
        evidence_fingerprint="manual",
    )
    assert decide_status([], [manual]) == "manual review required"
