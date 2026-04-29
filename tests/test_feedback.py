from difend.agents.feedback import apply_manual_review_feedback
from difend.agents.schemas import FeedbackRecord, ManualReviewItem, RiskArea, Severity


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
        label="false_positive",
        evidence_fingerprint="fingerprint",
    )

    active, suppressed = apply_manual_review_feedback([item], [record])

    assert active == []
    assert suppressed == [item]
