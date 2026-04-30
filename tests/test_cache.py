from difend.agents.cache import CacheKey


def test_cache_key_changes_when_expanded_context_changes():
    first = CacheKey(
        diff_hash="a",
        context_hash="b",
        model="gpt-5.4-mini",
        feedback_digest="c",
    )
    second = CacheKey(
        diff_hash="a",
        context_hash="changed",
        model="gpt-5.4-mini",
        feedback_digest="c",
    )

    assert first.digest() != second.digest()


def test_cache_key_changes_when_prompt_schema_gates_or_feedback_changes(monkeypatch):
    key = CacheKey(
        diff_hash="a",
        context_hash="b",
        model="gpt-5.4-mini",
        feedback_digest="c",
    )
    baseline = key.digest()

    monkeypatch.setattr("difend.agents.cache.PROMPT_VERSION", "changed")
    assert key.digest() != baseline

    monkeypatch.setattr("difend.agents.cache.PROMPT_VERSION", "original")
    monkeypatch.setattr("difend.agents.cache.SCHEMA_VERSION", "changed")
    assert key.digest() != baseline

    monkeypatch.setattr("difend.agents.cache.SCHEMA_VERSION", "original")
    monkeypatch.setattr("difend.agents.cache.GATES_VERSION", "changed")
    assert key.digest() != baseline

    changed_feedback = CacheKey(
        diff_hash="a",
        context_hash="b",
        model="gpt-5.4-mini",
        feedback_digest="changed",
    )
    assert changed_feedback.digest() != baseline
