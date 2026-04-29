from difend.agents.cache import CacheKey


def test_cache_key_changes_when_prompt_inputs_change():
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
