from agent_traffic_intelligence.identity.crypto.replay import ReplayCache


def test_nonce_replay_is_rejected_only_while_unexpired() -> None:
    cache = ReplayCache(max_entries=2)
    assert cache.seen_or_add("k1", "n1", expires=200, now=100) is False
    assert cache.seen_or_add("k1", "n1", expires=200, now=150) is True
    assert cache.seen_or_add("k1", "n1", expires=300, now=201) is False


def test_replay_cache_is_bounded() -> None:
    cache = ReplayCache(max_entries=2)
    cache.seen_or_add("k", "n1", expires=500, now=100)
    cache.seen_or_add("k", "n2", expires=500, now=100)
    cache.seen_or_add("k", "n3", expires=500, now=100)
    assert cache.seen_or_add("k", "n1", expires=500, now=101) is False
