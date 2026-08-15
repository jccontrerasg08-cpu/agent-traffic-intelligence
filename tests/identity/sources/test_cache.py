from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceType


def sample_document() -> SourceDocument:
    body = b'{"creationTime":"2026-08-14T00:00:00Z","prefixes":[]}'
    return SourceDocument.from_bytes(
        uri="https://example.com/ranges.json",
        source_type=SourceType.IP_RANGES,
        provider="example",
        binding_scope=BindingScope.PROVIDER,
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        content=body,
        content_type="application/json",
        parser_profile="prefixes-v1",
    )


def test_source_document_computes_sha256() -> None:
    document = sample_document()
    assert document.metadata.sha256 == hashlib.sha256(document.content).hexdigest()


def test_cache_round_trip_is_content_addressed(tmp_path) -> None:
    cache = SourceCache(tmp_path)
    document = sample_document()
    cache.put(document)

    loaded = cache.get(document.metadata.uri)
    assert loaded is not None
    assert loaded.content == document.content
    assert loaded.metadata.sha256 == document.metadata.sha256

    paths = [str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")]
    assert all("example.com" not in path for path in paths)
    assert any(document.metadata.sha256 in path for path in paths)
