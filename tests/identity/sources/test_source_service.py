from __future__ import annotations

from datetime import UTC, datetime

import pytest

import agent_traffic_intelligence.identity.source_service as service
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.source_service import (
    SourceSpec,
    _document_from_result,
    refresh_sources,
    source_status,
    validate_sources,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceType

VALID_RANGES = b'{"creationTime":"2026-08-14T00:00:00Z","prefixes":[]}'


def range_spec(provider: str = "example") -> SourceSpec:
    return SourceSpec(
        provider=provider,
        uri=f"https://{provider}.example/ranges.json",
        source_type=SourceType.IP_RANGES,
        parser_profile="prefixes-v1",
        binding_scope=BindingScope.PROVIDER,
    )


def cached_document(
    spec: SourceSpec,
    content: bytes = VALID_RANGES,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=spec.uri,
        source_type=spec.source_type,
        provider=spec.provider,
        binding_scope=spec.binding_scope,
        retrieved_at=datetime(2026, 8, 14, 12, 0, tzinfo=UTC),
        content=content,
        content_type="application/json",
        parser_profile=spec.parser_profile,
        etag=etag,
        last_modified=last_modified,
    )


class FakeFetcher:
    def __init__(self, results: list[FetchResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, str | None, str | None]] = []

    def fetch(
        self,
        uri: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        self.calls.append((uri, etag, last_modified))
        return self.results.pop(0)


def fetch_result(
    spec: SourceSpec,
    *,
    body: bytes | None = VALID_RANGES,
    not_modified: bool = False,
) -> FetchResult:
    return FetchResult(
        uri=spec.uri,
        status=304 if not_modified else 200,
        body=body,
        content_type=None if not_modified else "application/json",
        etag='"v2"',
        last_modified="Fri, 14 Aug 2026 12:00:00 GMT",
        cache_control="max-age=3600",
        redirects=0,
        not_modified=not_modified,
    )


def test_fetch_result_converts_to_cacheable_source_document() -> None:
    spec = range_spec()
    result = fetch_result(spec)
    document = _document_from_result(spec, result)
    assert document.metadata.binding_scope is BindingScope.PROVIDER
    assert document.metadata.etag == '"v2"'
    assert document.content == result.body


def test_status_and_validate_use_only_local_cache(tmp_path, monkeypatch) -> None:
    spec = range_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    assert source_status(cache)[0]["cached"] is False
    assert validate_sources(cache) == []

    cache.put(cached_document(spec))
    row = source_status(cache)[0]
    assert row["cached"] is True
    assert row["sha256"]
    assert validate_sources(cache) == []


def test_validate_reports_malformed_cached_source(tmp_path, monkeypatch) -> None:
    spec = range_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    cache.put(cached_document(spec, b"{}"))
    errors = validate_sources(cache)
    assert len(errors) == 1
    assert spec.uri in errors[0]


def test_refresh_stores_valid_source_and_uses_conditional_metadata(
    tmp_path,
    monkeypatch,
) -> None:
    spec = range_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    cache.put(
        cached_document(
            spec,
            etag='"v1"',
            last_modified="Thu, 13 Aug 2026 12:00:00 GMT",
        )
    )
    fetcher = FakeFetcher([fetch_result(spec)])
    refreshed, not_modified = refresh_sources(cache, fetcher=fetcher)
    assert (refreshed, not_modified) == (1, 0)
    assert fetcher.calls == [
        (spec.uri, '"v1"', "Thu, 13 Aug 2026 12:00:00 GMT")
    ]
    refreshed_document = cache.get(spec.uri)
    assert refreshed_document is not None
    assert refreshed_document.metadata.etag == '"v2"'


def test_refresh_304_and_provider_filter_do_not_rewrite_cache(
    tmp_path,
    monkeypatch,
) -> None:
    first = range_spec("first")
    second = range_spec("second")
    monkeypatch.setattr(service, "configured_sources", lambda: (first, second))
    cache = SourceCache(tmp_path)
    original = cached_document(first, etag='"v1"')
    cache.put(original)
    fetcher = FakeFetcher([fetch_result(first, body=None, not_modified=True)])
    refreshed, not_modified = refresh_sources(
        cache,
        provider="first",
        fetcher=fetcher,
    )
    assert (refreshed, not_modified) == (0, 1)
    assert len(fetcher.calls) == 1
    cached = cache.get(first.uri)
    assert cached is not None
    assert cached.metadata.sha256 == original.metadata.sha256
    assert cache.get(second.uri) is None


def test_malformed_refresh_is_rejected_before_replacing_cache(
    tmp_path,
    monkeypatch,
) -> None:
    spec = range_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    original = cached_document(spec)
    cache.put(original)
    fetcher = FakeFetcher([fetch_result(spec, body=b"{}")])

    with pytest.raises(ValueError):
        refresh_sources(cache, fetcher=fetcher)

    cached = cache.get(spec.uri)
    assert cached is not None
    assert cached.metadata.sha256 == original.metadata.sha256
