from __future__ import annotations

from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.source_service import (
    SourceSpec,
    _document_from_result,
)
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult
from agent_traffic_intelligence.identity.sources.models import SourceType


def test_fetch_result_converts_to_cacheable_source_document() -> None:
    spec = SourceSpec(
        provider="example",
        uri="https://example.com/ranges.json",
        source_type=SourceType.IP_RANGES,
        parser_profile="prefixes-v1",
        binding_scope=BindingScope.PROVIDER,
    )
    result = FetchResult(
        uri=spec.uri,
        status=200,
        body=b'{"creationTime":"2026-08-14T00:00:00Z","prefixes":[]}',
        content_type="application/json",
        etag='"v1"',
        last_modified="Fri, 14 Aug 2026 00:00:00 GMT",
        cache_control="max-age=3600",
        redirects=0,
        not_modified=False,
    )

    document = _document_from_result(spec, result)

    assert document.metadata.binding_scope is BindingScope.PROVIDER
    assert document.metadata.etag == '"v1"'
    assert document.content == result.body
