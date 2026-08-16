from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import agent_traffic_intelligence.identity.source_service as service
from agent_traffic_intelligence.identity.crypto.directory import jwk_thumbprint
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.source_service import SourceSpec, refresh_sources
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult
from agent_traffic_intelligence.identity.sources.models import (
    KeyAuthorityBinding,
    SourceAcquisition,
    SourceDocument,
    SourceType,
)

DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"


class NotModifiedFetcher:
    def fetch(
        self,
        uri: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        assert uri == DIRECTORY_URI
        assert etag == '"v1"'
        return FetchResult(
            uri=uri,
            status=304,
            body=None,
            content_type=None,
            etag='"v2"',
            last_modified="Fri, 15 Aug 2026 18:00:00 GMT",
            cache_control="max-age=3600",
            redirects=0,
            not_modified=True,
        )


def stored_directory() -> SourceDocument:
    raw_key = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
        "use": "sig",
    }
    key_id = jwk_thumbprint(raw_key)
    raw_key["kid"] = key_id
    body = json.dumps(
        {"keys": [raw_key]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    verified_at = datetime(2026, 8, 15, 17, 0, tzinfo=UTC)
    binding = KeyAuthorityBinding(
        key_thumbprint=key_id,
        authority="agent.example",
        body_sha256=hashlib.sha256(body).hexdigest(),
        verified_at=verified_at,
        expires_at=verified_at + timedelta(hours=6),
        profile="draft-meunier-webbotauth-httpsig-directory-00",
    )
    return SourceDocument.from_bytes(
        uri=DIRECTORY_URI,
        source_type=SourceType.KEY_DIRECTORY,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=verified_at,
        content=body,
        content_type="application/http-message-signatures-directory+json",
        parser_profile="directory-05",
        etag='"v1"',
        key_authority_bindings=(binding,),
        acquisition=SourceAcquisition.DIRECT_HTTPS,
    )


def test_304_revalidation_preserves_existing_key_authority_binding(
    tmp_path,
    monkeypatch,
) -> None:
    spec = SourceSpec(
        provider="example",
        uri=DIRECTORY_URI,
        source_type=SourceType.KEY_DIRECTORY,
        parser_profile="directory-05",
        binding_scope=BindingScope.AGENT,
    )
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    original = stored_directory()
    cache.put(original)

    refreshed, not_modified = refresh_sources(
        cache,
        fetcher=NotModifiedFetcher(),
    )

    assert (refreshed, not_modified) == (0, 1)
    cached = cache.get(DIRECTORY_URI)
    assert cached is not None
    assert cached.content == original.content
    assert cached.metadata.sha256 == original.metadata.sha256
    assert cached.metadata.etag == '"v2"'
    assert cached.metadata.key_authority_bindings == original.metadata.key_authority_bindings
    assert cached.metadata.acquisition is SourceAcquisition.DIRECT_HTTPS
