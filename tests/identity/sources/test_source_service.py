from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

import agent_traffic_intelligence.identity.source_service as service
from agent_traffic_intelligence.identity.crypto.directory import jwk_thumbprint
from agent_traffic_intelligence.identity.crypto.rfc9421_response import (
    response_component_resolver_class,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    structured_fields_module,
)
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
SOURCE_CREATED_AT = datetime(2026, 8, 14, 0, 0, tzinfo=UTC)
DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"


def range_spec(provider: str = "example") -> SourceSpec:
    return SourceSpec(
        provider=provider,
        uri=f"https://{provider}.example/ranges.json",
        source_type=SourceType.IP_RANGES,
        parser_profile="prefixes-v1",
        binding_scope=BindingScope.PROVIDER,
    )


def directory_spec() -> SourceSpec:
    return SourceSpec(
        provider="example",
        uri=DIRECTORY_URI,
        source_type=SourceType.KEY_DIRECTORY,
        parser_profile="directory-05",
        binding_scope=BindingScope.AGENT,
    )


def cached_document(
    spec: SourceSpec,
    content: bytes = VALID_RANGES,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    expires_at: datetime | None = None,
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=spec.uri,
        source_type=spec.source_type,
        provider=spec.provider,
        binding_scope=spec.binding_scope,
        retrieved_at=datetime(2026, 8, 14, 12, 0, tzinfo=UTC),
        source_created_at=SOURCE_CREATED_AT,
        expires_at=expires_at,
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
    uri: str | None = None,
    cache_control: str | None = "max-age=3600",
) -> FetchResult:
    return FetchResult(
        uri=uri or spec.uri,
        status=304 if not_modified else 200,
        body=body,
        content_type=None if not_modified else "application/json",
        etag='"v2"',
        last_modified="Fri, 14 Aug 2026 12:00:00 GMT",
        cache_control=cache_control,
        redirects=0,
        not_modified=not_modified,
    )


@dataclass
class MutableRequest:
    method: str
    url: str
    headers: dict[str, str]


@dataclass
class MutableResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    request: MutableRequest


class DirectoryKeyResolver:
    def __init__(self, key_id: str, private_key: object) -> None:
        self.key_id = key_id
        self.private_key = private_key

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private_key

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private_key.public_key()


def _signed_directory_fetch_result(
    spec: SourceSpec,
    *,
    published_kid: str | None = None,
) -> tuple[FetchResult, str]:
    hms = pytest.importorskip("http_message_signatures")
    algorithms = pytest.importorskip("http_message_signatures.algorithms")
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw_key = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii"),
        "use": "sig",
    }
    key_id = jwk_thumbprint(raw_key)
    raw_key["kid"] = published_kid or key_id
    body = json.dumps(
        {"keys": [raw_key]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    sf = structured_fields_module()
    content_digest = str(sf.Dictionary({"sha-256": hashlib.sha256(body).digest()}))
    resolver = DirectoryKeyResolver(str(raw_key["kid"]), private_key)
    request = MutableRequest(method="GET", url=spec.uri, headers={})
    response = MutableResponse(
        status_code=200,
        url="https://cdn.example/directory-cache",
        headers={"Content-Digest": content_digest},
        request=request,
    )
    signer = hms.HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=resolver,
        component_resolver_class=response_component_resolver_class(),
    )
    now = datetime.now()
    signer.sign(
        response,
        key_id=str(raw_key["kid"]),
        covered_component_ids=('"@authority";req', "content-digest"),
        created=now,
        expires=now + timedelta(minutes=5),
        label="directory-binding",
        tag="http-message-signatures-directory",
    )

    return (
        FetchResult(
            uri=response.url,
            status=response.status_code,
            body=body,
            content_type="application/http-message-signatures-directory+json",
            etag='"directory-v1"',
            last_modified="Fri, 14 Aug 2026 12:00:00 GMT",
            cache_control="max-age=3600",
            redirects=0,
            not_modified=False,
            signature=response.headers.get("Signature"),
            signature_input=response.headers.get("Signature-Input"),
            content_digest=content_digest,
        ),
        key_id,
    )


def test_fetch_result_converts_to_cacheable_source_document() -> None:
    spec = range_spec()
    result = fetch_result(spec)
    document = _document_from_result(spec, result)
    assert document.metadata.binding_scope is BindingScope.PROVIDER
    assert document.metadata.etag == '"v2"'
    assert document.metadata.source_created_at == SOURCE_CREATED_AT
    assert document.metadata.expires_at is not None
    assert document.metadata.expires_at - document.metadata.retrieved_at == timedelta(hours=1)
    assert document.metadata.acquisition.value == "direct_https"
    assert document.content == result.body


def test_redirected_fetch_is_cached_under_configured_authority_uri() -> None:
    spec = range_spec()
    result = fetch_result(
        spec,
        uri="https://cdn.example.net/provider-ranges.json",
    )
    document = _document_from_result(spec, result)
    assert document.metadata.uri == spec.uri


def test_cache_control_without_valid_max_age_leaves_expiry_unknown() -> None:
    spec = range_spec()
    for value in (None, "public", "max-age=not-a-number", "max-age=-1"):
        document = _document_from_result(spec, fetch_result(spec, cache_control=value))
        assert document.metadata.expires_at is None


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
    assert row["source_created_at"] == SOURCE_CREATED_AT.isoformat()
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
    assert refreshed_document.metadata.expires_at is not None


def test_signed_directory_refresh_caches_only_derived_authority_binding(
    tmp_path,
    monkeypatch,
) -> None:
    spec = directory_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    result, key_id = _signed_directory_fetch_result(spec)
    cache = SourceCache(tmp_path)
    fetcher = FakeFetcher([result])

    refreshed, not_modified = refresh_sources(cache, fetcher=fetcher)

    assert (refreshed, not_modified) == (1, 0)
    cached = cache.get(spec.uri)
    assert cached is not None
    assert len(cached.metadata.key_authority_bindings) == 1
    binding = cached.metadata.key_authority_bindings[0]
    assert binding.key_thumbprint == key_id
    assert binding.authority == "agent.example"
    assert binding.body_sha256 == cached.metadata.sha256
    metadata = cached.metadata.to_dict()
    assert "signature" not in metadata
    assert "signature_input" not in metadata
    assert "content_digest" not in metadata


def test_signed_directory_refresh_accepts_an_opaque_kid_and_binds_thumbprint(
    tmp_path,
    monkeypatch,
) -> None:
    spec = directory_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    result, thumbprint = _signed_directory_fetch_result(
        spec,
        published_kid="google-directory-key-1",
    )
    cache = SourceCache(tmp_path)

    refreshed, not_modified = refresh_sources(cache, fetcher=FakeFetcher([result]))

    assert (refreshed, not_modified) == (1, 0)
    cached = cache.get(spec.uri)
    assert cached is not None
    assert cached.metadata.key_authority_bindings[0].key_thumbprint == thumbprint


def test_refresh_304_revalidates_freshness_without_changing_content(
    tmp_path,
    monkeypatch,
) -> None:
    spec = range_spec()
    monkeypatch.setattr(service, "configured_sources", lambda: (spec,))
    cache = SourceCache(tmp_path)
    original = cached_document(
        spec,
        etag='"v1"',
        expires_at=datetime(2026, 8, 14, 11, 0, tzinfo=UTC),
    )
    cache.put(original)
    fetcher = FakeFetcher([fetch_result(spec, body=None, not_modified=True)])

    refreshed, not_modified = refresh_sources(cache, fetcher=fetcher)

    assert (refreshed, not_modified) == (0, 1)
    cached = cache.get(spec.uri)
    assert cached is not None
    assert cached.metadata.sha256 == original.metadata.sha256
    assert cached.content == original.content
    assert cached.metadata.retrieved_at > original.metadata.retrieved_at
    assert cached.metadata.expires_at is not None
    assert cached.metadata.expires_at > cached.metadata.retrieved_at
    assert cached.metadata.etag == '"v2"'


def test_provider_filter_does_not_fetch_other_sources(tmp_path, monkeypatch) -> None:
    first = range_spec("first")
    second = range_spec("second")
    monkeypatch.setattr(service, "configured_sources", lambda: (first, second))
    cache = SourceCache(tmp_path)
    fetcher = FakeFetcher([fetch_result(first, body=None, not_modified=True)])
    cache.put(cached_document(first))

    refresh_sources(cache, provider="first", fetcher=fetcher)

    assert len(fetcher.calls) == 1
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
