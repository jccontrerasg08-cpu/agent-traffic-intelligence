from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.crypto.discovery import (
    plan_signature_agent_resolution,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
    SignatureAgentReference,
)
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import (
    SourceAcquisition,
    SourceDocument,
    SourceType,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy

NOW = datetime(2026, 8, 16, 3, 45, tzinfo=UTC)
REFERENCE = SignatureAgentReference(
    label="sig1",
    uri="https://agent.example",
    discovery_type=SignatureAgentDiscoveryType.DIRECTORY,
)
TARGET = plan_signature_agent_resolution(REFERENCE)
JWKS_REFERENCE = SignatureAgentReference(
    label="sig1",
    uri="https://keys.example/jwks.json?tenant=one",
    discovery_type=SignatureAgentDiscoveryType.JWKS_URI,
)
JWKS_TARGET = plan_signature_agent_resolution(JWKS_REFERENCE)
CIMD_REFERENCE = SignatureAgentReference(
    label="sig1",
    uri="https://agent.example/card?profile=one",
    discovery_type=SignatureAgentDiscoveryType.CIMD,
)
CIMD_TARGET = plan_signature_agent_resolution(CIMD_REFERENCE)
CIMD_JWKS_URI = "https://keys.example/card-jwks.json"
JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    "use": "sig",
}
BODY = json.dumps({"keys": [JWK]}, separators=(",", ":"), sort_keys=True).encode()
GENERIC_JWK = {**JWK, "kid": "operator-label"}
JWKS_BODY = json.dumps(
    {"keys": [GENERIC_JWK]}, separators=(",", ":"), sort_keys=True
).encode()
CIMD_INLINE_BODY = json.dumps(
    {
        "client_id": CIMD_TARGET.fetch_uri,
        "jwks": {"keys": [GENERIC_JWK]},
    },
    separators=(",", ":"),
    sort_keys=True,
).encode()
CIMD_REMOTE_BODY = json.dumps(
    {
        "client_id": CIMD_TARGET.fetch_uri,
        "jwks_uri": CIMD_JWKS_URI,
    },
    separators=(",", ":"),
    sort_keys=True,
).encode()


def _module():
    try:
        from agent_traffic_intelligence.identity.crypto import cached_discovery
    except ImportError:
        pytest.fail("cache-only Signature-Agent discovery is not implemented")
    return cached_discovery


def policy(*uris: str) -> SourceTrustPolicy:
    return SourceTrustPolicy(frozenset(uris))


def cached_document(
    *,
    source_type: SourceType = SourceType.KEY_DIRECTORY,
    expires_at: datetime | None = None,
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=TARGET.fetch_uri,
        source_type=source_type,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        content=BODY,
        content_type="application/http-message-signatures-directory+json",
        parser_profile="draft-meunier-webbotauth-httpsig-directory-00",
        acquisition=SourceAcquisition.DIRECT_HTTPS,
    )


def cached_jwk_set(
    *,
    uri: str = JWKS_TARGET.fetch_uri,
    source_type: SourceType = SourceType.JWK_SET,
    expires_at: datetime | None = None,
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=uri,
        source_type=source_type,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        content=JWKS_BODY,
        content_type="application/json",
        parser_profile="rfc7517",
        acquisition=SourceAcquisition.DIRECT_HTTPS,
    )


def cached_cimd(
    content: bytes,
    *,
    expires_at: datetime | None = None,
) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=CIMD_TARGET.fetch_uri,
        source_type=SourceType.AGENT_CARD,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=NOW - timedelta(minutes=5),
        expires_at=expires_at,
        content=content,
        content_type="application/json",
        parser_profile="draft-meunier-webbotauth-registry-03",
        acquisition=SourceAcquisition.DIRECT_HTTPS,
    )


def test_directory_resolves_strict_cached_document_to_generic_key_set(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_document(expires_at=NOW + timedelta(hours=1)))

    resolved = module.resolve_cached_signature_agent(
        REFERENCE,
        cache=cache,
        trust_policy=policy(TARGET.fetch_uri),
        now=NOW,
    )

    assert resolved.identifier_uri == TARGET.identifier_uri
    assert resolved.discovery_type is SignatureAgentDiscoveryType.DIRECTORY
    assert len(resolved.jwk_set.keys) == 1
    assert resolved.documents == (cache.get(TARGET.fetch_uri),)


def test_directory_missing_or_untrusted_is_unavailable(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)

    with pytest.raises(module.CachedDiscoveryUnavailable):
        module.resolve_cached_signature_agent(
            REFERENCE,
            cache=cache,
            trust_policy=policy(TARGET.fetch_uri),
            now=NOW,
        )

    cache.put(cached_document())
    with pytest.raises(module.CachedDiscoveryUnavailable):
        module.resolve_cached_signature_agent(
            REFERENCE,
            cache=cache,
            trust_policy=policy(),
            now=NOW,
        )


def test_directory_rejects_wrong_cached_source_type(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_document(source_type=SourceType.JWK_SET))

    with pytest.raises(module.CachedDiscoveryError):
        module.resolve_cached_signature_agent(
            REFERENCE,
            cache=cache,
            trust_policy=policy(TARGET.fetch_uri),
            now=NOW,
        )


def test_directory_stale_cache_is_not_used(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_document(expires_at=NOW - timedelta(seconds=1)))

    with pytest.raises(module.CachedDiscoveryStale):
        module.resolve_cached_signature_agent(
            REFERENCE,
            cache=cache,
            trust_policy=policy(TARGET.fetch_uri),
            now=NOW,
        )


def test_jwks_uri_resolves_generic_cached_jwk_set_with_operator_kid(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_jwk_set(expires_at=NOW + timedelta(hours=1)))

    resolved = module.resolve_cached_signature_agent(
        JWKS_REFERENCE,
        cache=cache,
        trust_policy=policy(JWKS_TARGET.fetch_uri),
        now=NOW,
    )

    assert resolved.identifier_uri == JWKS_TARGET.identifier_uri
    assert resolved.discovery_type is SignatureAgentDiscoveryType.JWKS_URI
    assert len(resolved.jwk_set.keys) == 1
    assert resolved.jwk_set.keys[0].kid == "operator-label"
    assert resolved.documents == (cache.get(JWKS_TARGET.fetch_uri),)


def test_jwks_uri_rejects_strict_directory_source_type(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_jwk_set(source_type=SourceType.KEY_DIRECTORY))

    with pytest.raises(module.CachedDiscoveryError):
        module.resolve_cached_signature_agent(
            JWKS_REFERENCE,
            cache=cache,
            trust_policy=policy(JWKS_TARGET.fetch_uri),
            now=NOW,
        )


def test_cimd_resolves_inline_jwks_without_changing_client_identifier(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_cimd(CIMD_INLINE_BODY, expires_at=NOW + timedelta(hours=1)))

    resolved = module.resolve_cached_signature_agent(
        CIMD_REFERENCE,
        cache=cache,
        trust_policy=policy(CIMD_TARGET.fetch_uri),
        now=NOW,
    )

    assert resolved.identifier_uri == CIMD_TARGET.identifier_uri
    assert resolved.discovery_type is SignatureAgentDiscoveryType.CIMD
    assert resolved.jwk_set.keys[0].kid == "operator-label"
    assert resolved.documents == (cache.get(CIMD_TARGET.fetch_uri),)


def test_cimd_resolves_allowlisted_secondary_jwks_uri(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_cimd(CIMD_REMOTE_BODY, expires_at=NOW + timedelta(hours=1)))
    cache.put(
        cached_jwk_set(
            uri=CIMD_JWKS_URI,
            expires_at=NOW + timedelta(hours=1),
        )
    )

    resolved = module.resolve_cached_signature_agent(
        CIMD_REFERENCE,
        cache=cache,
        trust_policy=policy(CIMD_TARGET.fetch_uri, CIMD_JWKS_URI),
        now=NOW,
    )

    assert resolved.identifier_uri == CIMD_TARGET.identifier_uri
    assert resolved.discovery_type is SignatureAgentDiscoveryType.CIMD
    assert resolved.jwk_set.keys[0].kid == "operator-label"
    assert resolved.documents == (
        cache.get(CIMD_TARGET.fetch_uri),
        cache.get(CIMD_JWKS_URI),
    )


def test_cimd_secondary_jwks_uri_must_be_allowlisted(tmp_path) -> None:
    module = _module()
    cache = SourceCache(tmp_path)
    cache.put(cached_cimd(CIMD_REMOTE_BODY))
    cache.put(cached_jwk_set(uri=CIMD_JWKS_URI))

    with pytest.raises(module.CachedDiscoveryUnavailable):
        module.resolve_cached_signature_agent(
            CIMD_REFERENCE,
            cache=cache,
            trust_policy=policy(CIMD_TARGET.fetch_uri),
            now=NOW,
        )
