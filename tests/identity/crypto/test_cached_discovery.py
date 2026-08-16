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
JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    "use": "sig",
}
BODY = json.dumps({"keys": [JWK]}, separators=(",", ":"), sort_keys=True).encode()


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
