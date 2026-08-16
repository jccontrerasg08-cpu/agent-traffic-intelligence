from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
)
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.profiles import (
    CryptoDiscoveryType,
    CryptoSourceProfile,
    provider_profile,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import (
    SourceAcquisition,
    SourceDocument,
    SourceType,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy

NOW = datetime(2026, 8, 16, 4, 30, tzinfo=UTC)
JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    "kid": "operator-key",
}


def _module():
    try:
        from agent_traffic_intelligence.identity import configured
    except ImportError:
        pytest.fail("configured identity module is unavailable")
    return configured


def test_google_profile_builds_current_directory_reference() -> None:
    module = _module()
    google = provider_profile("google")
    assert google.crypto is not None
    source = google.crypto.signature_agents[0]

    reference = module.configured_signature_agent_reference(source)

    assert reference.uri == source.signature_agent_uri
    assert reference.discovery_type is SignatureAgentDiscoveryType.DIRECTORY


def test_configured_discovery_rejects_inconsistent_declared_fetch_uri(tmp_path) -> None:
    module = _module()
    google = provider_profile("google")
    assert google.crypto is not None
    source = replace(
        google.crypto.signature_agents[0],
        directory_uri="https://wrong.example/keys",
    )

    with pytest.raises(module.ConfiguredCryptoDiscoveryError, match="fetch URI"):
        module.resolve_configured_crypto_material(
            source,
            cache=SourceCache(tmp_path),
            trust_policy=SourceTrustPolicy(frozenset()),
            now=NOW,
        )


def test_configured_jwks_uri_resolves_only_allowlisted_cached_material(tmp_path) -> None:
    module = _module()
    uri = "https://keys.example/jwks.json?tenant=one"
    source = CryptoSourceProfile(
        signature_agent_uri=uri,
        directory_uri=uri,
        interoperability_profile=provider_profile("google").crypto.signature_agents[0].interoperability_profile,  # type: ignore[union-attr]
        discovery_type=CryptoDiscoveryType.JWKS_URI,
        binding_scope=BindingScope.AGENT,
        reviewed_on="2026-08-16",
        subject="ExampleBot",
    )
    cache = SourceCache(tmp_path)
    cache.put(
        SourceDocument.from_bytes(
            uri=uri,
            source_type=SourceType.JWK_SET,
            provider="example",
            binding_scope=BindingScope.AGENT,
            retrieved_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
            content=json.dumps({"keys": [JWK]}).encode(),
            content_type="application/json",
            parser_profile="rfc7517",
            acquisition=SourceAcquisition.DIRECT_HTTPS,
        )
    )

    resolved = module.resolve_configured_crypto_material(
        source,
        cache=cache,
        trust_policy=SourceTrustPolicy(frozenset({uri})),
        now=NOW,
    )

    assert resolved.discovery_type is SignatureAgentDiscoveryType.JWKS_URI
    assert resolved.identifier_uri == "https://keys.example/jwks.json"
    assert resolved.jwk_set.keys[0].kid == "operator-key"
