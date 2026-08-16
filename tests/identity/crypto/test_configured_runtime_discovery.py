from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.configured import ProviderAwareVerificationManager
from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.profiles import (
    CryptoDiscoveryType,
    CryptoInteroperabilityProfile,
    CryptoProfile,
    CryptoSourceProfile,
    ProviderProfile,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import (
    SourceAcquisition,
    SourceDocument,
    SourceType,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import (
    ActorType,
    IdentityClaim,
    RequestEvent,
    VerificationState,
)

hms = pytest.importorskip("http_message_signatures")
algorithms = pytest.importorskip("http_message_signatures.algorithms")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

JWKS_URI = "https://keys.example/jwks.json?tenant=one"


@dataclass
class Message:
    method: str
    url: str
    headers: dict[str, str]


class SigningResolver:
    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private.public_key()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _public_jwk(resolver: SigningResolver) -> dict[str, object]:
    raw = resolver.private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw),
        "kid": "test-key",
        "alg": "EdDSA",
        "use": "sig",
    }


def _signed_message(resolver: SigningResolver) -> Message:
    message = Message("GET", "https://example.com/docs", {})
    message.headers["Signature-Agent"] = (
        f'sig1="{JWKS_URI}";type=jwks_uri'
    )
    signer = hms.HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=resolver,
        component_resolver_class=Rfc9421Verifier._component_resolver(hms),
    )
    now = datetime.now()
    signer.sign(
        message,
        key_id="test-key",
        covered_component_ids=("@authority", '"signature-agent";key="sig1"'),
        created=now,
        expires=now + timedelta(minutes=5),
        label="sig1",
        tag="web-bot-auth",
    )
    return message


def _context(message: Message) -> VerificationContext:
    return VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method=message.method,
        target_uri=message.url,
        signature=message.headers.get("Signature"),
        signature_input=message.headers.get("Signature-Input"),
        signature_agent=message.headers.get("Signature-Agent"),
        covered_headers={},
    )


def test_runtime_verifies_allowlisted_cached_jwks_without_network(tmp_path) -> None:
    now = datetime.now(UTC)
    resolver = SigningResolver()
    source = CryptoSourceProfile(
        signature_agent_uri=JWKS_URI,
        directory_uri=JWKS_URI,
        interoperability_profile=CryptoInteroperabilityProfile.IETF_HTTPSIG_PROTOCOL_01,
        discovery_type=CryptoDiscoveryType.JWKS_URI,
        binding_scope=BindingScope.AGENT,
        reviewed_on="2026-08-16",
        subject="ExampleBot",
    )
    profile = ProviderProfile(
        provider="example",
        range_sources=(),
        fcrdns=None,
        crypto=CryptoProfile(signature_agents=(source,), reviewed_on="2026-08-16"),
    )
    cache = SourceCache(tmp_path)
    cache.put(
        SourceDocument.from_bytes(
            uri=JWKS_URI,
            source_type=SourceType.JWK_SET,
            provider="example",
            binding_scope=BindingScope.AGENT,
            retrieved_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
            content=json.dumps({"keys": [_public_jwk(resolver)]}).encode(),
            content_type="application/json",
            parser_profile="rfc7517",
            acquisition=SourceAcquisition.DIRECT_HTTPS,
        )
    )

    manager = ProviderAwareVerificationManager(cache)
    manager._profiles = {"example": profile}
    manager._trust = SourceTrustPolicy(frozenset({JWKS_URI}))
    message = _signed_message(resolver)
    event = RequestEvent(
        timestamp=now,
        request_id="runtime-jwks-1",
        client_id="client-1",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=100,
        http_version="HTTP/2",
        user_agent="ExampleBot/1.0",
        source="test",
    )
    claim = IdentityClaim(
        provider="example",
        agent="ExampleBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )

    resolution = manager.verify(
        event=event,
        context=_context(message),
        claim=claim,
    )

    assert resolution.state is VerificationState.VERIFIED
    assert resolution.agent_verified is True
    assert len(resolution.methods) == 1
    assert resolution.methods[0].outcome is VerificationOutcome.PASS
    assert resolution.methods[0].details["key_source_trusted"] is True
