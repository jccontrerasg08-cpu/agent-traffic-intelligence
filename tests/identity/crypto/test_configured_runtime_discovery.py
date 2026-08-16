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
CIMD_URI = "https://agent.example/client-metadata.json"


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


def _signed_message(
    resolver: SigningResolver,
    *,
    signature_agent_uri: str = JWKS_URI,
    discovery_type: str = "jwks_uri",
) -> Message:
    message = Message("GET", "https://example.com/docs", {})
    message.headers["Signature-Agent"] = (
        f'sig1="{signature_agent_uri}";type={discovery_type}'
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


def _event(now: datetime, request_id: str) -> RequestEvent:
    return RequestEvent(
        timestamp=now,
        request_id=request_id,
        client_id="client-1",
        method="GET",
        path="/docs",
        status=200,
        bytes_sent=100,
        http_version="HTTP/2",
        user_agent="ExampleBot/1.0",
        source="test",
    )


def _claim() -> IdentityClaim:
    return IdentityClaim(
        provider="example",
        agent="ExampleBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def _manager(
    cache: SourceCache,
    source: CryptoSourceProfile,
    *,
    allowlisted: frozenset[str],
) -> ProviderAwareVerificationManager:
    profile = ProviderProfile(
        provider="example",
        range_sources=(),
        fcrdns=None,
        crypto=CryptoProfile(signature_agents=(source,), reviewed_on="2026-08-16"),
    )
    manager = ProviderAwareVerificationManager(cache)
    manager._profiles = {"example": profile}
    manager._trust = SourceTrustPolicy(allowlisted)
    return manager


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

    manager = _manager(cache, source, allowlisted=frozenset({JWKS_URI}))
    message = _signed_message(resolver)
    resolution = manager.verify(
        event=_event(now, "runtime-jwks-1"),
        context=_context(message),
        claim=_claim(),
    )

    assert resolution.state is VerificationState.VERIFIED
    assert resolution.agent_verified is True
    assert len(resolution.methods) == 1
    assert resolution.methods[0].outcome is VerificationOutcome.PASS
    assert resolution.methods[0].details["key_source_trusted"] is True


def test_runtime_verifies_allowlisted_cached_cimd_inline_jwks_without_network(
    tmp_path,
) -> None:
    now = datetime.now(UTC)
    resolver = SigningResolver()
    source = CryptoSourceProfile(
        signature_agent_uri=CIMD_URI,
        directory_uri=CIMD_URI,
        interoperability_profile=CryptoInteroperabilityProfile.IETF_HTTPSIG_PROTOCOL_01,
        discovery_type=CryptoDiscoveryType.CIMD,
        binding_scope=BindingScope.AGENT,
        reviewed_on="2026-08-16",
        subject="ExampleBot",
    )
    cache = SourceCache(tmp_path)
    card = {
        "client_id": CIMD_URI,
        "client_name": "Example Bot",
        "jwks": {"keys": [_public_jwk(resolver)]},
        "web_bot_auth": {"expected-user-agent": "ExampleBot/1.0"},
    }
    cache.put(
        SourceDocument.from_bytes(
            uri=CIMD_URI,
            source_type=SourceType.AGENT_CARD,
            provider="example",
            binding_scope=BindingScope.AGENT,
            retrieved_at=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
            content=json.dumps(card).encode(),
            content_type="application/json",
            parser_profile="draft-meunier-webbotauth-registry-03",
            acquisition=SourceAcquisition.DIRECT_HTTPS,
        )
    )

    manager = _manager(cache, source, allowlisted=frozenset({CIMD_URI}))
    message = _signed_message(
        resolver,
        signature_agent_uri=CIMD_URI,
        discovery_type="cimd",
    )
    resolution = manager.verify(
        event=_event(now, "runtime-cimd-1"),
        context=_context(message),
        claim=_claim(),
    )

    assert resolution.state is VerificationState.VERIFIED
    assert resolution.agent_verified is True
    assert len(resolution.methods) == 1
    assert resolution.methods[0].outcome is VerificationOutcome.PASS
    assert resolution.methods[0].details["key_source_trusted"] is True
