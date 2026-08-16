from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote_from_bytes

import pytest

from agent_traffic_intelligence.identity.configured import ProviderAwareVerificationManager
from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import jwk_thumbprint
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
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


@dataclass
class Message:
    method: str
    url: str
    headers: dict[str, str]


class InlineSigningResolver:
    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.jwk: dict[str, object] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
            "use": "sig",
            "alg": "EdDSA",
        }
        self.key_id = jwk_thumbprint(self.jwk)
        self.jwk["kid"] = self.key_id

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private.public_key()


def _data_uri(resolver: InlineSigningResolver) -> str:
    body = json.dumps({"keys": [resolver.jwk]}, separators=(",", ":")).encode()
    return (
        "data:application/http-message-signatures-directory+json,"
        + quote_from_bytes(body, safe="")
    )


def _signed_message(
    resolver: InlineSigningResolver,
    *,
    discovery_type: str = "directory",
    uri: str | None = None,
) -> Message:
    signature_agent_uri = uri or _data_uri(resolver)
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
        key_id=resolver.key_id,
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


def _manager(tmp_path) -> ProviderAwareVerificationManager:
    manager = ProviderAwareVerificationManager(SourceCache(tmp_path))
    manager._profiles = {}
    return manager


def test_inline_data_directory_authenticates_key_without_claiming_agent_identity(
    tmp_path,
) -> None:
    now = datetime.now(UTC)
    resolver = InlineSigningResolver()
    inline_uri = _data_uri(resolver)
    message = _signed_message(resolver, uri=inline_uri)
    resolution = _manager(tmp_path).verify(
        event=_event(now, "inline-data-1"),
        context=_context(message),
        claim=_claim(),
    )

    assert resolution.state is VerificationState.CLAIMED
    assert resolution.agent_verified is False
    passed = [
        evidence
        for evidence in resolution.methods
        if evidence.method is VerificationMethod.WEB_BOT_AUTH
        and evidence.outcome is VerificationOutcome.PASS
    ]
    assert len(passed) == 1
    assert passed[0].binding_scope is BindingScope.KEY
    assert passed[0].subject == resolver.key_id
    assert passed[0].source_uri == "urn:ati:inline-data-directory:redacted"
    serialized = json.dumps(resolution.to_dict(), sort_keys=True)
    assert inline_uri not in serialized
    assert "data:application/http-message-signatures-directory+json" not in serialized


@pytest.mark.parametrize("discovery_type", ["jwks_uri", "cimd"])
def test_inline_data_is_not_accepted_for_non_directory_discovery_types(
    tmp_path,
    discovery_type: str,
) -> None:
    now = datetime.now(UTC)
    resolver = InlineSigningResolver()
    inline_uri = _data_uri(resolver)
    message = _signed_message(
        resolver,
        discovery_type=discovery_type,
        uri=inline_uri,
    )
    resolution = _manager(tmp_path).verify(
        event=_event(now, f"inline-data-{discovery_type}"),
        context=_context(message),
        claim=_claim(),
    )

    assert resolution.state is VerificationState.CLAIMED
    assert resolution.agent_verified is False
    assert not any(
        evidence.method is VerificationMethod.WEB_BOT_AUTH
        and evidence.outcome is VerificationOutcome.PASS
        for evidence in resolution.methods
    )
    assert inline_uri not in json.dumps(resolution.to_dict(), sort_keys=True)


def test_invalid_inline_data_media_type_is_ignored_without_payload_leak(tmp_path) -> None:
    now = datetime.now(UTC)
    resolver = InlineSigningResolver()
    payload = b'{"secret-marker":"must-not-leak"}'
    inline_uri = "data:application/json," + quote_from_bytes(payload, safe="")
    message = _signed_message(resolver, uri=inline_uri)
    resolution = _manager(tmp_path).verify(
        event=_event(now, "inline-data-invalid-media"),
        context=_context(message),
        claim=_claim(),
    )

    assert resolution.state is VerificationState.CLAIMED
    assert not any(
        evidence.method is VerificationMethod.WEB_BOT_AUTH
        and evidence.outcome is VerificationOutcome.PASS
        for evidence in resolution.methods
    )
    serialized = json.dumps(resolution.to_dict(), sort_keys=True)
    assert inline_uri not in serialized
    assert "must-not-leak" not in serialized
