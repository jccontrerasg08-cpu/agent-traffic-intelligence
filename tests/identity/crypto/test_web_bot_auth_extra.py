from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import (
    jwk_thumbprint,
    parse_key_directory,
)
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Verifier
from agent_traffic_intelligence.identity.crypto.web_bot_auth import WebBotAuthVerifier
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import ActorType, IdentityClaim

DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"


@dataclass
class Message:
    method: str
    url: str
    headers: dict[str, str]


def test_ed25519_end_to_end_web_bot_auth_chain() -> None:
    hms = pytest.importorskip("http_message_signatures")
    pytest.importorskip("http_sf")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x, "use": "sig"}
    key_id = jwk_thumbprint(jwk)
    jwk["kid"] = key_id
    directory = parse_key_directory({"keys": [jwk]})

    class PrivateResolver:
        def resolve_public_key(self, key_id_value: str) -> object:
            if key_id_value != key_id:
                raise KeyError(key_id_value)
            return private_key.public_key()

        def resolve_private_key(self, key_id_value: str) -> object:
            if key_id_value != key_id:
                raise KeyError(key_id_value)
            return private_key

    now = datetime.now(UTC)
    message = Message(
        method="GET",
        url="https://example.com/docs",
        headers={"Signature-Agent": f'sig1="{DIRECTORY_URI}"'},
    )
    signer = hms.HTTPMessageSigner(
        signature_algorithm=hms.algorithms.ED25519,
        key_resolver=PrivateResolver(),
        component_resolver_class=Rfc9421Verifier._component_resolver(hms),
    )
    signer.sign(
        message,
        key_id=key_id,
        created=now,
        expires=now + timedelta(minutes=5),
        nonce="e2e-nonce",
        tag="web-bot-auth",
        label="sig1",
        covered_component_ids=("@authority", '"signature-agent";key="sig1"'),
    )

    context = VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri=message.url,
        signature=message.headers["Signature"],
        signature_input=message.headers["Signature-Input"],
        signature_agent=message.headers["Signature-Agent"],
        covered_headers={},
    )
    claim = IdentityClaim(
        provider="example",
        agent="ExampleBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )
    verifier = WebBotAuthVerifier(
        directory=directory,
        directory_uri=DIRECTORY_URI,
        binding_scope=BindingScope.AGENT,
        subject="ExampleBot",
        trust_policy=SourceTrustPolicy(frozenset({DIRECTORY_URI})),
    )
    evidence = verifier.verify(context=context, claim=claim, now=now)

    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.AGENT
    assert evidence.details["algorithm"] == "ed25519"
    assert evidence.details["signature_agent_bound"] is True
