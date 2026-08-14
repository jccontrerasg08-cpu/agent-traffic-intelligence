from __future__ import annotations

from datetime import UTC, datetime

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Result
from agent_traffic_intelligence.identity.crypto.signature_agent import SignatureAgentReference
from agent_traffic_intelligence.identity.crypto.web_bot_auth import WebBotAuthVerifier
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import ActorType, IdentityClaim

IDENTITY_URI = "https://agent.bot.goog"
DIRECTORY_URI = "https://agent.bot.goog/.well-known/http-message-signatures-directory"
NOW = datetime(2026, 8, 14, 11, 0, tzinfo=UTC)


class FakeRfcVerifier:
    def __init__(self, result: Rfc9421Result) -> None:
        self.result = result

    def verify(
        self,
        context: VerificationContext,
        *,
        algorithm_id: str,
        expect_tag: str,
        required_components: frozenset[str] = frozenset(),
        max_age_seconds: int = 86400,
    ) -> Rfc9421Result:
        return self.result


class FakeSignatureAgentParser:
    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        return (SignatureAgentReference(label="sig1", uri=IDENTITY_URI),)


def test_google_identity_uri_can_use_well_known_key_directory() -> None:
    directory = parse_key_directory(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
                    "use": "sig",
                    "nbf": int(NOW.timestamp()) - 60,
                    "exp": int(NOW.timestamp()) + 7200,
                }
            ]
        }
    )
    key_id = directory.keys[0].key_id
    result = Rfc9421Result(
        outcome=VerificationOutcome.PASS,
        explanation="verified",
        label="sig1",
        algorithm_id="ed25519",
        covered_components={
            '"@authority"': "example.com",
            '"signature-agent";key="sig1"': f'"{IDENTITY_URI}"',
        },
        covered_component_names=frozenset({"@authority", "signature-agent"}),
        parameters={
            "created": int(NOW.timestamp()) - 10,
            "expires": int(NOW.timestamp()) + 300,
            "keyid": key_id,
            "tag": "web-bot-auth",
        },
    )
    verifier = WebBotAuthVerifier(
        directory=directory,
        directory_uri=DIRECTORY_URI,
        signature_agent_uri=IDENTITY_URI,
        binding_scope=BindingScope.AGENT,
        subject="Google-Agent",
        trust_policy=SourceTrustPolicy(frozenset({DIRECTORY_URI})),
        rfc_verifier=FakeRfcVerifier(result),
        signature_agent_parser=FakeSignatureAgentParser(),
    )
    context = VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature="sig1=:placeholder:",
        signature_input='sig1=("@authority");created=1',
        signature_agent=f'sig1="{IDENTITY_URI}"',
        covered_headers={},
    )
    claim = IdentityClaim(
        provider="google",
        agent="Google-Agent",
        actor_type=ActorType.AI_USER_AGENT,
        intent="user-triggered-agent",
    )

    evidence = verifier.verify(context=context, claim=claim, now=NOW)

    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.AGENT
    assert evidence.subject == "Google-Agent"
    assert evidence.source_uri == DIRECTORY_URI
