from __future__ import annotations

from datetime import UTC, datetime

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.replay import ReplayCache
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Result
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentReference,
)
from agent_traffic_intelligence.identity.crypto.web_bot_auth import (
    WebBotAuthVerifier,
)
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import ActorType, IdentityClaim

DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"
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
    def __init__(self, uri: str = DIRECTORY_URI) -> None:
        self.uri = uri

    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        return (SignatureAgentReference(label="sig1", uri=self.uri),)


def directory():
    return parse_key_directory(
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


def claim(provider: str = "example", agent: str = "ExampleBot") -> IdentityClaim:
    return IdentityClaim(
        provider=provider,
        agent=agent,
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def context(
    signature_agent: str = f'sig1="{DIRECTORY_URI}"',
) -> VerificationContext:
    return VerificationContext(
        source_ip=None,
        source_address_provenance=SourceAddressProvenance.UNKNOWN,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature="sig1=:placeholder:",
        signature_input='sig1=("@authority");created=1',
        signature_agent=signature_agent,
        covered_headers={},
    )


def good_result(
    *,
    nonce: str | None = "nonce-1",
    identity_uri: str = DIRECTORY_URI,
) -> Rfc9421Result:
    key_id = directory().keys[0].key_id
    return Rfc9421Result(
        outcome=VerificationOutcome.PASS,
        explanation="verified",
        label="sig1",
        algorithm_id="ed25519",
        covered_components={
            '"@authority"': "example.com",
            '"signature-agent";key="sig1"': f'"{identity_uri}"',
        },
        covered_component_names=frozenset({"@authority", "signature-agent"}),
        parameters={
            "created": int(NOW.timestamp()) - 10,
            "expires": int(NOW.timestamp()) + 300,
            "keyid": key_id,
            "tag": "web-bot-auth",
        },
        nonce=nonce,
    )


def verifier(
    result: Rfc9421Result,
    *,
    identity_uri: str = DIRECTORY_URI,
    parser_uri: str | None = None,
    replay: ReplayCache | None = None,
) -> WebBotAuthVerifier:
    return WebBotAuthVerifier(
        directory=directory(),
        directory_uri=DIRECTORY_URI,
        signature_agent_uri=identity_uri,
        binding_scope=BindingScope.AGENT,
        subject="ExampleBot",
        trust_policy=SourceTrustPolicy(frozenset({DIRECTORY_URI})),
        rfc_verifier=FakeRfcVerifier(result),
        signature_agent_parser=FakeSignatureAgentParser(parser_uri or identity_uri),
        replay_cache=replay,
    )


def test_valid_chain_binds_exact_agent_and_replay() -> None:
    cache = ReplayCache()
    instance = verifier(good_result(), replay=cache)
    first = instance.verify(context=context(), claim=claim(), now=NOW)
    second = instance.verify(context=context(), claim=claim(), now=NOW)
    assert first.outcome is VerificationOutcome.PASS
    assert first.binding_scope is BindingScope.AGENT
    assert first.details["replay_protected"] is True
    assert second.outcome is VerificationOutcome.MISMATCH


def test_unsigned_or_wrong_signature_agent_is_mismatch() -> None:
    result = good_result()
    unsigned = Rfc9421Result(
        outcome=result.outcome,
        explanation=result.explanation,
        label=result.label,
        algorithm_id=result.algorithm_id,
        covered_components={'"@authority"': "example.com"},
        covered_component_names=frozenset({"@authority"}),
        parameters=result.parameters,
        nonce=result.nonce,
    )
    unsigned_evidence = verifier(unsigned).verify(
        context=context(),
        claim=claim(),
        now=NOW,
    )
    wrong_uri_evidence = verifier(
        result,
        parser_uri="https://other.example/keys",
    ).verify(
        context=context(),
        claim=claim(),
        now=NOW,
    )
    assert unsigned_evidence.outcome is VerificationOutcome.MISMATCH
    assert wrong_uri_evidence.outcome is VerificationOutcome.MISMATCH


def test_google_style_identity_uri_can_use_well_known_directory() -> None:
    identity_uri = "https://agent.bot.goog"
    instance = verifier(
        good_result(nonce=None, identity_uri=identity_uri),
        identity_uri=identity_uri,
    )
    evidence = instance.verify(
        context=context(f'sig1="{identity_uri}"'),
        claim=claim("google", "Google-Agent"),
        now=NOW,
    )
    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.source_uri == DIRECTORY_URI
