from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.replay import ReplayCache
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Result
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentFormatError,
    SignatureAgentReference,
    SignatureAgentUnavailable,
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
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE
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


class UnavailableParser:
    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        raise SignatureAgentUnavailable("optional parser missing")


class InvalidParser:
    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        raise SignatureAgentFormatError("bad structured field")


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
    signature_agent: str | None = f'sig1="{DIRECTORY_URI}"',
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


def with_parameters(
    result: Rfc9421Result,
    **updates: object,
) -> Rfc9421Result:
    params = dict(result.parameters or {})
    for key, value in updates.items():
        if value is _MISSING:
            params.pop(key, None)
        else:
            params[key] = value
    return replace(result, parameters=params)


_MISSING = object()


def test_valid_chain_binds_exact_agent_and_replay() -> None:
    cache = ReplayCache()
    instance = verifier(good_result(), replay=cache)
    first = instance.verify(context=context(), claim=claim(), now=NOW)
    second = instance.verify(context=context(), claim=claim(), now=NOW)
    assert first.outcome is VerificationOutcome.PASS
    assert first.binding_scope is BindingScope.AGENT
    assert first.details["replay_protected"] is True
    assert second.outcome is VerificationOutcome.MISMATCH


def test_evidence_reports_current_protocol_profile() -> None:
    evidence = verifier(good_result(nonce=None)).verify(
        context=context(),
        claim=claim(),
        now=NOW,
    )

    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.source_profile == (
        f"{DEFAULT_STANDARDS_PROFILE.web_bot_auth_protocol}+"
        f"{DEFAULT_STANDARDS_PROFILE.message_signatures_directory}"
    )
    assert "architecture-05" not in evidence.source_profile
    assert "directory-05" not in evidence.source_profile


def test_unsigned_or_wrong_signature_agent_is_mismatch() -> None:
    result = good_result()
    unsigned = replace(
        result,
        covered_components={'"@authority"': "example.com"},
        covered_component_names=frozenset({"@authority"}),
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


def test_untrusted_directory_and_parser_failures_are_neutral_or_mismatch() -> None:
    result = good_result()
    untrusted = WebBotAuthVerifier(
        directory=directory(),
        directory_uri=DIRECTORY_URI,
        binding_scope=BindingScope.AGENT,
        trust_policy=SourceTrustPolicy(frozenset()),
        rfc_verifier=FakeRfcVerifier(result),
        signature_agent_parser=FakeSignatureAgentParser(),
    ).verify(context=context(), claim=claim(), now=NOW)
    assert untrusted.outcome is VerificationOutcome.UNAVAILABLE

    for parser, expected in (
        (UnavailableParser(), VerificationOutcome.UNAVAILABLE),
        (InvalidParser(), VerificationOutcome.MISMATCH),
    ):
        evidence = WebBotAuthVerifier(
            directory=directory(),
            directory_uri=DIRECTORY_URI,
            binding_scope=BindingScope.AGENT,
            trust_policy=SourceTrustPolicy(frozenset({DIRECTORY_URI})),
            rfc_verifier=FakeRfcVerifier(result),
            signature_agent_parser=parser,
        ).verify(context=context(), claim=claim(), now=NOW)
        assert evidence.outcome is expected


def test_rfc_failure_outcome_is_preserved() -> None:
    for outcome in (VerificationOutcome.UNAVAILABLE, VerificationOutcome.ERROR):
        result = Rfc9421Result(outcome=outcome, explanation="upstream result")
        evidence = verifier(result).verify(context=context(None), claim=claim(), now=NOW)
        assert evidence.outcome is outcome


@pytest.mark.parametrize(
    "result",
    [
        with_parameters(good_result(), created="bad"),
        with_parameters(good_result(), created=_MISSING),
        with_parameters(good_result(), expires=_MISSING),
        with_parameters(good_result(), tag="wrong"),
        with_parameters(good_result(), keyid=_MISSING),
        with_parameters(good_result(), keyid="missing"),
        with_parameters(
            good_result(),
            created=int(NOW.timestamp()),
            expires=int(NOW.timestamp()) + 86401,
        ),
        with_parameters(
            good_result(),
            created=int(NOW.timestamp()) + 60,
            expires=int(NOW.timestamp()) + 300,
        ),
        with_parameters(
            good_result(),
            created=int(NOW.timestamp()) - 300,
            expires=int(NOW.timestamp()) - 60,
        ),
        replace(good_result(), algorithm_id="rsa-pss-sha512"),
        replace(
            good_result(),
            covered_components={'"signature-agent";key="sig1"': '"x"'},
            covered_component_names=frozenset({"signature-agent"}),
        ),
    ],
)
def test_invalid_signature_policy_never_verifies(result: Rfc9421Result) -> None:
    evidence = verifier(result).verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is not VerificationOutcome.PASS


def test_non_https_signed_identity_and_naive_clock_fail_closed() -> None:
    evidence = verifier(good_result(), parser_uri="http://agent.example").verify(
        context=context(),
        claim=claim(),
        now=NOW,
    )
    assert evidence.outcome is VerificationOutcome.MISMATCH

    with pytest.raises(ValueError, match="timezone-aware"):
        verifier(good_result()).verify(
            context=context(),
            claim=claim(),
            now=datetime(2026, 8, 14, 11, 0),
        )


def test_signature_agent_is_optional_when_directory_binding_is_otherwise_valid() -> None:
    evidence = verifier(good_result(nonce=None)).verify(
        context=context(None),
        claim=claim(),
        now=NOW,
    )
    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.details["signature_agent_present"] is False
    assert evidence.details["nonce_present"] is False
