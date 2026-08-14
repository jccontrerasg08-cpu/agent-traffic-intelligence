from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import KeyDirectory, parse_key_directory
from agent_traffic_intelligence.identity.crypto.replay import ReplayCache
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


DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"
NOW = datetime(2026, 8, 14, 11, 0, tzinfo=UTC)


def directory() -> KeyDirectory:
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


def claim() -> IdentityClaim:
    return IdentityClaim(
        provider="example",
        agent="ExampleBot",
        actor_type=ActorType.AI_CRAWLER,
        intent="test",
    )


def context(
    signature_agent: str | None = (
        'sig1="https://agent.example/.well-known/http-message-signatures-directory"'
    ),
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


@dataclass
class FakeRfcVerifier:
    result: Rfc9421Result
    calls: list[str]

    def verify(
        self,
        context: VerificationContext,
        *,
        algorithm_id: str,
        expect_tag: str,
        required_components: frozenset[str] = frozenset(),
        max_age_seconds: int = 86400,
    ) -> Rfc9421Result:
        self.calls.append(algorithm_id)
        return self.result


class FakeSignatureAgentParser:
    def __init__(self, references: tuple[SignatureAgentReference, ...]) -> None:
        self.references = references

    def parse(self, raw: str) -> tuple[SignatureAgentReference, ...]:
        return self.references


def good_result(*, nonce: str | None = "nonce-1") -> Rfc9421Result:
    key_id = directory().keys[0].key_id
    return Rfc9421Result(
        outcome=VerificationOutcome.PASS,
        explanation="verified",
        label="sig1",
        algorithm_id="ed25519",
        covered_components={
            '"@authority"': "example.com",
            '"signature-agent";key="sig1"': f'"{DIRECTORY_URI}"',
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
    references: tuple[SignatureAgentReference, ...] | None = None,
    replay_cache: ReplayCache | None = None,
    trusted: bool = True,
) -> tuple[WebBotAuthVerifier, FakeRfcVerifier]:
    rfc = FakeRfcVerifier(result=result, calls=[])
    refs = references or (
        SignatureAgentReference(label="sig1", uri=DIRECTORY_URI),
    )
    allowed = frozenset({DIRECTORY_URI}) if trusted else frozenset()
    return (
        WebBotAuthVerifier(
            directory=directory(),
            directory_uri=DIRECTORY_URI,
            binding_scope=BindingScope.AGENT,
            subject="ExampleBot",
            trust_policy=SourceTrustPolicy(allowed),
            rfc_verifier=rfc,
            signature_agent_parser=FakeSignatureAgentParser(refs),
            replay_cache=replay_cache,
        ),
        rfc,
    )


def test_valid_chain_binds_exact_agent() -> None:
    instance, rfc = verifier(good_result(), replay_cache=ReplayCache())
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)

    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.binding_scope is BindingScope.AGENT
    assert evidence.subject == "ExampleBot"
    assert evidence.details["signature_agent_bound"] is True
    assert evidence.details["replay_protected"] is True
    assert rfc.calls == ["ed25519"]


def test_signature_agent_present_but_unsigned_is_mismatch() -> None:
    result = good_result()
    result = Rfc9421Result(
        outcome=result.outcome,
        explanation=result.explanation,
        label=result.label,
        algorithm_id=result.algorithm_id,
        covered_components={'"@authority"': "example.com"},
        covered_component_names=frozenset({"@authority"}),
        parameters=result.parameters,
        nonce=result.nonce,
    )
    instance, _ = verifier(result)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.MISMATCH
    assert "Signature-Agent" in evidence.explanation


def test_signed_signature_agent_for_different_directory_is_mismatch() -> None:
    refs = (SignatureAgentReference(label="sig1", uri="https://other.example/keys"),)
    instance, _ = verifier(good_result(), references=refs)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.MISMATCH


def test_validity_window_over_24_hours_is_mismatch() -> None:
    result = good_result()
    params = dict(result.parameters or {})
    params["expires"] = int(params["created"]) + 86401
    result = Rfc9421Result(
        outcome=result.outcome,
        explanation=result.explanation,
        label=result.label,
        algorithm_id=result.algorithm_id,
        covered_components=result.covered_components,
        covered_component_names=result.covered_component_names,
        parameters=params,
        nonce=result.nonce,
    )
    instance, _ = verifier(result)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.MISMATCH
    assert "validity window" in evidence.explanation


def test_missing_authority_and_target_uri_is_mismatch() -> None:
    result = good_result()
    result = Rfc9421Result(
        outcome=result.outcome,
        explanation=result.explanation,
        label=result.label,
        algorithm_id=result.algorithm_id,
        covered_components={'"signature-agent";key="sig1"': f'"{DIRECTORY_URI}"'},
        covered_component_names=frozenset({"signature-agent"}),
        parameters=result.parameters,
        nonce=result.nonce,
    )
    instance, _ = verifier(result)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.MISMATCH
    assert "@authority" in evidence.explanation


def test_unknown_directory_under_registry_only_is_unavailable() -> None:
    instance, rfc = verifier(good_result(), trusted=False)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.UNAVAILABLE
    assert rfc.calls == []


def test_replayed_nonce_is_mismatch() -> None:
    cache = ReplayCache()
    instance, _ = verifier(good_result(), replay_cache=cache)
    first = instance.verify(context=context(), claim=claim(), now=NOW)
    second = instance.verify(context=context(), claim=claim(), now=NOW)
    assert first.outcome is VerificationOutcome.PASS
    assert second.outcome is VerificationOutcome.MISMATCH
    assert "nonce" in second.explanation


def test_no_nonce_can_verify_but_is_marked_unprotected() -> None:
    instance, _ = verifier(good_result(nonce=None), replay_cache=ReplayCache())
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.PASS
    assert evidence.details["nonce_present"] is False
    assert evidence.details["replay_protected"] is False


def test_non_integer_temporal_parameter_is_mismatch_not_exception() -> None:
    result = good_result()
    params = dict(result.parameters or {})
    params["created"] = "not-an-integer"
    result = Rfc9421Result(
        outcome=result.outcome,
        explanation=result.explanation,
        label=result.label,
        algorithm_id=result.algorithm_id,
        covered_components=result.covered_components,
        covered_component_names=result.covered_component_names,
        parameters=params,
        nonce=result.nonce,
    )
    instance, _ = verifier(result)
    evidence = instance.verify(context=context(), claim=claim(), now=NOW)
    assert evidence.outcome is VerificationOutcome.MISMATCH
    assert "created" in evidence.explanation
