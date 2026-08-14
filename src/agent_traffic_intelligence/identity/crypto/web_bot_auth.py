"""Policy and identity binding for the pinned Web Bot Auth architecture profile."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import KeyDirectory
from agent_traffic_intelligence.identity.crypto.key_resolver import JwkKeyResolver
from agent_traffic_intelligence.identity.crypto.replay import ReplayCache
from agent_traffic_intelligence.identity.crypto.rfc9421 import (
    Rfc9421Result,
    Rfc9421Verifier,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentFormatError,
    SignatureAgentParser,
    SignatureAgentReference,
    SignatureAgentUnavailable,
    StructuredFieldSignatureAgentParser,
)
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.sources.trust import (
    SourceTrustPolicy,
    canonicalize_source_uri,
)
from agent_traffic_intelligence.models import IdentityClaim

_WEB_BOT_AUTH_TAG = "web-bot-auth"
_MAX_VALIDITY_SECONDS = 24 * 60 * 60
_CLOCK_SKEW_SECONDS = 5
_KEY_PARAM_RE = re.compile(r';key="([^"\\]+)"')


class RfcVerifier(Protocol):
    def verify(
        self,
        context: VerificationContext,
        *,
        algorithm_id: str,
        expect_tag: str,
        required_components: frozenset[str] = frozenset(),
        max_age_seconds: int = _MAX_VALIDITY_SECONDS,
    ) -> Rfc9421Result: ...


@dataclass(frozen=True, slots=True)
class WebBotAuthPolicy:
    max_validity_seconds: int = _MAX_VALIDITY_SECONDS
    clock_skew_seconds: int = _CLOCK_SKEW_SECONDS


class WebBotAuthVerifier:
    def __init__(
        self,
        *,
        directory: KeyDirectory,
        directory_uri: str,
        binding_scope: BindingScope,
        signature_agent_uri: str | None = None,
        trust_policy: SourceTrustPolicy,
        subject: str | None = None,
        rfc_verifier: RfcVerifier | None = None,
        signature_agent_parser: SignatureAgentParser | None = None,
        replay_cache: ReplayCache | None = None,
        policy: WebBotAuthPolicy | None = None,
    ) -> None:
        self._directory = directory
        self._directory_uri = canonicalize_source_uri(directory_uri)
        self._signature_agent_uri = canonicalize_source_uri(
            signature_agent_uri or directory_uri
        )
        self._binding_scope = binding_scope
        self._subject = subject
        self._trust_policy = trust_policy
        self._rfc = rfc_verifier or Rfc9421Verifier(JwkKeyResolver(directory))
        self._signature_agent_parser = (
            signature_agent_parser or StructuredFieldSignatureAgentParser()
        )
        self._replay_cache = replay_cache
        self._policy = policy or WebBotAuthPolicy()

    def verify(
        self,
        *,
        context: VerificationContext,
        claim: IdentityClaim,
        now: datetime,
    ) -> VerificationEvidence:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Web Bot Auth verification time must be timezone-aware")
        if not self._trust_policy.allows(self._directory_uri):
            return self._evidence(
                claim,
                VerificationOutcome.UNAVAILABLE,
                "key directory is not trusted",
                {"directory_trusted": False},
            )

        references: tuple[SignatureAgentReference, ...] = ()
        if context.signature_agent is not None:
            try:
                references = self._signature_agent_parser.parse(context.signature_agent)
            except SignatureAgentUnavailable:
                return self._evidence(
                    claim,
                    VerificationOutcome.UNAVAILABLE,
                    "Structured Fields support is unavailable",
                    {"directory_trusted": True},
                )
            except SignatureAgentFormatError as exc:
                return self._evidence(
                    claim,
                    VerificationOutcome.MISMATCH,
                    f"Signature-Agent parse failed: {exc}",
                    {"directory_trusted": True},
                )

        result = self._verify_rfc(context)
        if result.outcome is not VerificationOutcome.PASS:
            return self._evidence(
                claim,
                result.outcome,
                result.explanation,
                {"directory_trusted": True},
            )

        params = result.parameters or {}
        try:
            created = self._integer_parameter(params.get("created"), "created")
            expires = self._integer_parameter(params.get("expires"), "expires")
        except ValueError as exc:
            return self._mismatch(claim, str(exc))
        key_id = params.get("keyid")
        if not isinstance(key_id, str) or not key_id:
            return self._mismatch(claim, "verified signature is missing a usable keyid")
        if params.get("tag") != _WEB_BOT_AUTH_TAG:
            return self._mismatch(claim, "verified signature has the wrong Web Bot Auth tag")
        if created is None or expires is None:
            return self._mismatch(claim, "Web Bot Auth requires created and expires")
        if expires <= created or expires - created > self._policy.max_validity_seconds:
            return self._mismatch(claim, "signature validity window violates ATI policy")
        now_ts = int(now.timestamp())
        skew = self._policy.clock_skew_seconds
        if created > now_ts + skew or expires < now_ts - skew:
            return self._mismatch(
                claim,
                "signature validity window does not include verification time",
            )
        if not ({"@authority", "@target-uri"} & result.covered_component_names):
            return self._mismatch(
                claim,
                "Web Bot Auth must sign @authority or @target-uri",
            )

        try:
            key = self._directory.by_id(key_id)
        except KeyError:
            return self._evidence(
                claim,
                VerificationOutcome.UNAVAILABLE,
                "keyid is absent from trusted directory",
                {"directory_trusted": True},
            )
        if not key.active_at(now):
            return self._mismatch(
                claim,
                "directory key is not active at verification time",
            )
        if not self._algorithm_matches_key(
            result.algorithm_id,
            key.alg,
            key.kty,
            key.jwk.get("crv"),
        ):
            return self._mismatch(
                claim,
                "signature algorithm is incompatible with directory key",
            )

        signature_agent_bound = False
        legacy = False
        if references:
            selected = self._bound_signature_agent(result, references)
            if selected is None:
                return self._mismatch(
                    claim,
                    "Signature-Agent was not covered by the verified signature",
                )
            try:
                referenced_uri = canonicalize_source_uri(selected.uri)
            except ValueError:
                return self._mismatch(
                    claim,
                    "signed Signature-Agent URI is not acceptable HTTPS",
                )
            if referenced_uri != self._signature_agent_uri:
                return self._mismatch(
                    claim,
                    "signed Signature-Agent URI does not match registered agent identity",
                )
            signature_agent_bound = True
            legacy = selected.legacy

        nonce_present = result.nonce is not None
        replay_protected = False
        if result.nonce is not None and self._replay_cache is not None:
            if self._replay_cache.seen_or_add(
                key_id,
                result.nonce,
                expires=expires,
                now=now_ts,
            ):
                return self._mismatch(claim, "signature nonce was already observed")
            replay_protected = True

        return self._evidence(
            claim,
            VerificationOutcome.PASS,
            "Web Bot Auth signature and trusted directory binding verified",
            {
                "algorithm": result.algorithm_id,
                "directory_trusted": True,
                "key_active": True,
                "signed_authority_or_target": True,
                "signature_agent_present": bool(references),
                "signature_agent_bound": signature_agent_bound,
                "legacy_signature_agent": legacy,
                "nonce_present": nonce_present,
                "replay_protected": replay_protected,
            },
        )

    def _verify_rfc(self, context: VerificationContext) -> Rfc9421Result:
        results: list[Rfc9421Result] = []
        for algorithm_id in self._candidate_algorithms():
            result = self._rfc.verify(
                context,
                algorithm_id=algorithm_id,
                expect_tag=_WEB_BOT_AUTH_TAG,
                max_age_seconds=self._policy.max_validity_seconds,
            )
            if result.outcome is VerificationOutcome.PASS:
                return result
            results.append(result)
        if any(item.outcome is VerificationOutcome.ERROR for item in results):
            return next(
                item
                for item in results
                if item.outcome is VerificationOutcome.ERROR
            )
        if results and all(
            item.outcome is VerificationOutcome.UNAVAILABLE for item in results
        ):
            return results[0]
        return Rfc9421Result(
            outcome=VerificationOutcome.MISMATCH,
            explanation="no allowed asymmetric algorithm verified the Web Bot Auth signature",
        )

    def _candidate_algorithms(self) -> tuple[str, ...]:
        algorithms: list[str] = []
        for key in self._directory.keys:
            crv = key.jwk.get("crv")
            candidates: tuple[str, ...]
            if key.kty == "OKP" and crv == "Ed25519":
                candidates = ("ed25519",)
            elif key.kty == "EC" and crv == "P-256":
                candidates = ("ecdsa-p256-sha256",)
            elif key.kty == "RSA":
                candidates = ("rsa-pss-sha512", "rsa-v1_5-sha256")
            else:
                candidates = ()
            for algorithm in candidates:
                if algorithm not in algorithms:
                    algorithms.append(algorithm)
        return tuple(algorithms)

    @staticmethod
    def _integer_parameter(value: object, name: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"verified signature parameter {name} must be an integer"
            )
        return value

    @staticmethod
    def _algorithm_matches_key(
        verified_algorithm: str | None,
        key_alg: str | None,
        kty: str,
        crv: object,
    ) -> bool:
        compatible = {
            "ed25519": {None, "EdDSA", "ed25519"},
            "ecdsa-p256-sha256": {None, "ES256", "ecdsa-p256-sha256"},
            "rsa-pss-sha512": {None, "PS512", "rsa-pss-sha512"},
            "rsa-v1_5-sha256": {None, "RS256", "rsa-v1_5-sha256"},
        }
        if verified_algorithm == "ed25519" and not (
            kty == "OKP" and crv == "Ed25519"
        ):
            return False
        if verified_algorithm == "ecdsa-p256-sha256" and not (
            kty == "EC" and crv == "P-256"
        ):
            return False
        if verified_algorithm and verified_algorithm.startswith("rsa-") and kty != "RSA":
            return False
        return (
            verified_algorithm is not None
            and key_alg in compatible.get(verified_algorithm, set())
        )

    @staticmethod
    def _bound_signature_agent(
        result: Rfc9421Result,
        references: tuple[SignatureAgentReference, ...],
    ) -> SignatureAgentReference | None:
        signed_keys: set[str | None] = set()
        for component in result.covered_components or {}:
            component_name = component.split(";", 1)[0].strip('"').casefold()
            if component_name != "signature-agent":
                continue
            match = _KEY_PARAM_RE.search(component)
            signed_keys.add(match.group(1) if match else None)
        return next(
            (reference for reference in references if reference.label in signed_keys),
            None,
        )

    def _mismatch(
        self,
        claim: IdentityClaim,
        explanation: str,
    ) -> VerificationEvidence:
        return self._evidence(
            claim,
            VerificationOutcome.MISMATCH,
            explanation,
            {"directory_trusted": True},
        )

    def _evidence(
        self,
        claim: IdentityClaim,
        outcome: VerificationOutcome,
        explanation: str,
        details: dict[str, str | int | float | bool | None],
    ) -> VerificationEvidence:
        subject: str | None
        if self._binding_scope is BindingScope.AGENT:
            subject = self._subject or claim.agent
        elif self._binding_scope is BindingScope.PROVIDER:
            subject = self._subject or claim.provider
        else:
            subject = self._subject
        return VerificationEvidence(
            method=VerificationMethod.WEB_BOT_AUTH,
            outcome=outcome,
            binding_scope=self._binding_scope,
            authority=claim.provider,
            subject=subject,
            explanation=explanation,
            source_uri=self._directory_uri,
            source_profile="draft-meunier-web-bot-auth-architecture-05+directory-05",
            retrieved_at=None,
            expires_at=None,
            source_sha256=None,
            details=details,
        )
