"""Official published-range identity verifier."""

from __future__ import annotations

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.network.formats.jafar import parse_jafar
from agent_traffic_intelligence.identity.network.formats.prefixes_v1 import (
    parse_prefixes_v1,
)
from agent_traffic_intelligence.identity.network.ranges import (
    PublishedRangeSet,
    RangeFormatError,
)
from agent_traffic_intelligence.identity.profiles import (
    NegativeSemantics,
    RangeSourceProfile,
)
from agent_traffic_intelligence.identity.sources.models import SourceDocument
from agent_traffic_intelligence.models import IdentityClaim

_TRUSTED_ADDRESS_PROVENANCE = {
    SourceAddressProvenance.DIRECT_PEER,
    SourceAddressProvenance.TRUSTED_EDGE_CLIENT,
}


class OfficialRangeVerifier:
    """Verify a claim against one authoritative provider-owned range publication."""

    def verify(
        self,
        *,
        context: VerificationContext,
        claim: IdentityClaim,
        source_profile: RangeSourceProfile,
        document: SourceDocument,
    ) -> VerificationEvidence:
        if claim.provider.casefold() != (document.metadata.provider or "").casefold():
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.INDETERMINATE,
                explanation="range document provider does not match the identity claim",
                details={"applicable": False},
            )
        if document.metadata.uri != source_profile.uri:
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.ERROR,
                explanation="cached range document URI does not match the provider profile",
                details={"applicable": False},
            )
        if source_profile.subject is not None and source_profile.subject != claim.agent:
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.INDETERMINATE,
                explanation="agent-specific range source does not apply to the claimed agent",
                details={"applicable": False},
            )
        if (
            context.source_ip is None
            or context.source_address_provenance not in _TRUSTED_ADDRESS_PROVENANCE
        ):
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.UNAVAILABLE,
                explanation="a trusted ephemeral source address is unavailable",
                details={"applicable": True},
            )

        try:
            published = self._parse(document.content, source_profile.format_profile)
            match = published.match(context.source_ip)
        except RangeFormatError as exc:
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.ERROR,
                explanation=f"published range source could not be validated: {exc}",
                details={"applicable": True},
            )

        details: dict[str, str | int | float | bool | None] = {
            "applicable": True,
            "matched": match.matched,
            "prefix_length": match.prefix_length,
        }
        if source_profile.category is not None:
            details["category"] = source_profile.category
        if match.services:
            details["services"] = ",".join(match.services)

        if match.matched:
            return self._evidence(
                claim=claim,
                source_profile=source_profile,
                document=document,
                outcome=VerificationOutcome.PASS,
                explanation="source address matched an official published range",
                details=details,
            )
        if source_profile.negative_semantics is NegativeSemantics.AUTHORITATIVE_NEGATIVE:
            outcome = VerificationOutcome.MISMATCH
            explanation = "source address was outside an authoritative published range set"
        else:
            outcome = VerificationOutcome.INDETERMINATE
            explanation = "source address did not match a positive-only published range set"
        return self._evidence(
            claim=claim,
            source_profile=source_profile,
            document=document,
            outcome=outcome,
            explanation=explanation,
            details=details,
        )

    @staticmethod
    def _parse(content: bytes, format_profile: str) -> PublishedRangeSet:
        if format_profile == "prefixes-v1":
            return parse_prefixes_v1(content)
        if format_profile == "jafar-00":
            return parse_jafar(content)
        raise RangeFormatError(f"unsupported range format profile: {format_profile}")

    @staticmethod
    def _evidence(
        *,
        claim: IdentityClaim,
        source_profile: RangeSourceProfile,
        document: SourceDocument,
        outcome: VerificationOutcome,
        explanation: str,
        details: dict[str, str | int | float | bool | None],
    ) -> VerificationEvidence:
        subject = source_profile.subject or claim.provider
        return VerificationEvidence(
            method=VerificationMethod.OFFICIAL_RANGE,
            outcome=outcome,
            binding_scope=source_profile.binding_scope,
            authority=claim.provider,
            subject=subject,
            explanation=explanation,
            source_uri=document.metadata.uri,
            source_profile=source_profile.format_profile,
            retrieved_at=document.metadata.retrieved_at,
            expires_at=document.metadata.expires_at,
            source_sha256=document.metadata.sha256,
            details=details,
        )
