"""Deterministic resolution of independent identity-verification evidence."""

from __future__ import annotations

from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationOutcome,
    VerificationResolution,
)
from agent_traffic_intelligence.models import IdentityClaim, VerificationState

_NEUTRAL_OUTCOMES = {
    VerificationOutcome.UNAVAILABLE,
    VerificationOutcome.INDETERMINATE,
    VerificationOutcome.STALE,
    VerificationOutcome.ERROR,
}


def _evidence_key(item: VerificationEvidence) -> tuple[str, str, str, str, str, str]:
    return (
        item.method.value,
        item.binding_scope.value,
        item.authority or "",
        item.subject or "",
        item.outcome.value,
        item.source_uri or "",
    )


def _provider_matches(claim: IdentityClaim, item: VerificationEvidence) -> bool:
    return item.authority is not None and item.authority.casefold() == claim.provider.casefold()


def _agent_matches(claim: IdentityClaim, item: VerificationEvidence) -> bool:
    return _provider_matches(claim, item) and item.subject == claim.agent


class IdentityResolver:
    """Resolve scoped evidence without converting operational failure into identity failure."""

    def resolve(
        self,
        claim: IdentityClaim,
        evidence: tuple[VerificationEvidence, ...],
    ) -> VerificationResolution:
        ordered = tuple(sorted(evidence, key=_evidence_key))

        matching_agent_pass = any(
            item.outcome is VerificationOutcome.PASS
            and item.binding_scope is BindingScope.AGENT
            and _agent_matches(claim, item)
            for item in ordered
        )
        matching_provider_pass = any(
            item.outcome is VerificationOutcome.PASS
            and item.binding_scope in {BindingScope.PROVIDER, BindingScope.AGENT}
            and _provider_matches(claim, item)
            for item in ordered
        )

        foreign_strong_passes = tuple(
            item
            for item in ordered
            if item.outcome is VerificationOutcome.PASS
            and item.binding_scope in {BindingScope.PROVIDER, BindingScope.AGENT}
            and (
                not _provider_matches(claim, item)
                or (
                    item.binding_scope is BindingScope.AGENT
                    and not _agent_matches(claim, item)
                )
            )
        )
        applicable_mismatches = tuple(
            item
            for item in ordered
            if item.outcome is VerificationOutcome.MISMATCH
            and item.binding_scope in {BindingScope.PROVIDER, BindingScope.AGENT}
            and _provider_matches(claim, item)
            and (
                item.binding_scope is BindingScope.PROVIDER
                or item.subject in (None, claim.agent)
            )
        )

        conflicts: list[str] = []
        for item in foreign_strong_passes:
            subject = item.subject or item.authority or "unknown"
            conflicts.append(
                f"strong {item.binding_scope.value} evidence binds request to {subject}"
            )
        if applicable_mismatches and (matching_agent_pass or matching_provider_pass):
            conflicts.append("authoritative positive and negative identity evidence disagree")

        if conflicts:
            state = VerificationState.CONFLICTED
            provider_verified = False
            agent_verified = False
        elif matching_agent_pass:
            state = VerificationState.VERIFIED
            provider_verified = True
            agent_verified = True
        elif applicable_mismatches:
            state = VerificationState.FAILED
            provider_verified = False
            agent_verified = False
        else:
            state = VerificationState.CLAIMED
            provider_verified = matching_provider_pass
            agent_verified = False

        assert all(
            item.outcome in _NEUTRAL_OUTCOMES
            or item.outcome in {VerificationOutcome.PASS, VerificationOutcome.MISMATCH}
            for item in ordered
        )

        return VerificationResolution(
            state=state,
            provider_verified=provider_verified,
            agent_verified=agent_verified,
            provider=claim.provider,
            agent=claim.agent,
            methods=ordered,
            conflicts=tuple(conflicts),
        )
