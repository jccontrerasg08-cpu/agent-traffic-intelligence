"""Bounded concurrent orchestration of independent identity verifiers."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Protocol

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
    VerificationResolution,
)
from agent_traffic_intelligence.identity.policy import VerificationPolicy
from agent_traffic_intelligence.identity.resolver import IdentityResolver
from agent_traffic_intelligence.models import IdentityClaim, RequestEvent


class IdentityVerifier(Protocol):
    """Common execution seam implemented by configured network/crypto adapters."""

    @property
    def name(self) -> str: ...

    @property
    def method(self) -> VerificationMethod: ...

    @property
    def binding_scope(self) -> BindingScope: ...

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence: ...


class VerificationManager:
    """Run verifiers concurrently and resolve their immutable evidence deterministically."""

    def __init__(
        self,
        verifiers: tuple[IdentityVerifier, ...],
        *,
        policy: VerificationPolicy | None = None,
        resolver: IdentityResolver | None = None,
    ) -> None:
        self._verifiers = verifiers
        self._policy = policy or VerificationPolicy()
        self._resolver = resolver or IdentityResolver()

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationResolution:
        if not self._verifiers:
            return self._resolver.resolve(claim, ())

        executor = ThreadPoolExecutor(
            max_workers=min(self._policy.max_workers, len(self._verifiers)),
            thread_name_prefix="ati-verify",
        )
        futures: dict[Future[VerificationEvidence], IdentityVerifier] = {
            executor.submit(
                verifier.verify,
                event=event,
                context=context,
                claim=claim,
            ): verifier
            for verifier in self._verifiers
        }
        done, not_done = wait(
            futures,
            timeout=self._policy.verifier_timeout_seconds,
        )

        evidence: list[VerificationEvidence] = []
        for future in done:
            verifier = futures[future]
            try:
                evidence.append(future.result())
            except Exception as exc:  # pragma: no cover - exercised via public behavior
                evidence.append(self._execution_error(verifier, claim, exc))

        for future in not_done:
            verifier = futures[future]
            future.cancel()
            evidence.append(self._timeout(verifier, claim))

        executor.shutdown(wait=False, cancel_futures=True)
        return self._resolver.resolve(claim, tuple(evidence))

    @staticmethod
    def _subject(verifier: IdentityVerifier, claim: IdentityClaim) -> str | None:
        if verifier.binding_scope is BindingScope.AGENT:
            return claim.agent
        if verifier.binding_scope is BindingScope.PROVIDER:
            return claim.provider
        return None

    @classmethod
    def _timeout(
        cls,
        verifier: IdentityVerifier,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            method=verifier.method,
            outcome=VerificationOutcome.UNAVAILABLE,
            binding_scope=verifier.binding_scope,
            authority=claim.provider,
            subject=cls._subject(verifier, claim),
            explanation=f"verifier {verifier.name} exceeded the configured timeout",
            source_uri=None,
            source_profile="manager-timeout",
            retrieved_at=None,
            expires_at=None,
            source_sha256=None,
            details={"timeout": True},
        )

    @classmethod
    def _execution_error(
        cls,
        verifier: IdentityVerifier,
        claim: IdentityClaim,
        exc: Exception,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            method=verifier.method,
            outcome=VerificationOutcome.ERROR,
            binding_scope=verifier.binding_scope,
            authority=claim.provider,
            subject=cls._subject(verifier, claim),
            explanation=(
                f"verifier {verifier.name} raised an unexpected {type(exc).__name__}"
            ),
            source_uri=None,
            source_profile="manager-execution",
            retrieved_at=None,
            expires_at=None,
            source_sha256=None,
            details={"exception_type": type(exc).__name__},
        )
