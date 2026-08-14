"""Provider-aware composition of cached network and cryptographic verifiers."""

from __future__ import annotations

from dataclasses import dataclass, replace

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    parse_key_directory,
)
from agent_traffic_intelligence.identity.crypto.web_bot_auth import WebBotAuthVerifier
from agent_traffic_intelligence.identity.manager import IdentityVerifier, VerificationManager
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
    VerificationResolution,
)
from agent_traffic_intelligence.identity.network.fcrdns import FcrdnsVerifier
from agent_traffic_intelligence.identity.network.verifier import OfficialRangeVerifier
from agent_traffic_intelligence.identity.policy import VerificationMode, VerificationPolicy
from agent_traffic_intelligence.identity.profiles import (
    CryptoSourceProfile,
    FcrdnsProfile,
    ProviderProfile,
    RangeSourceProfile,
    load_provider_profiles,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import IdentityClaim, RequestEvent


@dataclass(slots=True)
class _RangeAdapter:
    provider: str
    profile: RangeSourceProfile
    cache: SourceCache
    name: str = "official-range"
    method: VerificationMethod = VerificationMethod.OFFICIAL_RANGE

    @property
    def binding_scope(self) -> BindingScope:
        return self.profile.binding_scope

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        document = self.cache.get(self.profile.uri)
        if document is None:
            return _neutral_missing(
                method=self.method,
                scope=self.binding_scope,
                authority=self.provider,
                subject=self.profile.subject or self.provider,
                source_uri=self.profile.uri,
                explanation="official range source is not present in the local cache",
            )
        expires_at = document.metadata.expires_at
        if expires_at is not None and expires_at < event.timestamp:
            return VerificationEvidence(
                method=self.method,
                outcome=VerificationOutcome.STALE,
                binding_scope=self.binding_scope,
                authority=self.provider,
                subject=self.profile.subject or self.provider,
                explanation="cached official range source is stale",
                source_uri=document.metadata.uri,
                source_profile=self.profile.format_profile,
                retrieved_at=document.metadata.retrieved_at,
                expires_at=expires_at,
                source_sha256=document.metadata.sha256,
                details={"cached": True},
            )
        return OfficialRangeVerifier().verify(
            context=context,
            claim=claim,
            source_profile=self.profile,
            document=document,
        )


@dataclass(slots=True)
class _FcrdnsAdapter:
    provider: str
    profile: FcrdnsProfile
    name: str = "fcrdns"
    method: VerificationMethod = VerificationMethod.FCRDNS

    @property
    def binding_scope(self) -> BindingScope:
        return self.profile.binding_scope

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        return FcrdnsVerifier().verify(context=context, claim=claim, profile=self.profile)


@dataclass(slots=True)
class _CryptoAdapter:
    provider: str
    profile: CryptoSourceProfile
    cache: SourceCache
    trust: SourceTrustPolicy
    name: str = "web-bot-auth"
    method: VerificationMethod = VerificationMethod.WEB_BOT_AUTH

    @property
    def binding_scope(self) -> BindingScope:
        return self.profile.binding_scope

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationEvidence:
        document = self.cache.get(self.profile.directory_uri)
        if document is None:
            return _neutral_missing(
                method=self.method,
                scope=self.binding_scope,
                authority=self.provider,
                subject=self.profile.subject,
                source_uri=self.profile.directory_uri,
                explanation="Web Bot Auth key directory is not present in the local cache",
            )
        try:
            directory = parse_key_directory(document.content)
        except DirectoryFormatError as exc:
            return VerificationEvidence(
                method=self.method,
                outcome=VerificationOutcome.ERROR,
                binding_scope=self.binding_scope,
                authority=self.provider,
                subject=self.profile.subject,
                explanation=f"cached key directory could not be validated: {exc}",
                source_uri=document.metadata.uri,
                source_profile="directory-05",
                retrieved_at=document.metadata.retrieved_at,
                expires_at=document.metadata.expires_at,
                source_sha256=document.metadata.sha256,
                details={"cached": True},
            )
        raw = WebBotAuthVerifier(
            directory=directory,
            directory_uri=self.profile.directory_uri,
            signature_agent_uri=self.profile.signature_agent_uri,
            binding_scope=self.profile.binding_scope,
            subject=self.profile.subject,
            trust_policy=self.trust,
        ).verify(context=context, claim=claim, now=event.timestamp)
        return replace(raw, authority=self.provider)


class ProviderAwareVerificationManager(VerificationManager):
    """Run claim-relevant network checks and cross-provider crypto checks."""

    def __init__(
        self,
        cache: SourceCache,
        *,
        mode: VerificationMode = VerificationMode.OFFLINE,
        policy: VerificationPolicy | None = None,
    ) -> None:
        self._cache = cache
        self._mode = mode
        self._effective_policy = policy or VerificationPolicy(mode=mode)
        self._profiles = load_provider_profiles()
        self._trust = SourceTrustPolicy.default()
        super().__init__((), policy=self._effective_policy)

    def verify(
        self,
        *,
        event: RequestEvent,
        context: VerificationContext,
        claim: IdentityClaim,
    ) -> VerificationResolution:
        verifiers: list[IdentityVerifier] = []
        profile = self._profiles.get(claim.provider.casefold())
        if profile is not None:
            verifiers.extend(self._network_verifiers(profile, claim))
        if context.signature is not None and context.signature_input is not None:
            verifiers.extend(self._crypto_verifiers())
        manager = VerificationManager(tuple(verifiers), policy=self._effective_policy)
        return manager.verify(event=event, context=context, claim=claim)

    def _network_verifiers(
        self,
        profile: ProviderProfile,
        claim: IdentityClaim,
    ) -> list[IdentityVerifier]:
        result: list[IdentityVerifier] = [
            _RangeAdapter(profile.provider, source, self._cache)
            for source in profile.range_sources
            if source.subject is None or source.subject == claim.agent
        ]
        if self._mode is not VerificationMode.OFFLINE and profile.fcrdns is not None:
            result.append(_FcrdnsAdapter(profile.provider, profile.fcrdns))
        return result

    def _crypto_verifiers(self) -> list[IdentityVerifier]:
        result: list[IdentityVerifier] = []
        for profile in self._profiles.values():
            if profile.crypto is None:
                continue
            result.extend(
                _CryptoAdapter(profile.provider, source, self._cache, self._trust)
                for source in profile.crypto.signature_agents
            )
        return result


def _neutral_missing(
    *,
    method: VerificationMethod,
    scope: BindingScope,
    authority: str,
    subject: str | None,
    source_uri: str,
    explanation: str,
) -> VerificationEvidence:
    return VerificationEvidence(
        method=method,
        outcome=VerificationOutcome.UNAVAILABLE,
        binding_scope=scope,
        authority=authority,
        subject=subject,
        explanation=explanation,
        source_uri=source_uri,
        source_profile="runtime-cache",
        retrieved_at=None,
        expires_at=None,
        source_sha256=None,
        details={"cached": False},
    )
