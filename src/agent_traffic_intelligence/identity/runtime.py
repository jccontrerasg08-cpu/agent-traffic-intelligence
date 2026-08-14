"""Runtime composition of provider profiles, cached sources, and verification adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.crypto.directory import DirectoryFormatError, parse_key_directory
from agent_traffic_intelligence.identity.crypto.web_bot_auth import WebBotAuthVerifier
from agent_traffic_intelligence.identity.manager import IdentityVerifier, VerificationManager
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.network.fcrdns import FcrdnsVerifier
from agent_traffic_intelligence.identity.network.verifier import OfficialRangeVerifier
from agent_traffic_intelligence.identity.policy import VerificationMode, VerificationPolicy
from agent_traffic_intelligence.identity.profiles import (
    CryptoSourceProfile,
    FcrdnsProfile,
    RangeSourceProfile,
    load_provider_profiles,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.trust import SourceTrustPolicy
from agent_traffic_intelligence.models import IdentityClaim, RequestEvent


@dataclass(slots=True)
class CachedRangeIdentityVerifier:
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
            return _unavailable(
                self.method,
                self.binding_scope,
                claim,
                self.profile.subject,
                self.profile.uri,
                "official range source is not present in the local cache",
            )
        expires_at = document.metadata.expires_at
        if expires_at is not None and expires_at < event.timestamp:
            return VerificationEvidence(
                method=self.method,
                outcome=VerificationOutcome.STALE,
                binding_scope=self.binding_scope,
                authority=claim.provider,
                subject=self.profile.subject or claim.provider,
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
class ConfiguredFcrdnsIdentityVerifier:
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
class CachedWebBotAuthIdentityVerifier:
    profile: CryptoSourceProfile
    cache: SourceCache
    trust_policy: SourceTrustPolicy
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
            return _unavailable(
                self.method,
                self.binding_scope,
                claim,
                self.profile.subject,
                self.profile.directory_uri,
                "Web Bot Auth key directory is not present in the local cache",
            )
        try:
            directory = parse_key_directory(document.content)
        except DirectoryFormatError as exc:
            return VerificationEvidence(
                method=self.method,
                outcome=VerificationOutcome.ERROR,
                binding_scope=self.binding_scope,
                authority=claim.provider,
                subject=self.profile.subject or claim.agent,
                explanation=f"cached key directory could not be validated: {exc}",
                source_uri=document.metadata.uri,
                source_profile="directory-05",
                retrieved_at=document.metadata.retrieved_at,
                expires_at=document.metadata.expires_at,
                source_sha256=document.metadata.sha256,
                details={"cached": True},
            )
        verifier = WebBotAuthVerifier(
            directory=directory,
            directory_uri=self.profile.directory_uri,
            signature_agent_uri=self.profile.signature_agent_uri,
            binding_scope=self.profile.binding_scope,
            subject=self.profile.subject,
            trust_policy=self.trust_policy,
        )
        return verifier.verify(context=context, claim=claim, now=event.timestamp)


def default_source_cache_dir() -> Path:
    return Path.home() / ".cache" / "agent-traffic-intelligence" / "identity-sources"


def build_verification_manager(
    *,
    mode: VerificationMode,
    cache: SourceCache,
    policy: VerificationPolicy | None = None,
) -> VerificationManager:
    """Build capability-scoped verifiers without performing network I/O."""

    trust = SourceTrustPolicy.default()
    verifiers: list[IdentityVerifier] = []
    for provider in load_provider_profiles().values():
        for source in provider.range_sources:
            verifiers.append(CachedRangeIdentityVerifier(source, cache))
        if mode is not VerificationMode.OFFLINE and provider.fcrdns is not None:
            verifiers.append(ConfiguredFcrdnsIdentityVerifier(provider.fcrdns))
        if provider.crypto is not None:
            for source in provider.crypto.signature_agents:
                verifiers.append(CachedWebBotAuthIdentityVerifier(source, cache, trust))
    effective = policy or VerificationPolicy(mode=mode)
    return VerificationManager(tuple(verifiers), policy=effective)


def _unavailable(
    method: VerificationMethod,
    scope: BindingScope,
    claim: IdentityClaim,
    subject: str | None,
    source_uri: str,
    explanation: str,
) -> VerificationEvidence:
    return VerificationEvidence(
        method=method,
        outcome=VerificationOutcome.UNAVAILABLE,
        binding_scope=scope,
        authority=claim.provider,
        subject=subject or (claim.agent if scope is BindingScope.AGENT else claim.provider),
        explanation=explanation,
        source_uri=source_uri,
        source_profile="runtime-cache",
        retrieved_at=None,
        expires_at=None,
        source_sha256=None,
        details={"cached": False, "checked_at": datetime.now(UTC).isoformat()},
    )
