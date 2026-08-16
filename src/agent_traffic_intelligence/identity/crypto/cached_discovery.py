"""Hermetic Signature-Agent key discovery from the local source cache."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from agent_traffic_intelligence.identity.crypto.agent_card import (
    AgentCardFormatError,
    parse_agent_card,
)
from agent_traffic_intelligence.identity.crypto.directory import (
    DirectoryFormatError,
    parse_key_directory,
)
from agent_traffic_intelligence.identity.crypto.discovery import (
    plan_signature_agent_resolution,
)
from agent_traffic_intelligence.identity.crypto.jwk_set import (
    JwkSet,
    JwkSetFormatError,
    parse_jwk_set,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
    SignatureAgentReference,
)
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceType
from agent_traffic_intelligence.identity.sources.trust import (
    SourceTrustPolicy,
    canonicalize_source_uri,
)


class CachedDiscoveryUnavailable(LookupError):
    """The requested discovery material is not locally available or trusted."""


class CachedDiscoveryStale(CachedDiscoveryUnavailable):
    """The requested cached discovery material is expired."""


class CachedDiscoveryError(ValueError):
    """Cached discovery material violates the expected protocol contract."""


@dataclass(frozen=True, slots=True)
class ResolvedSignatureAgentMaterial:
    """Normalized key material and provenance documents for one identifier."""

    identifier_uri: str
    discovery_type: SignatureAgentDiscoveryType
    jwk_set: JwkSet
    documents: tuple[SourceDocument, ...]


def _require_cached_document(
    uri: str,
    *,
    expected_type: SourceType,
    cache: SourceCache,
    trust_policy: SourceTrustPolicy,
    now: datetime,
) -> SourceDocument:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("cached discovery time must be timezone-aware")
    if not trust_policy.allows(uri):
        raise CachedDiscoveryUnavailable("Signature-Agent source is not allowlisted")
    document = cache.get(uri)
    if document is None:
        raise CachedDiscoveryUnavailable("Signature-Agent source is not present in cache")
    if document.metadata.source_type is not expected_type:
        raise CachedDiscoveryError(
            f"cached Signature-Agent source must be {expected_type.value}"
        )
    expires_at = document.metadata.expires_at
    if expires_at is not None and expires_at < now:
        raise CachedDiscoveryStale("cached Signature-Agent source is stale")
    return document


def _resolve_directory(
    reference: SignatureAgentReference,
    *,
    cache: SourceCache,
    trust_policy: SourceTrustPolicy,
    now: datetime,
) -> ResolvedSignatureAgentMaterial:
    target = plan_signature_agent_resolution(reference)
    document = _require_cached_document(
        target.fetch_uri,
        expected_type=SourceType.KEY_DIRECTORY,
        cache=cache,
        trust_policy=trust_policy,
        now=now,
    )
    try:
        parse_key_directory(document.content)
        jwk_set = parse_jwk_set(document.content)
    except (DirectoryFormatError, JwkSetFormatError) as exc:
        raise CachedDiscoveryError("cached Signature-Agent directory is malformed") from exc
    return ResolvedSignatureAgentMaterial(
        identifier_uri=target.identifier_uri,
        discovery_type=SignatureAgentDiscoveryType.DIRECTORY,
        jwk_set=jwk_set,
        documents=(document,),
    )


def _resolve_jwks_uri(
    reference: SignatureAgentReference,
    *,
    cache: SourceCache,
    trust_policy: SourceTrustPolicy,
    now: datetime,
) -> ResolvedSignatureAgentMaterial:
    target = plan_signature_agent_resolution(reference)
    document = _require_cached_document(
        target.fetch_uri,
        expected_type=SourceType.JWK_SET,
        cache=cache,
        trust_policy=trust_policy,
        now=now,
    )
    try:
        jwk_set = parse_jwk_set(document.content)
    except JwkSetFormatError as exc:
        raise CachedDiscoveryError("cached Signature-Agent JWK Set is malformed") from exc
    return ResolvedSignatureAgentMaterial(
        identifier_uri=target.identifier_uri,
        discovery_type=SignatureAgentDiscoveryType.JWKS_URI,
        jwk_set=jwk_set,
        documents=(document,),
    )


def _resolve_cimd(
    reference: SignatureAgentReference,
    *,
    cache: SourceCache,
    trust_policy: SourceTrustPolicy,
    now: datetime,
) -> ResolvedSignatureAgentMaterial:
    target = plan_signature_agent_resolution(reference)
    card_document = _require_cached_document(
        target.fetch_uri,
        expected_type=SourceType.AGENT_CARD,
        cache=cache,
        trust_policy=trust_policy,
        now=now,
    )
    try:
        card = parse_agent_card(card_document.content, retrieved_from=target.fetch_uri)
    except (AgentCardFormatError, JwkSetFormatError) as exc:
        raise CachedDiscoveryError("cached Signature-Agent CIMD card is malformed") from exc

    if card.inline_jwks is not None:
        return ResolvedSignatureAgentMaterial(
            identifier_uri=target.identifier_uri,
            discovery_type=SignatureAgentDiscoveryType.CIMD,
            jwk_set=card.inline_jwks,
            documents=(card_document,),
        )

    if card.jwks_uri is None:
        raise CachedDiscoveryUnavailable("cached CIMD card does not provide key material")
    try:
        jwks_uri = canonicalize_source_uri(card.jwks_uri)
    except ValueError as exc:
        raise CachedDiscoveryError("cached CIMD jwks_uri is not acceptable HTTPS") from exc
    jwks_document = _require_cached_document(
        jwks_uri,
        expected_type=SourceType.JWK_SET,
        cache=cache,
        trust_policy=trust_policy,
        now=now,
    )
    try:
        jwk_set = parse_jwk_set(jwks_document.content)
    except JwkSetFormatError as exc:
        raise CachedDiscoveryError("cached CIMD JWK Set is malformed") from exc
    return ResolvedSignatureAgentMaterial(
        identifier_uri=target.identifier_uri,
        discovery_type=SignatureAgentDiscoveryType.CIMD,
        jwk_set=jwk_set,
        documents=(card_document, jwks_document),
    )


def resolve_cached_signature_agent(
    reference: SignatureAgentReference,
    *,
    cache: SourceCache,
    trust_policy: SourceTrustPolicy,
    now: datetime,
) -> ResolvedSignatureAgentMaterial:
    """Resolve a Signature-Agent member using cache only; never perform network I/O."""

    if reference.discovery_type is SignatureAgentDiscoveryType.DIRECTORY:
        return _resolve_directory(
            reference,
            cache=cache,
            trust_policy=trust_policy,
            now=now,
        )
    if reference.discovery_type is SignatureAgentDiscoveryType.JWKS_URI:
        return _resolve_jwks_uri(
            reference,
            cache=cache,
            trust_policy=trust_policy,
            now=now,
        )
    if reference.discovery_type is SignatureAgentDiscoveryType.CIMD:
        return _resolve_cimd(
            reference,
            cache=cache,
            trust_policy=trust_policy,
            now=now,
        )
    raise CachedDiscoveryUnavailable(
        "Signature-Agent discovery type is not available from the cache-only resolver"
    )
