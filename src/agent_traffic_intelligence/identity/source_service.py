"""Explicit status, validation, and refresh operations for external identity sources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from agent_traffic_intelligence.identity.crypto.directory import parse_key_directory
from agent_traffic_intelligence.identity.crypto.directory_response import (
    DirectoryResponseVerifier,
)
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.network.formats.jafar import parse_jafar
from agent_traffic_intelligence.identity.network.formats.prefixes_v1 import (
    parse_prefixes_v1,
)
from agent_traffic_intelligence.identity.profiles import load_provider_profiles
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult, SafeFetcher
from agent_traffic_intelligence.identity.sources.models import (
    KeyAuthorityBinding,
    SourceDocument,
    SourceType,
    ValidationStatus,
)


@dataclass(frozen=True, slots=True)
class SourceSpec:
    provider: str
    uri: str
    source_type: SourceType
    parser_profile: str
    binding_scope: BindingScope


def configured_sources() -> tuple[SourceSpec, ...]:
    specs: list[SourceSpec] = []
    for provider in load_provider_profiles().values():
        specs.extend(
            SourceSpec(
                provider=provider.provider,
                uri=source.uri,
                source_type=SourceType.IP_RANGES,
                parser_profile=source.format_profile,
                binding_scope=source.binding_scope,
            )
            for source in provider.range_sources
        )
        if provider.crypto is not None:
            specs.extend(
                SourceSpec(
                    provider=provider.provider,
                    uri=source.directory_uri,
                    source_type=SourceType.KEY_DIRECTORY,
                    parser_profile="directory-05",
                    binding_scope=source.binding_scope,
                )
                for source in provider.crypto.signature_agents
            )
    return tuple(specs)


def source_status(cache: SourceCache) -> list[dict[str, str | bool | None]]:
    rows: list[dict[str, str | bool | None]] = []
    for spec in configured_sources():
        document = cache.get(spec.uri)
        rows.append(
            {
                "provider": spec.provider,
                "uri": spec.uri,
                "type": spec.source_type.value,
                "cached": document is not None,
                "sha256": document.metadata.sha256 if document else None,
                "retrieved_at": (
                    document.metadata.retrieved_at.isoformat() if document else None
                ),
                "source_created_at": (
                    document.metadata.source_created_at.isoformat()
                    if document and document.metadata.source_created_at
                    else None
                ),
                "expires_at": (
                    document.metadata.expires_at.isoformat()
                    if document and document.metadata.expires_at
                    else None
                ),
                "validation_status": (
                    document.metadata.validation_status.value if document else None
                ),
            }
        )
    return rows


def validate_sources(cache: SourceCache) -> list[str]:
    errors: list[str] = []
    for spec in configured_sources():
        document = cache.get(spec.uri)
        if document is None:
            continue
        try:
            _source_created_at(spec, document.content)
        except ValueError as exc:
            errors.append(f"{spec.provider} {spec.uri}: {exc}")
    return errors


def refresh_sources(
    cache: SourceCache,
    *,
    provider: str | None = None,
    fetcher: SafeFetcher | None = None,
) -> tuple[int, int]:
    client = fetcher or SafeFetcher()
    refreshed = 0
    not_modified = 0
    for spec in configured_sources():
        if provider is not None and spec.provider.casefold() != provider.casefold():
            continue
        previous = cache.get(spec.uri)
        result = client.fetch(
            spec.uri,
            etag=previous.metadata.etag if previous else None,
            last_modified=previous.metadata.last_modified if previous else None,
        )
        if result.not_modified:
            if previous is None:
                raise ValueError("received 304 Not Modified without a cached source")
            cache.put(_revalidated_document(spec, previous, result))
            not_modified += 1
            continue
        cache.put(_document_from_result(spec, result))
        refreshed += 1
    return refreshed, not_modified


def _source_created_at(spec: SourceSpec, content: bytes) -> datetime | None:
    if spec.source_type is SourceType.IP_RANGES:
        if spec.parser_profile == "jafar-00":
            return parse_jafar(content).creation_time
        if spec.parser_profile == "prefixes-v1":
            return parse_prefixes_v1(content).creation_time
        raise ValueError(f"unsupported IP range parser profile: {spec.parser_profile}")
    if spec.source_type is SourceType.KEY_DIRECTORY:
        parse_key_directory(content)
        return None
    raise ValueError(f"unsupported source type: {spec.source_type.value}")


def _max_age_seconds(cache_control: str | None) -> int | None:
    if cache_control is None:
        return None
    for directive in cache_control.split(","):
        name, separator, raw_value = directive.strip().partition("=")
        if name.casefold() != "max-age" or not separator:
            continue
        try:
            value = int(raw_value.strip().strip('"'))
        except ValueError:
            return None
        return value if value >= 0 else None
    return None


def _expires_at(retrieved_at: datetime, cache_control: str | None) -> datetime | None:
    max_age = _max_age_seconds(cache_control)
    if max_age is None:
        return None
    return retrieved_at + timedelta(seconds=max_age)


def _key_authority_bindings(
    spec: SourceSpec,
    result: FetchResult,
    *,
    body: bytes,
    retrieved_at: datetime,
) -> tuple[KeyAuthorityBinding, ...]:
    if spec.source_type is not SourceType.KEY_DIRECTORY:
        return ()
    directory = parse_key_directory(body)
    return DirectoryResponseVerifier().verify(
        directory=directory,
        body=body,
        request_uri=spec.uri,
        response_uri=result.uri,
        status_code=result.status,
        signature=result.signature,
        signature_input=result.signature_input,
        content_digest=result.content_digest,
        now=retrieved_at,
    ).bindings


def _document_from_result(spec: SourceSpec, result: FetchResult) -> SourceDocument:
    if result.body is None:
        raise ValueError("fresh identity source response must contain a body")
    retrieved_at = datetime.now(UTC)
    source_created_at = _source_created_at(spec, result.body)
    key_authority_bindings = _key_authority_bindings(
        spec,
        result,
        body=result.body,
        retrieved_at=retrieved_at,
    )
    return SourceDocument.from_bytes(
        uri=spec.uri,
        source_type=spec.source_type,
        provider=spec.provider,
        binding_scope=spec.binding_scope,
        retrieved_at=retrieved_at,
        source_created_at=source_created_at,
        expires_at=_expires_at(retrieved_at, result.cache_control),
        content=result.body,
        content_type=result.content_type,
        parser_profile=spec.parser_profile,
        etag=result.etag,
        last_modified=result.last_modified,
        validation_status=ValidationStatus.VALID,
        key_authority_bindings=key_authority_bindings,
    )


def _revalidated_document(
    spec: SourceSpec,
    previous: SourceDocument,
    result: FetchResult,
) -> SourceDocument:
    retrieved_at = datetime.now(UTC)
    expires_at = _expires_at(retrieved_at, result.cache_control)
    return SourceDocument.from_bytes(
        uri=spec.uri,
        source_type=spec.source_type,
        provider=spec.provider,
        binding_scope=spec.binding_scope,
        retrieved_at=retrieved_at,
        source_created_at=previous.metadata.source_created_at,
        expires_at=expires_at if expires_at is not None else previous.metadata.expires_at,
        content=previous.content,
        content_type=previous.metadata.content_type,
        parser_profile=spec.parser_profile,
        etag=result.etag or previous.metadata.etag,
        last_modified=result.last_modified or previous.metadata.last_modified,
        validation_status=ValidationStatus.VALID,
    )
