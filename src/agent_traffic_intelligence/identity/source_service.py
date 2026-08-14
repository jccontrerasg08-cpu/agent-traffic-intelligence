"""Explicit status, validation, and refresh operations for external identity sources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from agent_traffic_intelligence.identity.crypto.directory import DirectoryFormatError, parse_key_directory
from agent_traffic_intelligence.identity.network.formats.jafar import parse_jafar
from agent_traffic_intelligence.identity.network.formats.prefixes_v1 import parse_prefixes_v1
from agent_traffic_intelligence.identity.network.ranges import RangeFormatError
from agent_traffic_intelligence.identity.profiles import load_provider_profiles
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult, SafeFetcher
from agent_traffic_intelligence.identity.sources.models import SourceDocument, SourceType


@dataclass(frozen=True, slots=True)
class SourceSpec:
    provider: str
    uri: str
    source_type: SourceType
    parser_profile: str
    binding_scope: object


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
            if spec.source_type is SourceType.IP_RANGES:
                if spec.parser_profile == "jafar-00":
                    parse_jafar(document.content)
                else:
                    parse_prefixes_v1(document.content)
            elif spec.source_type is SourceType.KEY_DIRECTORY:
                parse_key_directory(document.content)
        except (RangeFormatError, DirectoryFormatError) as exc:
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
            not_modified += 1
            continue
        assert result.body is not None
        document = _document_from_result(spec, result)
        cache.put(document)
        refreshed += 1
    return refreshed, not_modified


def _document_from_result(spec: SourceSpec, result: FetchResult) -> SourceDocument:
    return SourceDocument.from_bytes(
        uri=result.uri,
        source_type=spec.source_type,
        provider=spec.provider,
        binding_scope=spec.binding_scope,
        retrieved_at=datetime.now(UTC),
        content=result.body or b"",
        content_type=result.content_type,
        parser_profile=spec.parser_profile,
        etag=result.etag,
        last_modified=result.last_modified,
        cache_control=result.cache_control,
    )
