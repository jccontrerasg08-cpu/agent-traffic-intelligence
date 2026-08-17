"""Trust policy for remote identity-source discovery."""

from __future__ import annotations

import string
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from agent_traffic_intelligence.identity.profiles import load_provider_profiles

_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_HEX = frozenset(string.hexdigits)


def _normalize_percent_encoding(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "%":
            output.append(char)
            index += 1
            continue
        pair = value[index + 1 : index + 3]
        if index + 2 >= len(value) or any(item not in _HEX for item in pair):
            raise ValueError("source URI has invalid percent encoding")
        decoded = chr(int(pair, 16))
        output.append(decoded if decoded in _UNRESERVED else f"%{pair.upper()}")
        index += 3
    return "".join(output)


def _remove_dot_segments(path: str) -> str:
    absolute = path.startswith("/")
    trailing = path.endswith("/")
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    result = "/".join(segments)
    if absolute:
        result = f"/{result}"
    if not result:
        return "/" if absolute else ""
    return f"{result}/" if trailing and result != "/" else result


def _format_host(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def canonicalize_source_uri(uri: str) -> str:
    """Canonicalize an HTTPS URI without resolving or fetching it."""

    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("source URI is malformed") from exc
    if parsed.scheme.casefold() != "https":
        raise ValueError("source URI must use https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source URI must not contain credentials")
    if not parsed.hostname:
        raise ValueError("source URI must contain a hostname")
    hostname = parsed.hostname.casefold().rstrip(".")
    if not hostname:
        raise ValueError("source URI must contain a hostname")
    netloc = _format_host(hostname)
    if port not in (None, 443):
        netloc = f"{netloc}:{port}"
    path = _remove_dot_segments(_normalize_percent_encoding(parsed.path or "/"))
    query = _normalize_percent_encoding(parsed.query)
    return urlunsplit(("https", netloc, path, query, ""))


@dataclass(frozen=True, slots=True)
class SourceTrustPolicy:
    """Registry-only allowlist for source and Signature-Agent discovery."""

    allowed_uris: frozenset[str]

    @classmethod
    def default(cls) -> SourceTrustPolicy:
        uris: set[str] = set()
        for profile in load_provider_profiles().values():
            for range_source in profile.range_sources:
                uris.add(canonicalize_source_uri(range_source.uri))
            if profile.crypto is not None:
                for crypto_source in profile.crypto.signature_agents:
                    uris.add(canonicalize_source_uri(crypto_source.directory_uri))
        return cls(frozenset(uris))

    def allows(self, uri: str) -> bool:
        try:
            canonical = canonicalize_source_uri(uri)
        except ValueError:
            return False
        return canonical in self.allowed_uris
