"""Trust policy for remote identity-source discovery."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from agent_traffic_intelligence.identity.profiles import load_provider_profiles


def canonicalize_source_uri(uri: str) -> str:
    """Canonicalize an HTTPS URI without resolving or fetching it."""

    parsed = urlsplit(uri)
    if parsed.scheme.casefold() != "https":
        raise ValueError("source URI must use https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source URI must not contain credentials")
    if not parsed.hostname:
        raise ValueError("source URI must contain a hostname")
    hostname = parsed.hostname.casefold().rstrip(".")
    port = parsed.port
    netloc = hostname if port in (None, 443) else f"{hostname}:{port}"
    path = parsed.path or "/"
    return urlunsplit(("https", netloc, path, parsed.query, ""))


@dataclass(frozen=True, slots=True)
class SourceTrustPolicy:
    """Registry-only allowlist for source and Signature-Agent discovery."""

    allowed_uris: frozenset[str]

    @classmethod
    def default(cls) -> SourceTrustPolicy:
        uris: set[str] = set()
        for profile in load_provider_profiles().values():
            for source in profile.range_sources:
                uris.add(canonicalize_source_uri(source.uri))
            if profile.crypto is not None:
                for uri in profile.crypto.signature_agents:
                    uris.add(canonicalize_source_uri(uri))
        return cls(frozenset(uris))

    def allows(self, uri: str) -> bool:
        try:
            canonical = canonicalize_source_uri(uri)
        except ValueError:
            return False
        return canonical in self.allowed_uris
