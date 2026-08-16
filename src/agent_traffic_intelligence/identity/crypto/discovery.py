"""Pure planning for current Signature-Agent key-discovery targets."""

from __future__ import annotations

import string
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
    SignatureAgentReference,
)

_WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory"
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_HEX = frozenset(string.hexdigits)


class SignatureAgentResolutionError(ValueError):
    """Raised when a Signature-Agent reference cannot be resolved safely."""


@dataclass(frozen=True, slots=True)
class SignatureAgentResolutionTarget:
    """Network target and stable protocol identifier for one discovery member."""

    fetch_uri: str
    identifier_uri: str
    discovery_type: SignatureAgentDiscoveryType


def _normalize_percent_encoding(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "%":
            output.append(char)
            index += 1
            continue
        if index + 2 >= len(value):
            raise SignatureAgentResolutionError("Signature-Agent URI has invalid percent encoding")
        pair = value[index + 1 : index + 3]
        if any(item not in _HEX for item in pair):
            raise SignatureAgentResolutionError("Signature-Agent URI has invalid percent encoding")
        decoded = chr(int(pair, 16))
        if decoded in _UNRESERVED:
            output.append(decoded)
        else:
            output.append(f"%{pair.upper()}")
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
        result = "/" if absolute else ""
    elif trailing and result != "/":
        result += "/"
    return result


def _format_host(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def _canonical_https(uri: str) -> tuple[str, str, str, str]:
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise SignatureAgentResolutionError("Signature-Agent URI is malformed") from exc
    if parsed.scheme.casefold() != "https":
        raise SignatureAgentResolutionError("Signature-Agent discovery requires https")
    if parsed.username is not None or parsed.password is not None:
        raise SignatureAgentResolutionError("Signature-Agent URI must not contain credentials")
    if not parsed.hostname:
        raise SignatureAgentResolutionError("Signature-Agent URI must contain a hostname")

    hostname = parsed.hostname.casefold().rstrip(".")
    if not hostname:
        raise SignatureAgentResolutionError("Signature-Agent URI must contain a hostname")
    netloc = _format_host(hostname)
    if port not in (None, 443):
        netloc = f"{netloc}:{port}"

    path = _remove_dot_segments(_normalize_percent_encoding(parsed.path or "/"))
    query = _normalize_percent_encoding(parsed.query)
    return netloc, path, query, parsed.fragment


def plan_signature_agent_resolution(
    reference: SignatureAgentReference,
) -> SignatureAgentResolutionTarget:
    """Validate a current-protocol member and derive fetch + identifier URIs."""

    discovery_type = reference.discovery_type
    if discovery_type is None:
        raise SignatureAgentResolutionError("Signature-Agent discovery type is unavailable")

    netloc, path, query, fragment = _canonical_https(reference.uri)
    if discovery_type is SignatureAgentDiscoveryType.DIRECTORY:
        if path != "/" or query or fragment:
            raise SignatureAgentResolutionError(
                "directory discovery member must be an HTTPS origin"
            )
        directory_uri = urlunsplit(("https", netloc, _WELL_KNOWN_DIRECTORY, "", ""))
        return SignatureAgentResolutionTarget(
            fetch_uri=directory_uri,
            identifier_uri=directory_uri,
            discovery_type=discovery_type,
        )

    if discovery_type not in (
        SignatureAgentDiscoveryType.JWKS_URI,
        SignatureAgentDiscoveryType.CIMD,
    ):
        raise SignatureAgentResolutionError("unsupported Signature-Agent discovery type")

    fetch_uri = urlunsplit(("https", netloc, path, query, ""))
    identifier_uri = urlunsplit(("https", netloc, path, "", ""))
    return SignatureAgentResolutionTarget(
        fetch_uri=fetch_uri,
        identifier_uri=identifier_uri,
        discovery_type=discovery_type,
    )
