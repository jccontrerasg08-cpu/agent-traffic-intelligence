"""Hardened HTTPS fetcher for explicitly approved identity sources."""

from __future__ import annotations

import http.client
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urljoin, urlsplit


_MAX_BODY_BYTES = 2 * 1024 * 1024
_MAX_REDIRECTS = 3
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class FetchSecurityError(ValueError):
    """Raised when a URI or resolved destination violates fetch policy."""


class FetchProtocolError(RuntimeError):
    """Raised for malformed or unsupported HTTP responses."""


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))
        object.__setattr__(self, "body", bytes(self.body))


@dataclass(frozen=True, slots=True)
class FetchResult:
    uri: str
    status: int
    body: bytes | None
    content_type: str | None
    etag: str | None
    last_modified: str | None
    cache_control: str | None
    redirects: int
    not_modified: bool


class AddressResolver(Protocol):
    def resolve(self, hostname: str) -> tuple[str, ...]: ...


class FetchTransport(Protocol):
    def request(
        self,
        uri: str,
        *,
        headers: dict[str, str],
        allowed_addresses: tuple[str, ...],
        max_bytes: int,
    ) -> TransportResponse: ...


class SocketAddressResolver:
    """Resolve A/AAAA records using the host resolver."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = {str(item[4][0]) for item in results}
        return tuple(sorted(addresses))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a prevalidated IP but authenticates the original host."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        pinned_address: str,
        timeout: float,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = pinned_address

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedHttpsTransport:
    """Dial only addresses already approved by SafeFetcher, with TLS hostname validation."""

    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout_seconds = timeout_seconds

    def request(
        self,
        uri: str,
        *,
        headers: dict[str, str],
        allowed_addresses: tuple[str, ...],
        max_bytes: int,
    ) -> TransportResponse:
        parsed = urlsplit(uri)
        if parsed.hostname is None:
            raise FetchSecurityError("HTTPS URI must contain a hostname")
        port = parsed.port or 443
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        last_error: OSError | ssl.SSLError | None = None
        for address in allowed_addresses:
            connection = _PinnedHTTPSConnection(
                parsed.hostname,
                port,
                pinned_address=address,
                timeout=self._timeout_seconds,
            )
            try:
                request_headers = {
                    "Accept": "application/json",
                    "Connection": "close",
                    **headers,
                }
                connection.request("GET", target, headers=request_headers)
                response = connection.getresponse()
                body = response.read(max_bytes + 1)
                response_headers = {key: value for key, value in response.getheaders()}
                return TransportResponse(
                    status=response.status,
                    headers=response_headers,
                    body=body,
                )
            except (OSError, ssl.SSLError) as exc:
                last_error = exc
            finally:
                connection.close()
        raise FetchProtocolError("all validated HTTPS destination addresses failed") from last_error


class SafeFetcher:
    """Fetch small JSON identity sources without turning discovery into an SSRF primitive."""

    def __init__(
        self,
        *,
        resolver: AddressResolver | None = None,
        transport: FetchTransport | None = None,
        max_bytes: int = _MAX_BODY_BYTES,
        max_redirects: int = _MAX_REDIRECTS,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")
        self._resolver = resolver or SocketAddressResolver()
        self._transport = transport or PinnedHttpsTransport()
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects

    def fetch(
        self,
        uri: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        headers: dict[str, str] = {}
        if etag is not None:
            headers["If-None-Match"] = etag
        if last_modified is not None:
            headers["If-Modified-Since"] = last_modified

        current = uri
        redirects = 0
        while True:
            hostname = self._validate_uri(current)
            addresses = self._resolve_public_addresses(hostname)
            response = self._transport.request(
                current,
                headers=headers,
                allowed_addresses=addresses,
                max_bytes=self._max_bytes,
            )
            if response.status in _REDIRECT_STATUSES:
                if redirects >= self._max_redirects:
                    raise FetchProtocolError("redirect limit exceeded")
                location = self._header(response.headers, "location")
                if location is None or not location.strip():
                    raise FetchProtocolError("redirect response is missing Location")
                current = urljoin(current, location)
                redirects += 1
                continue
            return self._finalize(current, response, redirects)

    def _resolve_public_addresses(self, hostname: str) -> tuple[str, ...]:
        try:
            raw_addresses = self._resolver.resolve(hostname)
        except (socket.gaierror, socket.herror, TimeoutError, OSError) as exc:
            raise FetchProtocolError("destination DNS resolution failed") from exc
        if not raw_addresses:
            raise FetchProtocolError("destination DNS resolution returned no addresses")

        normalized: set[str] = set()
        for raw in raw_addresses:
            try:
                address = ip_address(raw)
            except ValueError as exc:
                raise FetchProtocolError("resolver returned an invalid IP address") from exc
            if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            if (
                not address.is_global
                or address.is_multicast
                or address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or address.is_private
                or address.is_reserved
            ):
                raise FetchSecurityError("all resolved destination addresses must be public")
            normalized.add(str(address))
        return tuple(sorted(normalized))

    @staticmethod
    def _validate_uri(uri: str) -> str:
        parsed = urlsplit(uri)
        if parsed.scheme.casefold() != "https":
            raise FetchSecurityError("source URI must use https")
        if parsed.username is not None or parsed.password is not None:
            raise FetchSecurityError("source URI must not contain credentials")
        if parsed.hostname is None:
            raise FetchSecurityError("source URI must contain a hostname")
        if parsed.fragment:
            raise FetchSecurityError("source URI must not contain a fragment")
        return parsed.hostname.casefold().rstrip(".")

    def _finalize(
        self,
        uri: str,
        response: TransportResponse,
        redirects: int,
    ) -> FetchResult:
        etag = self._header(response.headers, "etag")
        last_modified = self._header(response.headers, "last-modified")
        cache_control = self._header(response.headers, "cache-control")
        if response.status == 304:
            return FetchResult(
                uri=uri,
                status=response.status,
                body=None,
                content_type=None,
                etag=etag,
                last_modified=last_modified,
                cache_control=cache_control,
                redirects=redirects,
                not_modified=True,
            )
        if not 200 <= response.status <= 299:
            raise FetchProtocolError(f"unexpected HTTP status: {response.status}")
        if len(response.body) > self._max_bytes:
            raise FetchProtocolError("identity source exceeded the 2 MiB response limit")

        raw_content_type = self._header(response.headers, "content-type")
        if raw_content_type is None:
            raise FetchProtocolError("identity source is missing a media type")
        content_type = raw_content_type.split(";", 1)[0].strip().casefold()
        if content_type != "application/json" and not content_type.endswith("+json"):
            raise FetchProtocolError("identity source media type must be JSON")
        return FetchResult(
            uri=uri,
            status=response.status,
            body=response.body,
            content_type=content_type,
            etag=etag,
            last_modified=last_modified,
            cache_control=cache_control,
            redirects=redirects,
            not_modified=False,
        )

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str | None:
        target = name.casefold()
        for key, value in headers.items():
            if key.casefold() == target:
                return value
        return None
