from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_traffic_intelligence.identity.sources.fetcher import (
    FetchProtocolError,
    FetchSecurityError,
    SafeFetcher,
    TransportResponse,
)


class FakeResolver:
    def __init__(self, mapping: dict[str, tuple[str, ...]]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        return self.mapping.get(hostname, ())


@dataclass
class RequestCall:
    uri: str
    headers: dict[str, str]
    allowed_addresses: tuple[str, ...]


class FakeTransport:
    def __init__(self, responses: list[TransportResponse]) -> None:
        self.responses = responses
        self.calls: list[RequestCall] = []

    def request(
        self,
        uri: str,
        *,
        headers: dict[str, str],
        allowed_addresses: tuple[str, ...],
        max_bytes: int,
    ) -> TransportResponse:
        self.calls.append(RequestCall(uri, dict(headers), allowed_addresses))
        if not self.responses:
            raise AssertionError("unexpected transport call")
        return self.responses.pop(0)


def response(
    status: int = 200,
    *,
    body: bytes = b"{}",
    content_type: str = "application/json",
    **headers: str,
) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers={"Content-Type": content_type, **headers},
        body=body,
    )


def test_rejects_non_https_and_embedded_credentials_before_network() -> None:
    resolver = FakeResolver({})
    transport = FakeTransport([])
    fetcher = SafeFetcher(resolver=resolver, transport=transport)
    with pytest.raises(FetchSecurityError, match="https"):
        fetcher.fetch("http://example.com/data.json")
    with pytest.raises(FetchSecurityError, match="credentials"):
        fetcher.fetch("https://user:pass@example.com/data.json")
    assert resolver.calls == []
    assert transport.calls == []


@pytest.mark.parametrize(
    "blocked",
    ["127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1", "ff02::1"],
)
def test_rejects_non_public_destination_addresses(blocked: str) -> None:
    fetcher = SafeFetcher(
        resolver=FakeResolver({"example.com": (blocked,)}),
        transport=FakeTransport([]),
    )
    with pytest.raises(FetchSecurityError, match="public"):
        fetcher.fetch("https://example.com/data.json")


def test_redirect_is_re_resolved_and_private_target_is_rejected() -> None:
    resolver = FakeResolver({"public.example": ("93.184.216.34",), "internal.example": ("10.0.0.5",)})
    transport = FakeTransport([response(302, Location="https://internal.example/secrets")])
    fetcher = SafeFetcher(resolver=resolver, transport=transport)
    with pytest.raises(FetchSecurityError, match="public"):
        fetcher.fetch("https://public.example/start")
    assert resolver.calls == ["public.example", "internal.example"]
    assert len(transport.calls) == 1


def test_rejects_more_than_three_redirects() -> None:
    resolver = FakeResolver({"example.com": ("93.184.216.34",)})
    transport = FakeTransport([
        response(302, Location="/1"),
        response(302, Location="/2"),
        response(302, Location="/3"),
        response(302, Location="/4"),
    ])
    with pytest.raises(FetchProtocolError, match="redirect"):
        SafeFetcher(resolver=resolver, transport=transport).fetch("https://example.com/start")


def test_rejects_oversized_body_and_wrong_media_type() -> None:
    resolver = FakeResolver({"example.com": ("93.184.216.34",)})
    oversized = FakeTransport([response(body=b"x" * (2 * 1024 * 1024 + 1))])
    with pytest.raises(FetchProtocolError, match="2 MiB"):
        SafeFetcher(resolver=resolver, transport=oversized).fetch("https://example.com/data.json")
    wrong_type = FakeTransport([response(content_type="text/html")])
    with pytest.raises(FetchProtocolError, match="media type"):
        SafeFetcher(resolver=resolver, transport=wrong_type).fetch("https://example.com/data.json")


def test_conditional_headers_and_304_are_preserved() -> None:
    resolver = FakeResolver({"example.com": ("93.184.216.34",)})
    transport = FakeTransport([
        TransportResponse(
            status=304,
            headers={"ETag": '"v2"', "Last-Modified": "Thu, 13 Aug 2026 12:00:00 GMT"},
            body=b"",
        )
    ])
    result = SafeFetcher(resolver=resolver, transport=transport).fetch(
        "https://example.com/data.json",
        etag='"v1"',
        last_modified="Wed, 12 Aug 2026 12:00:00 GMT",
    )
    assert transport.calls[0].headers["If-None-Match"] == '"v1"'
    assert result.not_modified is True
    assert result.body is None
    assert result.etag == '"v2"'


def test_success_passes_only_validated_addresses_to_transport() -> None:
    resolver = FakeResolver({"example.com": ("93.184.216.34", "8.8.8.8")})
    transport = FakeTransport([response(ETag='"v1"')])
    result = SafeFetcher(resolver=resolver, transport=transport).fetch("https://example.com/data.json")
    assert transport.calls[0].allowed_addresses == ("8.8.8.8", "93.184.216.34")
    assert result.body == b"{}"
