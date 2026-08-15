from __future__ import annotations

import importlib
import importlib.util
from dataclasses import dataclass

import pytest

from agent_traffic_intelligence.identity.sources.fetcher import TransportResponse

_MODULE = "agent_traffic_intelligence.identity.sources.client_card"


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
        del headers, max_bytes
        self.calls.append(RequestCall(uri, allowed_addresses))
        if not self.responses:
            raise AssertionError("unexpected transport call")
        return self.responses.pop(0)


def response(status: int, body: bytes = b"{}", **headers: str) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers={"Content-Type": "application/json", **headers},
        body=body,
    )


def load_client_card_module():
    if importlib.util.find_spec(_MODULE) is None:
        pytest.skip("client card module not implemented yet")
    return importlib.import_module(_MODULE)


def test_client_card_adapter_module_exists() -> None:
    assert importlib.util.find_spec(_MODULE) is not None


def test_client_card_fetch_accepts_only_exact_200_document() -> None:
    module = load_client_card_module()
    client_id = "https://agent.example/bot"
    transport = FakeTransport(
        [response(200, b'{"client_id":"https://agent.example/bot","client_name":"Bot"}')]
    )
    fetcher = module.ClientCardFetcher(
        resolver=FakeResolver({"agent.example": ("93.184.216.34",)}),
        transport=transport,
    )

    result = fetcher.fetch(client_id)

    assert result.status is module.ClientCardFetchStatus.SUCCESS
    assert result.card is not None
    assert result.card.client_id == client_id
    assert result.explanation == "client card fetched and validated"


def test_client_card_fetch_never_follows_redirects() -> None:
    module = load_client_card_module()
    transport = FakeTransport(
        [
            response(302, Location="https://other.example/bot"),
            response(200, b'{"client_id":"https://other.example/bot"}'),
        ]
    )
    fetcher = module.ClientCardFetcher(
        resolver=FakeResolver(
            {
                "agent.example": ("93.184.216.34",),
                "other.example": ("8.8.8.8",),
            }
        ),
        transport=transport,
    )

    result = fetcher.fetch("https://agent.example/bot")

    assert result.status is module.ClientCardFetchStatus.UNAVAILABLE
    assert len(transport.calls) == 1
    assert "redirect" in result.explanation


def test_client_card_fetch_rejects_non_200_and_identity_mismatch() -> None:
    module = load_client_card_module()
    resolver = FakeResolver({"agent.example": ("93.184.216.34",)})

    non_200 = module.ClientCardFetcher(
        resolver=resolver,
        transport=FakeTransport([response(201, b'{"client_id":"https://agent.example/bot"}')]),
    ).fetch("https://agent.example/bot")
    assert non_200.status is module.ClientCardFetchStatus.UNAVAILABLE

    mismatch = module.ClientCardFetcher(
        resolver=resolver,
        transport=FakeTransport([response(200, b'{"client_id":"https://agent.example/other"}')]),
    ).fetch("https://agent.example/bot")
    assert mismatch.status is module.ClientCardFetchStatus.INVALID
    assert "client_id" in mismatch.explanation


def test_client_card_fetch_rejects_private_destination_without_transport() -> None:
    module = load_client_card_module()
    transport = FakeTransport([])
    fetcher = module.ClientCardFetcher(
        resolver=FakeResolver({"agent.example": ("127.0.0.1",)}),
        transport=transport,
    )

    result = fetcher.fetch("https://agent.example/bot")

    assert result.status is module.ClientCardFetchStatus.INVALID
    assert transport.calls == []
    assert "source policy" in result.explanation
