from __future__ import annotations

from dataclasses import dataclass, field
from urllib.request import Request

import pytest

from agent_traffic_intelligence.identity.standards_health import (
    DatatrackerNoRedirectHandler,
    StandardsHealthOperationalError,
    UrllibDatatrackerTransport,
    default_draft_pins,
    document_api_url,
)


@dataclass
class FakeResponse:
    status: int
    final_url: str
    body: bytes
    content_type: str = "application/json"
    read_sizes: list[int] = field(default_factory=list)

    @property
    def headers(self) -> dict[str, str]:
        return {"Content-Type": self.content_type}

    def geturl(self) -> str:
        return self.final_url

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


@dataclass
class FakeOpener:
    response: FakeResponse | None = None
    error: BaseException | None = None

    def __post_init__(self) -> None:
        self.calls: list[tuple[Request, float]] = []

    def open(self, request: Request, *, timeout: float):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


def test_urllib_transport_sends_minimal_json_request_and_reads_max_plus_one() -> None:
    url = document_api_url(default_draft_pins()[0])
    response = FakeResponse(status=200, final_url=url, body=b"{}")
    opener = FakeOpener(response=response)
    transport = UrllibDatatrackerTransport(opener=opener)

    result = transport.get(url, timeout_seconds=2.5, max_body_bytes=16)

    assert result.status == 200
    assert result.final_url == url
    assert result.content_type == "application/json"
    assert result.body == b"{}"
    assert response.read_sizes == [17]
    request, timeout = opener.calls[0]
    headers = {key.casefold(): value for key, value in request.header_items()}
    assert timeout == 2.5
    assert headers["accept"] == "application/json"
    assert headers["user-agent"].startswith("agent-traffic-intelligence/")
    assert "authorization" not in headers
    assert "cookie" not in headers


def test_no_redirect_handler_refuses_redirect_request() -> None:
    handler = DatatrackerNoRedirectHandler()
    request = Request("https://datatracker.ietf.org/api/v1/doc/document/example/")

    assert (
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://datatracker.ietf.org/api/v1/doc/document/other/",
        )
        is None
    )


def test_urllib_transport_redacts_operational_exception_details() -> None:
    url = document_api_url(default_draft_pins()[0])
    transport = UrllibDatatrackerTransport(
        opener=FakeOpener(error=OSError("secret-socket-marker"))
    )

    with pytest.raises(StandardsHealthOperationalError) as captured:
        transport.get(url, timeout_seconds=1.0, max_body_bytes=128)

    assert "secret-socket-marker" not in str(captured.value)
    assert "OSError" in str(captured.value)
