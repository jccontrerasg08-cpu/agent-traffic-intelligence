from __future__ import annotations

from dataclasses import dataclass

import pytest

pytest.importorskip("http_message_signatures")

from http_sf.compat import Item

from agent_traffic_intelligence.identity.crypto.rfc9421_response import (
    ResponseMessage,
    ResponseRequest,
    response_component_resolver_class,
)


@dataclass
class Headers:
    values: dict[str, str]


def item(raw: str) -> Item:
    node = Item()
    node.parse(raw.encode("utf-8"))
    return node


def test_response_resolver_uses_original_request_authority_for_req() -> None:
    request = ResponseRequest(
        method="GET",
        url="https://agent.example/.well-known/http-message-signatures-directory",
        headers={},
    )
    response = ResponseMessage(
        status_code=200,
        url="https://cdn.example/cached-directory",
        headers={"Content-Digest": "sha-256=:ZGlnZXN0:"},
        request=request,
    )
    resolver = response_component_resolver_class()(response)

    assert resolver.resolve(item('"@authority";req')) == "agent.example"
    assert resolver.resolve(item('"@authority"')) == "cdn.example"
    assert resolver.resolve(item('"@status"')) == "200"
    assert resolver.resolve(item('"content-digest"')) == "sha-256=:ZGlnZXN0:"
