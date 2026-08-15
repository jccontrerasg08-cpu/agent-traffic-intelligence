from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

hms = pytest.importorskip("http_message_signatures")
algorithms = pytest.importorskip("http_message_signatures.algorithms")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

from agent_traffic_intelligence.identity.crypto.rfc9421_response import (
    ResponseMessage,
    ResponseRequest,
    Rfc9421ResponseVerifier,
    response_component_resolver_class,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    structured_fields_module,
)
from agent_traffic_intelligence.identity.models import VerificationOutcome


class KeyResolver:
    def __init__(self) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != "test-key":
            raise KeyError(key_id)
        return self.private.public_key()


@dataclass
class MutableRequest:
    method: str
    url: str
    headers: dict[str, str]


@dataclass
class MutableResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    request: MutableRequest


def item(raw: str):
    node = structured_fields_module().Item()
    node.parse(raw.encode("utf-8"))
    return node


def digest_field(body: bytes) -> str:
    sf = structured_fields_module()
    return str(sf.Dictionary({"sha-256": hashlib.sha256(body).digest()}))


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


def test_verifies_real_ed25519_directory_response_signature() -> None:
    resolver = KeyResolver()
    body = b'{"keys":[]}'
    request = MutableRequest(
        method="GET",
        url="https://agent.example/.well-known/http-message-signatures-directory",
        headers={},
    )
    response = MutableResponse(
        status_code=200,
        url="https://cdn.example/cached-directory",
        headers={"Content-Digest": digest_field(body)},
        request=request,
    )
    now = datetime.now()
    signer = hms.HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=resolver,
        component_resolver_class=response_component_resolver_class(),
    )
    signer.sign(
        response,
        key_id="test-key",
        covered_component_ids=('"@authority";req', "content-digest"),
        created=now,
        expires=now + timedelta(minutes=5),
        label="bind1",
        tag="http-message-signatures-directory",
    )
    message = ResponseMessage(
        status_code=response.status_code,
        url=response.url,
        headers=dict(response.headers),
        request=ResponseRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
        ),
    )

    result = Rfc9421ResponseVerifier(resolver).verify(
        message,
        algorithm_id="ed25519",
        expect_tag="http-message-signatures-directory",
        required_components=frozenset({"@authority", "content-digest"}),
    )

    assert result.outcome is VerificationOutcome.PASS
    assert result.algorithm_id == "ed25519"
    assert result.parameters["keyid"] == "test-key"
    assert "@authority" in result.covered_component_names
    assert "content-digest" in result.covered_component_names
