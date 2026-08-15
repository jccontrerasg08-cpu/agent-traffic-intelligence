from __future__ import annotations

import base64
import hashlib
import importlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.crypto.directory import (
    jwk_thumbprint,
    parse_key_directory,
)
from agent_traffic_intelligence.identity.crypto.rfc9421_response import (
    response_component_resolver_class,
)
from agent_traffic_intelligence.identity.crypto.signature_agent import (
    structured_fields_module,
)

hms = pytest.importorskip("http_message_signatures")
algorithms = pytest.importorskip("http_message_signatures.algorithms")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"


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


class KeyResolver:
    def __init__(self, key_id: str, private_key: object) -> None:
        self.key_id = key_id
        self.private_key = private_key

    def resolve_private_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private_key

    def resolve_public_key(self, key_id: str) -> object:
        if key_id != self.key_id:
            raise KeyError(key_id)
        return self.private_key.public_key()


def digest_field(body: bytes) -> str:
    sf = structured_fields_module()
    return str(sf.Dictionary({"sha-256": hashlib.sha256(body).digest()}))


def directory_body_and_signer() -> tuple[object, bytes, KeyResolver]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw_key = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii"),
        "use": "sig",
    }
    key_id = jwk_thumbprint(raw_key)
    raw_key["kid"] = key_id
    body = json.dumps(
        {"keys": [raw_key]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return parse_key_directory(body), body, KeyResolver(key_id, private_key)


def signed_directory_response(body: bytes, resolver: KeyResolver) -> MutableResponse:
    request = MutableRequest(method="GET", url=DIRECTORY_URI, headers={})
    response = MutableResponse(
        status_code=200,
        url="https://cdn.example/directory-cache",
        headers={"Content-Digest": digest_field(body)},
        request=request,
    )
    signer = hms.HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=resolver,
        component_resolver_class=response_component_resolver_class(),
    )
    now = datetime.now()
    signer.sign(
        response,
        key_id=resolver.key_id,
        covered_component_ids=('"@authority";req', "content-digest"),
        created=now,
        expires=now + timedelta(minutes=5),
        label="directory-binding",
        tag="http-message-signatures-directory",
    )
    return response


def test_valid_signed_directory_response_binds_key_to_request_authority() -> None:
    directory, body, resolver = directory_body_and_signer()
    response = signed_directory_response(body, resolver)

    try:
        module = importlib.import_module(
            "agent_traffic_intelligence.identity.crypto.directory_response"
        )
    except ModuleNotFoundError:
        pytest.fail("DirectoryResponseVerifier is not implemented")

    result = module.DirectoryResponseVerifier().verify(
        directory=directory,
        body=body,
        request_uri=DIRECTORY_URI,
        response_uri=response.url,
        status_code=response.status_code,
        signature=response.headers.get("Signature"),
        signature_input=response.headers.get("Signature-Input"),
        content_digest=response.headers.get("Content-Digest"),
        now=datetime.now(UTC),
    )

    assert len(result.bindings) == 1
    binding = result.bindings[0]
    assert binding.key_thumbprint == resolver.key_id
    assert binding.authority == "agent.example"
    assert binding.body_sha256 == hashlib.sha256(body).hexdigest()
    assert binding.profile == "draft-meunier-webbotauth-httpsig-directory-00"
