from __future__ import annotations

import json

import pytest

from agent_traffic_intelligence.identity.crypto.directory import jwk_thumbprint
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.source_service import SourceSpec, _document_from_result
from agent_traffic_intelligence.identity.sources.fetcher import FetchResult
from agent_traffic_intelligence.identity.sources.models import SourceType

DIRECTORY_URI = "https://agent.example/.well-known/http-message-signatures-directory"


def directory_body() -> bytes:
    raw_key = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
        "use": "sig",
    }
    raw_key["kid"] = jwk_thumbprint(raw_key)
    return json.dumps(
        {"keys": [raw_key]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def directory_spec() -> SourceSpec:
    return SourceSpec(
        provider="example",
        uri=DIRECTORY_URI,
        source_type=SourceType.KEY_DIRECTORY,
        parser_profile="directory-05",
        binding_scope=BindingScope.AGENT,
    )


@pytest.mark.parametrize("content_type", [None, "application/json", "text/plain"])
def test_directory_rejects_wrong_or_missing_media_type(content_type: str | None) -> None:
    result = FetchResult(
        uri=DIRECTORY_URI,
        status=200,
        body=directory_body(),
        content_type=content_type,
        etag=None,
        last_modified=None,
        cache_control="max-age=3600",
        redirects=0,
        not_modified=False,
    )

    with pytest.raises(ValueError, match="media type"):
        _document_from_result(directory_spec(), result)
