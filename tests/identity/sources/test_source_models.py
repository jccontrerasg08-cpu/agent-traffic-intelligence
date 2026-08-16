from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.sources.cache import SourceCache
from agent_traffic_intelligence.identity.sources.models import (
    KeyAuthorityBinding,
    SourceDocument,
    SourceMetadata,
    SourceType,
)

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
BODY_SHA256 = "a" * 64
KEY_THUMBPRINT = "thumbprint-example"


def binding() -> KeyAuthorityBinding:
    return KeyAuthorityBinding(
        key_thumbprint=KEY_THUMBPRINT,
        authority="agent.example",
        body_sha256=BODY_SHA256,
        verified_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        profile="draft-meunier-webbotauth-httpsig-directory-00",
    )


def test_key_authority_binding_is_privacy_safe_and_round_trips() -> None:
    value = binding()
    payload = value.to_dict()

    assert payload["key_thumbprint"] == KEY_THUMBPRINT
    assert payload["authority"] == "agent.example"
    assert payload["body_sha256"] == BODY_SHA256
    assert "signature" not in payload
    assert "signature_input" not in payload
    assert KeyAuthorityBinding.from_dict(payload) == value


def test_key_authority_binding_validates_time_and_digest() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        KeyAuthorityBinding(
            key_thumbprint=KEY_THUMBPRINT,
            authority="agent.example",
            body_sha256=BODY_SHA256,
            verified_at=datetime(2026, 8, 14, 12, 0),
            expires_at=None,
            profile="directory-00",
        )
    with pytest.raises(ValueError, match="SHA-256"):
        KeyAuthorityBinding(
            key_thumbprint=KEY_THUMBPRINT,
            authority="agent.example",
            body_sha256="bad",
            verified_at=NOW,
            expires_at=None,
            profile="directory-00",
        )


def test_source_metadata_defaults_old_manifests_to_no_key_bindings() -> None:
    metadata = SourceMetadata.from_dict(
        {
            "uri": "https://agent.example/.well-known/http-message-signatures-directory",
            "source_type": "key_directory",
            "provider": "example",
            "binding_scope": "agent",
            "retrieved_at": NOW.isoformat(),
            "sha256": BODY_SHA256,
            "content_type": "application/http-message-signatures-directory+json",
            "parser_profile": "httpsig-directory-00",
            "validation_status": "valid",
        }
    )

    assert metadata.key_authority_bindings == ()
    assert metadata.acquisition.value == "unknown"


def test_source_cache_persists_only_derived_key_bindings(tmp_path) -> None:
    body = b'{"keys":[]}'
    document = SourceDocument.from_bytes(
        uri="https://agent.example/.well-known/http-message-signatures-directory",
        source_type=SourceType.KEY_DIRECTORY,
        provider="example",
        binding_scope=BindingScope.AGENT,
        retrieved_at=NOW,
        content=body,
        content_type="application/http-message-signatures-directory+json",
        parser_profile="httpsig-directory-00",
        key_authority_bindings=(
            KeyAuthorityBinding(
                key_thumbprint=KEY_THUMBPRINT,
                authority="agent.example",
                body_sha256=hashlib.sha256(body).hexdigest(),
                verified_at=NOW,
                expires_at=NOW + timedelta(hours=1),
                profile="draft-meunier-webbotauth-httpsig-directory-00",
            ),
        ),
    )
    cache = SourceCache(tmp_path)
    cache.put(document)

    loaded = cache.get(document.metadata.uri)
    assert loaded is not None
    assert loaded.metadata.key_authority_bindings == document.metadata.key_authority_bindings
    manifest_text = cache.manifest_path.read_text(encoding="utf-8").casefold()
    assert "signature-input" not in manifest_text
    assert '"signature"' not in manifest_text
