"""Verify HTTP Message Signature bindings on key-directory responses."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from agent_traffic_intelligence.identity.crypto.content_digest import (
    ContentDigestError,
    validate_content_digest,
)
from agent_traffic_intelligence.identity.crypto.directory import DirectoryKey, KeyDirectory
from agent_traffic_intelligence.identity.crypto.key_resolver import JwkKeyResolver
from agent_traffic_intelligence.identity.crypto.rfc9421 import Rfc9421Result
from agent_traffic_intelligence.identity.crypto.rfc9421_response import (
    ResponseMessage,
    ResponseRequest,
    Rfc9421ResponseVerifier,
)
from agent_traffic_intelligence.identity.models import VerificationOutcome
from agent_traffic_intelligence.identity.sources.models import KeyAuthorityBinding
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE

_DIRECTORY_TAG = "http-message-signatures-directory"
_REQUIRED_COMPONENTS = frozenset({"@authority", "content-digest"})


@dataclass(frozen=True, slots=True)
class DirectoryBindingResult:
    """Privacy-safe bindings derived from a fetched directory response."""

    bindings: tuple[KeyAuthorityBinding, ...]


class DirectoryResponseVerifier:
    """Bind directory keys to the authority of the request that fetched them."""

    def verify(
        self,
        *,
        directory: KeyDirectory,
        body: bytes,
        request_uri: str,
        response_uri: str,
        status_code: int,
        signature: str | None,
        signature_input: str | None,
        content_digest: str | None,
        now: datetime,
    ) -> DirectoryBindingResult:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("directory response verification time must be timezone-aware")
        if not signature or not signature_input or not content_digest:
            return DirectoryBindingResult(())

        try:
            validate_content_digest(content_digest, body)
        except ContentDigestError:
            return DirectoryBindingResult(())

        authority = urlsplit(request_uri).netloc.casefold()
        if not authority:
            raise ValueError("directory request URI must include an authority")

        message = ResponseMessage(
            status_code=status_code,
            url=response_uri,
            headers={
                "Signature": signature,
                "Signature-Input": signature_input,
                "Content-Digest": content_digest,
            },
            request=ResponseRequest(method="GET", url=request_uri, headers={}),
        )
        verifier = Rfc9421ResponseVerifier(JwkKeyResolver(directory))
        body_sha256 = hashlib.sha256(body).hexdigest()
        bindings: list[KeyAuthorityBinding] = []

        for key in directory.keys:
            for algorithm_id in self._candidate_algorithms(key):
                result = verifier.verify(
                    message,
                    algorithm_id=algorithm_id,
                    expect_tag=_DIRECTORY_TAG,
                    required_components=_REQUIRED_COMPONENTS,
                    expected_key_id=key.key_id,
                )
                if result.outcome is not VerificationOutcome.PASS:
                    continue
                if not self._covers_request_authority(result):
                    continue
                bindings.append(
                    KeyAuthorityBinding(
                        key_thumbprint=key.thumbprint,
                        authority=authority,
                        body_sha256=body_sha256,
                        verified_at=now,
                        expires_at=self._expires_at(result),
                        profile=DEFAULT_STANDARDS_PROFILE.message_signatures_directory,
                    )
                )
                break

        return DirectoryBindingResult(tuple(bindings))

    @staticmethod
    def _candidate_algorithms(key: DirectoryKey) -> tuple[str, ...]:
        crv = key.jwk.get("crv")
        if key.kty == "OKP" and crv == "Ed25519":
            return ("ed25519",)
        if key.kty == "EC" and crv == "P-256":
            return ("ecdsa-p256-sha256",)
        if key.kty == "RSA":
            if key.alg in {"PS512", "rsa-pss-sha512"}:
                return ("rsa-pss-sha512",)
            if key.alg in {"RS256", "rsa-v1_5-sha256"}:
                return ("rsa-v1_5-sha256",)
            return ("rsa-pss-sha512", "rsa-v1_5-sha256")
        return ()

    @staticmethod
    def _covers_request_authority(result: Rfc9421Result) -> bool:
        for component in result.covered_components or {}:
            normalized = component.casefold().replace(" ", "")
            if normalized.startswith('"@authority";') and ";req" in normalized:
                return True
        return False

    @staticmethod
    def _expires_at(result: Rfc9421Result) -> datetime | None:
        expires = (result.parameters or {}).get("expires")
        if isinstance(expires, bool) or not isinstance(expires, int):
            return None
        return datetime.fromtimestamp(expires, tz=UTC)
