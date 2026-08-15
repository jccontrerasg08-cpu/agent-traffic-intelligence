from __future__ import annotations

import base64

import pytest

from agent_traffic_intelligence.identity.crypto.jwk_set import (
    JwkSetFormatError,
    JwkSetKey,
    parse_jwk_set,
)


def okp_jwk(**extra: object) -> dict[str, object]:
    x = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x, **extra}


def test_generic_jwk_set_preserves_operator_kid_and_ignores_set_extensions() -> None:
    parsed = parse_jwk_set(
        {
            "keys": [okp_jwk(kid="operator-key-1", alg="EdDSA", use="sig")],
            "future-set-member": {"ignored": True},
        }
    )

    key = parsed.keys[0]
    assert key.kid == "operator-key-1"
    assert key.thumbprint
    assert key.thumbprint != key.kid
    assert key.alg == "EdDSA"
    assert key.use == "sig"
    assert dict(key.jwk)["kid"] == "operator-key-1"


def test_generic_jwk_set_accepts_json_bytes_and_text() -> None:
    payload = '{"keys":[{"kty":"RSA","e":"AQAB","n":"modulus"}]}'

    assert parse_jwk_set(payload).keys[0].kty == "RSA"
    assert parse_jwk_set(payload.encode()).keys[0].kty == "RSA"


def test_generic_jwk_set_rejects_private_or_bad_metadata() -> None:
    with pytest.raises(JwkSetFormatError, match="private"):
        parse_jwk_set({"keys": [okp_jwk(d="private")]})
    with pytest.raises(JwkSetFormatError, match="kid"):
        parse_jwk_set({"keys": [okp_jwk(kid=7)]})
    with pytest.raises(JwkSetFormatError, match="alg"):
        parse_jwk_set({"keys": [okp_jwk(alg=7)]})
    with pytest.raises(JwkSetFormatError, match="use"):
        parse_jwk_set({"keys": [okp_jwk(use=7)]})
    with pytest.raises(JwkSetFormatError, match="nbf"):
        parse_jwk_set({"keys": [okp_jwk(nbf=True)]})


def test_generic_jwk_set_rejects_invalid_shapes_and_duplicate_keys() -> None:
    for payload in (b"not-json", "not-json", [], {"keys": "not-a-list"}):
        with pytest.raises(JwkSetFormatError):
            parse_jwk_set(payload)

    with pytest.raises(JwkSetFormatError, match="object"):
        parse_jwk_set({"keys": ["not-an-object"]})
    with pytest.raises(JwkSetFormatError, match="unsupported"):
        parse_jwk_set({"keys": [{"kty": "oct", "k": "secret"}]})
    with pytest.raises(JwkSetFormatError, match="duplicate"):
        parse_jwk_set({"keys": [okp_jwk(), okp_jwk()]})


def test_generic_jwk_set_key_rejects_invalid_validity_window() -> None:
    with pytest.raises(JwkSetFormatError, match="later"):
        JwkSetKey(
            kid=None,
            thumbprint="thumbprint",
            kty="OKP",
            alg=None,
            use=None,
            not_before=10,
            expires=10,
            jwk=okp_jwk(),
        )
