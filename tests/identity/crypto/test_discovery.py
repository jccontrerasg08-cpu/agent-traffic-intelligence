from __future__ import annotations

import pytest

from agent_traffic_intelligence.identity.crypto.signature_agent import (
    SignatureAgentDiscoveryType,
    SignatureAgentReference,
)


def _module():
    try:
        from agent_traffic_intelligence.identity.crypto import discovery
    except ImportError:
        pytest.fail("Signature-Agent discovery planning is not implemented")
    return discovery


def reference(
    uri: str,
    discovery_type: SignatureAgentDiscoveryType,
) -> SignatureAgentReference:
    return SignatureAgentReference(
        label="sig1",
        uri=uri,
        discovery_type=discovery_type,
    )


def test_directory_origin_maps_to_well_known_identifier() -> None:
    module = _module()
    target = module.plan_signature_agent_resolution(
        reference(
            "https://Agent.Example:443",
            SignatureAgentDiscoveryType.DIRECTORY,
        )
    )

    expected = "https://agent.example/.well-known/http-message-signatures-directory"
    assert target.fetch_uri == expected
    assert target.identifier_uri == expected
    assert target.discovery_type is SignatureAgentDiscoveryType.DIRECTORY


@pytest.mark.parametrize(
    "uri",
    [
        "http://agent.example",
        "data:application/http-message-signatures-directory+json,%7B%22keys%22%3A%5B%5D%7D",
        "https://agent.example/path",
        "https://agent.example/?query=1",
        "https://user:pass@agent.example",
    ],
)
def test_directory_rejects_non_origin_or_non_https_member(uri: str) -> None:
    module = _module()

    with pytest.raises(module.SignatureAgentResolutionError):
        module.plan_signature_agent_resolution(
            reference(uri, SignatureAgentDiscoveryType.DIRECTORY)
        )


def test_jwks_uri_fetch_keeps_query_but_identifier_drops_it() -> None:
    module = _module()
    target = module.plan_signature_agent_resolution(
        reference(
            "https://Keys.Example:443/jwks.json?tenant=one#local",
            SignatureAgentDiscoveryType.JWKS_URI,
        )
    )

    assert target.fetch_uri == "https://keys.example/jwks.json?tenant=one"
    assert target.identifier_uri == "https://keys.example/jwks.json"
    assert target.discovery_type is SignatureAgentDiscoveryType.JWKS_URI


def test_cimd_uses_same_identifier_rule_as_direct_jwks() -> None:
    module = _module()
    target = module.plan_signature_agent_resolution(
        reference(
            "https://Agent.Example/card?profile=1#ignored",
            SignatureAgentDiscoveryType.CIMD,
        )
    )

    assert target.fetch_uri == "https://agent.example/card?profile=1"
    assert target.identifier_uri == "https://agent.example/card"
    assert target.discovery_type is SignatureAgentDiscoveryType.CIMD


@pytest.mark.parametrize(
    "discovery_type",
    [SignatureAgentDiscoveryType.JWKS_URI, SignatureAgentDiscoveryType.CIMD],
)
def test_dynamic_resolution_requires_absolute_https_uri(discovery_type) -> None:
    module = _module()

    for uri in (
        "http://agent.example/keys",
        "data:application/json,%7B%7D",
        "/relative",
        "https://user:pass@agent.example/keys",
    ):
        with pytest.raises(module.SignatureAgentResolutionError):
            module.plan_signature_agent_resolution(reference(uri, discovery_type))
