"""Provider-policy forward-confirmed reverse DNS verification."""

from __future__ import annotations

import socket
from ipaddress import IPv6Address, ip_address
from typing import Protocol

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.profiles import FcrdnsProfile
from agent_traffic_intelligence.models import IdentityClaim


_TRUSTED_ADDRESS_PROVENANCE = {
    SourceAddressProvenance.DIRECT_PEER,
    SourceAddressProvenance.TRUSTED_EDGE_CLIENT,
}
_LOOKUP_ERRORS = (ValueError, TimeoutError, socket.herror, socket.gaierror, OSError)


class DnsResolver(Protocol):
    """Minimal DNS seam so deterministic tests never need the network."""

    def reverse(self, address: str) -> tuple[str, ...]: ...

    def forward(self, hostname: str) -> tuple[str, ...]: ...


class SocketDnsResolver:
    """Standard-library DNS implementation for explicitly enabled live mode."""

    def reverse(self, address: str) -> tuple[str, ...]:
        hostname, aliases, _addresses = socket.gethostbyaddr(address)
        return tuple(dict.fromkeys((hostname, *aliases)))

    def forward(self, hostname: str) -> tuple[str, ...]:
        results = socket.getaddrinfo(hostname, None)
        addresses = {str(item[4][0]) for item in results}
        return tuple(sorted(addresses))


class FcrdnsVerifier:
    """Verify provider identity using documented rDNS suffixes and forward confirmation."""

    def __init__(self, resolver: DnsResolver | None = None) -> None:
        self._resolver = resolver or SocketDnsResolver()

    def verify(
        self,
        *,
        context: VerificationContext,
        claim: IdentityClaim,
        profile: FcrdnsProfile | None,
    ) -> VerificationEvidence:
        if profile is None:
            return self._evidence(
                claim=claim,
                profile=None,
                outcome=VerificationOutcome.UNAVAILABLE,
                explanation="provider has no documented FCrDNS verification policy",
                details={"confirmed": False},
            )
        if (
            context.source_ip is None
            or context.source_address_provenance not in _TRUSTED_ADDRESS_PROVENANCE
        ):
            return self._evidence(
                claim=claim,
                profile=profile,
                outcome=VerificationOutcome.UNAVAILABLE,
                explanation="a trusted ephemeral source address is unavailable for FCrDNS",
                details={"confirmed": False},
            )

        try:
            source_address = self._normalize_address(context.source_ip)
            reverse_names = self._resolver.reverse(context.source_ip)
        except _LOOKUP_ERRORS:
            return self._evidence(
                claim=claim,
                profile=profile,
                outcome=VerificationOutcome.UNAVAILABLE,
                explanation="reverse DNS lookup was unavailable",
                details={"confirmed": False},
            )

        candidates: list[tuple[str, str]] = []
        for raw_name in reverse_names:
            hostname = self._normalize_hostname(raw_name)
            suffix = self._matching_suffix(hostname, profile.allowed_suffixes)
            if suffix is not None:
                candidates.append((hostname, suffix))
        if not candidates:
            return self._evidence(
                claim=claim,
                profile=profile,
                outcome=VerificationOutcome.MISMATCH,
                explanation="reverse DNS names did not match a documented provider suffix",
                details={"confirmed": False},
            )

        lookup_error = False
        for hostname, suffix in candidates:
            try:
                forward_addresses = self._resolver.forward(hostname)
                normalized = {self._normalize_address(item) for item in forward_addresses}
            except _LOOKUP_ERRORS:
                lookup_error = True
                continue
            if source_address in normalized:
                return self._evidence(
                    claim=claim,
                    profile=profile,
                    outcome=VerificationOutcome.PASS,
                    explanation="reverse DNS identity was confirmed by a forward lookup",
                    details={"confirmed": True, "matched_suffix": suffix},
                )

        if lookup_error:
            return self._evidence(
                claim=claim,
                profile=profile,
                outcome=VerificationOutcome.UNAVAILABLE,
                explanation="forward DNS confirmation was unavailable",
                details={"confirmed": False},
            )
        return self._evidence(
            claim=claim,
            profile=profile,
            outcome=VerificationOutcome.MISMATCH,
            explanation="forward DNS results did not contain the original source address",
            details={"confirmed": False},
        )

    @staticmethod
    def _normalize_hostname(value: str) -> str:
        return value.casefold().rstrip(".")

    @staticmethod
    def _matching_suffix(hostname: str, suffixes: tuple[str, ...]) -> str | None:
        for suffix in suffixes:
            normalized = suffix.casefold().rstrip(".")
            if hostname == normalized or hostname.endswith(f".{normalized}"):
                return normalized
        return None

    @staticmethod
    def _normalize_address(value: str) -> str:
        address = ip_address(value)
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return str(address)

    @staticmethod
    def _evidence(
        *,
        claim: IdentityClaim,
        profile: FcrdnsProfile | None,
        outcome: VerificationOutcome,
        explanation: str,
        details: dict[str, str | int | float | bool | None],
    ) -> VerificationEvidence:
        scope = profile.binding_scope if profile is not None else BindingScope.PROVIDER
        reviewed_on = profile.reviewed_on if profile is not None else "unavailable"
        return VerificationEvidence(
            method=VerificationMethod.FCRDNS,
            outcome=outcome,
            binding_scope=scope,
            authority=claim.provider,
            subject=claim.provider,
            explanation=explanation,
            source_uri=None,
            source_profile=f"provider-fcrdns-policy:{reviewed_on}",
            retrieved_at=None,
            expires_at=None,
            source_sha256=None,
            details=details,
        )
