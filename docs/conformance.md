# Conformance Boundaries

ATI validates evidence against explicitly pinned profiles; it does not claim universal compliance with every evolving bot-authentication proposal.

## ATI can assert

- whether a supported official range publication parsed under its declared profile;
- whether a trusted ephemeral source address matched that publication;
- whether provider-documented FCrDNS passed reverse and forward confirmation;
- whether an RFC 9421 signature verifies under a supported asymmetric algorithm;
- which components were actually covered by that signature;
- whether Web Bot Auth application-policy requirements and trusted-directory binding passed;
- whether strong identity evidence conflicts.

## ATI deliberately does not assert

- exact foundation-model identity from ordinary network traffic;
- provider identity from ASN/cloud hosting alone;
- that a self-asserted Agent Card purpose is truthful;
- that a verified bot is safe or low risk;
- that an unavailable network/DNS check is an identity failure;
- that parsing a future Internet-Draft revision implies compatibility.

Conformance fixtures are deterministic and offline. Live endpoints are source-health inputs, not unit-test dependencies.
