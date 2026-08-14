# Security Policy

## Supported versions

This project is pre-alpha. Security fixes are applied to the default branch only until the first stable release line exists.

## Reporting a vulnerability

Please use GitHub Private Vulnerability Reporting when it is enabled for the repository. Do not open a public issue containing exploit details, secrets, production traffic, credentials, raw packet captures, or personal data.

If private reporting is unavailable, contact the maintainer privately before sharing sensitive reproduction material.

## Data handling rules

Never attach real access logs to a public issue unless they have been independently sanitized. In particular, remove or transform:

- raw IP addresses;
- cookies and authorization headers;
- query-string values;
- request/response bodies;
- account identifiers and session tokens.

Use the synthetic fixtures under `examples/data/` for public reproductions whenever possible.

## Security model

V0 is observe-only. It must fail without silently weakening privacy transforms. If a raw client IP is supplied without a pseudonymization key, analysis stops rather than emitting the address.

A known User-Agent is only a claim. Do not use V0 `identity_confidence` as proof that an actor is authentic.
