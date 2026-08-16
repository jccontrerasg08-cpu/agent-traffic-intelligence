# Security Policy

## Supported versions

This project is pre-alpha. Security fixes are applied to the default branch until a stable release line exists.

## Reporting a vulnerability

Use [GitHub Private Vulnerability Reporting](https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence/security/advisories/new) for reports. Do not open public issues containing exploit details, credentials, secrets, production traffic, raw packet captures, private keys, signature material, or personal data. If private reporting is unavailable, contact the maintainer privately before sharing sensitive reproduction material.

## Public reproduction data

Never attach real access logs without independent sanitization. Remove or transform:

- raw IP addresses;
- cookies and authorization headers;
- query-string values;
- request/response bodies;
- account identifiers and session tokens;
- HTTP `Signature`, `Signature-Input`, and request-controlled discovery payloads;
- private keys or other signing secrets.

Use the synthetic fixtures under `examples/data/` and `tests/` for public reproductions whenever possible.

## Identity verification safety

ATI is observe-only. Authentication evidence is not enforcement policy, and a known User-Agent remains only a claim until stronger identity evidence verifies it. A verified identity is not automatically safe and does not lower `risk_score` by itself.

### Privacy boundary

`RequestEvent` is privacy-minimized. Raw source addresses and the HTTP material needed to reconstruct signatures belong only in the ephemeral `VerificationContext`; they must not be serialized into detections, manifests, cache keys, or exception text.

Raw client IP input requires the configured pseudonymization key. Analysis fails closed rather than emitting an unhashed address. Untrusted forwarded headers must not drive positive network verification.

Inline `data:` key directories are bounded and request-controlled. Their payload is not persisted in verification evidence; successful inline authentication is restricted to `KEY` scope and does not by itself verify a provider or named agent.

### Network boundary

Normal `ati analyze` does not perform arbitrary discovery fetches. Configured `directory`, `jwks_uri`, and `cimd` verification resolves from the local cache. A nested CIMD `jwks_uri` requires its own explicit trust-policy authorization; the existence of a cached document is not permission to use it.

Network-capable operations are explicit, such as source refresh and `ati standards health`. Fetchers use constrained HTTPS destinations, bounded bodies/timeouts, strict response validation, and redirect policy appropriate to the operation. Request-controlled unknown discovery URLs are not auto-fetched.

### Cryptographic boundary

RFC 9421 verification proves only what the successfully covered components and resolved key establish. Key possession, provider identity, and exact-agent identity are separate binding scopes.

ATI validates Web Bot Auth application policy such as the expected tag, validity window, signed authority/target context, key compatibility, and signed `Signature-Agent` binding. Optional nonce replay tracking is bounded and in-process; ATI does not claim distributed replay prevention.

For remote key material, `strict_current` sources require a current cryptographic authority/body binding to preserve provider or agent scope. Without it, a successful request signature is downgraded to `KEY` scope. `deployed_compatible` is an explicit source-specific interoperability policy for documented deployments, not a global weakening of request-signature verification.

### Failure semantics

Timeouts, stale sources, unsupported draft/profile revisions, optional dependency failures, DNS/HTTP failures, and parser execution errors are operational/neutral outcomes. They do not automatically become maliciousness or identity failure.

A verification pass affects identity evidence only. It does not directly lower `risk_score` or change automation/AI scores.

## Source and key compromise

Provider range documents and key directories are external trust dependencies. Cached evidence records URI, profile, freshness and SHA-256 provenance. If a provider source/key is suspected compromised, disable or remove that source profile and review affected detections rather than silently rewriting history.

## Repository automation

Actions are pinned to full commit SHAs and permissions are least privilege. `pull_request_target` workflows must never checkout or execute PR-head code. Artifact attestations, when release publishing is added, establish provenance only and do not replace vulnerability review.

## High-value vulnerability classes

Please report, privately, any reproducible case involving:

- raw IP, signature, credential, cookie, private-key, or inline-payload leakage;
- SSRF, redirect bypass, DNS rebinding, or trust-policy bypass in source/discovery fetching;
- accepting an unsigned or insufficiently covered `Signature-Agent` as authenticated identity;
- provider/agent scope granted from key possession without the required authority binding;
- replay-policy bypass that contradicts documented ATI guarantees;
- malformed or stale source material incorrectly producing `VERIFIED`;
- current-profile input silently downgrading into a weaker legacy parser;
- standards/provider drift silently rewriting trust policy or pinned revisions.
