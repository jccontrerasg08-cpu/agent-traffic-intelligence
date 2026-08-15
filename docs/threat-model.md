# Threat Model

## Protected assets

- reliable, explainable traffic classification;
- privacy of request/network data;
- integrity of identity source/provenance material;
- integrity of repository automation and releases.

## Trust categories

**Trusted:** reviewed repository code, pinned workflow dependencies, validated internal schemas, curated provider profiles and verified immutable release artifacts.

**Semi-trusted:** provider-owned JSON/JWKS/Agent Cards, DNS responses, cached external source documents and standards drafts. These must still be validated, scoped and freshness-checked.

**Untrusted:** arbitrary requests, User-Agent strings, forwarded headers, unknown Signature-Agent URLs, public web content, issue/PR input and third-party artifacts not explicitly reviewed.

## Adversaries and failure modes

### Spoofed User-Agent

A request can claim any bot token. UA remains a claim; V1 requires scoped network or cryptographic evidence for stronger identity.

### Proxy-header spoofing

`X-Forwarded-For` and equivalents are attacker-controlled unless the directly connected peer is explicitly trusted. Default V1 never promotes them into positive source-address evidence.

### PTR/DNS spoofing and rebinding

PTR alone is insufficient. FCrDNS requires provider-documented suffix plus forward confirmation. Remote-source fetches validate public DNS destinations and pin the connection to already validated addresses while keeping TLS hostname validation.

### SSRF through Signature-Agent

Unknown request-provided discovery URIs are parsed but not automatically fetched. Default `registry_only` policy is intentionally restrictive.

### Signature confusion and unsigned context

A valid signature is accepted only for the expected application tag and ATI trusts only components actually returned as covered by RFC 9421 verification. Signed-agent binding must itself be covered.

### Replay

Created/expires windows are checked independently of cryptographic validity. A bounded process-local nonce cache can detect repeat nonces during a validity window; distributed persistent replay state is outside V1 offline scope.

### Stale/compromised source material

Sources are content-addressed and carry freshness/provenance. Stale/error/unavailable sources cannot become categorical failures. Source-health automation must not silently rewrite trust policy.

### Supply-chain workflow compromise

Third-party Actions execute privileged automation. ATI pins Actions to full commit SHAs, keeps permissions least privilege and avoids unnecessary Actions. Metadata workflows never execute untrusted PR code under `pull_request_target`.

### Residential proxies, TLS mimicry and real-browser automation

IP/ASN/TLS fingerprints remain supporting behavioral evidence only. They are not identity proof and advanced browser automation can be fundamentally ambiguous server-side.

### Poisoning and concept drift

V1 has no online training. Future ML pipelines must separate trusted labels, time-based evaluation, model provenance, rollback and drift monitoring.

## Failure policy

V1 remains observe-only. Operational verifier failures preserve evidence and default to neutral identity outcomes rather than enforcement. Any future blocking/challenge/rate-limit layer must remain separate and undergo its own threat review.
