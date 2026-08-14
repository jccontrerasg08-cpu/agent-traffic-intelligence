# V1 Verified Identity Design

**Status:** Approved design, research-refined
**Date:** 2026-08-14
**Branch:** `design/v1-verified-identity`

## 1. Objective

V1 adds verifiable machine identity to Agent Traffic Intelligence while preserving the V0 invariants:

- observe-only operation;
- no enforcement side effects;
- four independent outputs (`automation_score`, `ai_score`, `identity_confidence`, `risk_score`);
- explainable evidence for every identity decision;
- no raw client IPs, credentials, request bodies, cookie values, or query-string values in serialized detections;
- no claim that an exact foundation model can be inferred from network traffic without explicit evidence.

V1 develops two verification tracks in parallel behind one common interface:

1. **Network identity**: official IP ranges and provider-specific forward-confirmed reverse DNS (FCrDNS).
2. **Cryptographic identity**: RFC 9421 HTTP Message Signatures plus the emerging Web Bot Auth key-directory and `Signature-Agent` conventions.

The tracks are independent. One may succeed while the other is unavailable. Their evidence is resolved centrally rather than being collapsed into a single boolean.

## 2. Research conclusions that change the original V1 sketch

The Web Bot Auth ecosystem expanded substantially in 2026. ATI should avoid inventing equivalent private formats where active standards work already exists.

The implementation therefore tracks these layers separately:

- **RFC 9421** is the stable standards-track baseline for HTTP Message Signatures.
- **HTTP Message Signatures Directory** is an active Internet-Draft defining JWKS-based key discovery, `Signature-Agent`, freshness and key rotation conventions.
- **Web Bot Auth architecture** is an active Internet-Draft defining how bots use RFC 9421 signatures for identity.
- **JAFAR** is an active Internet-Draft defining a machine-readable JSON format for bot/crawler IP ranges.
- **Signature Agent Card / registry** is an active Internet-Draft describing metadata such as expected User-Agent, robots.txt token/compliance, trigger, purpose, rate expectations, known URLs, JWKS URI and IP-list URI.
- **Crawler best practices** is active IETF work describing identifiable User-Agents, robots.txt behavior, caching, rate responsibility, published IP ranges and crawler documentation.

All Internet-Drafts remain work in progress. ATI MUST version the draft profile it implements and MUST isolate draft-specific parsing from stable internal contracts so that a draft revision does not force a public API redesign.

## 3. Trust hierarchy

Identity evidence has an explicit source hierarchy. A source being informative does not make it authoritative for all fields.

### 3.1 Stable protocol authority

1. Published RFCs, especially RFC 9421 and HTTP semantics/caching RFCs.
2. Active IETF Web Bot Auth drafts, treated as versioned work in progress rather than stable RFCs.

### 3.2 Provider authority

3. Provider-owned documentation and machine-readable endpoints.
4. Provider-published DNS naming rules.

Current examples verified during design research:

- OpenAI publishes crawler-specific JSON range files such as `searchbot.json`, `gptbot.json`, and `adsbot.json`.
- Google publishes separate JSON ranges for common crawlers, special crawlers, user-triggered fetchers, and user-triggered agents, and documents FCrDNS hostname masks.
- Perplexity documents separate IP JSON endpoints for `PerplexityBot` and `Perplexity-User`.
- Anthropic currently states that it does not publish crawler IP ranges; network verification must therefore report unavailable rather than manufacture confidence.

### 3.3 Research references

Open-source repositories can inform architecture, interoperability tests, and dependency selection, but they MUST NOT become identity authorities merely because they contain bot lists.

The design reviewed:

- `thibmeu/http-message-signatures-directory` for the active Web Bot Auth draft source tree;
- `pyauth/http-message-signatures` for a maintained Python RFC 9421 implementation;
- `HumanSecurity/human-verified-ai-agent` for separation of key management, signature handling and request orchestration.

ATI will not copy implementation code from these projects. License and attribution review remains required for every dependency.

## 4. Core semantic distinction

V1 distinguishes five concepts that must not be conflated:

1. **Claim** — what a request says it is, e.g. `User-Agent: GPTBot`.
2. **Authentication evidence** — evidence that the request controls an expected network origin or cryptographic key.
3. **Binding evidence** — evidence that the authenticated key/network identity belongs to the claimed provider/agent.
4. **Metadata** — self-described purpose, trigger, robots behavior, expected rate and similar Agent Card data.
5. **Risk** — behavior that is abusive or operationally dangerous.

A valid signature proves possession of a key; it does not automatically prove that a friendly `client_name` is a real-world organization. A published Agent Card is metadata until its authority and key binding are validated. Likewise, a verified identity does not imply low risk.

## 5. Architecture

```text
raw log record / edge event
          |
          +------------------------------+
          |                              |
          v                              v
 privacy normalizer              VerificationContext
          |                       (ephemeral only)
          v                              |
   RequestEvent                          |
          |                              |
          +--------------+---------------+
                         v
                IdentityClaim matcher
                         |
                         v
                VerificationManager
                /                 \
               /                   \
        network verifiers      crypto verifiers
        - source IP            - RFC 9421
        - official CIDR        - Signature-Agent
        - FCrDNS               - JWKS directory
        - provider policy      - replay/time policy
               \                   /
                \                 /
                 +-------+-------+
                         v
                VerificationEvidence[]
                         |
                         v
                IdentityResolver
                         |
          +--------------+---------------+
          |              |               |
       verified       conflicted       claimed/failed
          |              |               |
          +--------------+---------------+
                         v
               explainable Detection
```

## 6. Privacy-preserving ingestion boundary

### 6.1 Problem

V0 deliberately removes the raw client address while producing `RequestEvent`. Network verification needs the source IP, but reintroducing it into `RequestEvent` or output would violate V0's privacy contract.

### 6.2 Decision: ephemeral `VerificationContext`

The parser/adapter produces two logical views from one input record:

- a serializable, privacy-minimized `RequestEvent`;
- a non-serializable `VerificationContext` used only during identity verification.

`VerificationContext` may contain:

- source IP address;
- original authority/host needed for signature verification;
- HTTP method and request target components required by RFC 9421;
- only the HTTP headers required to reconstruct covered signature components;
- `Signature`, `Signature-Input`, and `Signature-Agent` where present;
- adapter trust metadata such as whether the source address came directly from the edge or from a configured trusted proxy chain.

It MUST NOT be included in `Detection.to_dict()`, logs, cache keys that can be exported, exception messages, or persistent evidence snapshots.

After verification, only privacy-safe facts survive, e.g. `matched_official_range=true`, provider, method, source digest and freshness timestamps.

## 7. Source-address trust

`remote_addr` or the edge adapter's equivalent is authoritative by default.

Forwarded headers such as `X-Forwarded-For` MUST NOT be trusted by default. A future/optional trusted-proxy configuration may walk a forwarded chain only when the directly connected peer is in an explicitly configured trusted-proxy set.

The verifier must support IPv4 and IPv6, including careful normalization of IPv4-mapped IPv6 addresses. CIDR matching uses Python's standard-library `ipaddress` semantics and canonical networks.

## 8. Verification result model

### 8.1 Final identity states

Extend `VerificationState` with:

- `NONE`
- `CLAIMED`
- `VERIFIED`
- `FAILED`
- `CONFLICTED`

`CONFLICTED` is required because strong evidence can disagree. Example: a User-Agent claims provider A while a valid cryptographic identity is bound to provider B.

### 8.2 Per-method outcomes

Individual verifiers return a richer internal outcome than the final state:

- `PASS`
- `MISMATCH`
- `UNAVAILABLE`
- `INDETERMINATE`
- `STALE`
- `ERROR`

`ERROR` describes verifier execution failure, not maliciousness.

### 8.3 `VerificationEvidence`

Each method emits an immutable record containing at least:

- `method`;
- `outcome`;
- claimed provider/agent if applicable;
- authenticated authority or subject if known;
- human-readable explanation;
- source URI or source identifier;
- source format/profile;
- `retrieved_at`;
- `expires_at` when known;
- SHA-256 digest of the source material when applicable;
- privacy-safe structured details;
- optional score delta for `identity_confidence` only.

No verifier directly changes `automation_score`, `ai_score`, or `risk_score` merely because an identity passed authentication.

## 9. Network verification track

### 9.1 Modules

Proposed package boundary:

```text
src/agent_traffic_intelligence/identity/
  network/
    source_address.py
    cidr.py
    fcrdns.py
    verifier.py
    providers/
      base.py
      openai.py
      google.py
      perplexity.py
      anthropic.py
    formats/
      jafar.py
      legacy_prefixes.py
```

### 9.2 IP publication parsing

ATI should implement a normalized `PublishedRangeSet` independent of source JSON shape.

Parsers support:

1. JAFAR-compatible documents.
2. Existing provider `prefixes` documents with `ipv4Prefix` / `ipv6Prefix`.
3. Provider adapters only where an official endpoint differs materially.

Unknown fields are ignored for forward compatibility. Invalid prefix objects are rejected or ignored according to the applicable profile while surfacing validation diagnostics.

For overlapping ranges, the most specific matching prefix wins when source metadata differs, following the JAFAR design.

### 9.3 Freshness

Range documents keep:

- publisher `creationTime` when supplied;
- HTTP `ETag`;
- `Last-Modified`;
- `Cache-Control` freshness;
- local retrieval time;
- SHA-256 digest;
- parser/profile version.

Conditional HTTP requests use `If-None-Match` and/or `If-Modified-Since` when live fetching is enabled.

Polling MUST respect HTTP cache directives and MUST never exceed provider guidance. Scheduled health checks are separated from deterministic PR CI.

### 9.4 FCrDNS

FCrDNS is provider-policy driven:

1. reverse-resolve source address;
2. require an allowed provider hostname suffix/pattern;
3. forward-resolve the resulting hostname;
4. require the original source address to appear in the A/AAAA result set.

Provider suffixes are authoritative only when documented by the provider. A PTR result alone never verifies identity.

DNS timeout, NXDOMAIN, temporary resolver failure or missing provider policy produces `UNAVAILABLE`/`INDETERMINATE`, not `FAILED`.

### 9.5 Provider behavior

- **Google**: support its documented JSON categories and documented FCrDNS hostname masks.
- **OpenAI**: support crawler-specific official JSON range endpoints. Do not infer undocumented rDNS rules.
- **Perplexity**: support its documented bot/user JSON endpoints.
- **Anthropic**: return network verification unavailable while official IP ranges remain unpublished.

Provider adapters expose capabilities instead of pretending every provider supports the same verification methods.

## 10. Cryptographic verification track

### 10.1 Stable base

RFC 9421 defines canonicalization and HTTP Message Signature verification. ATI MUST NOT create a proprietary signature format.

### 10.2 Dependency strategy

V0's zero-runtime-dependency install remains valid.

Cryptographic verification is an optional extra, proposed as:

```text
agent-traffic-intelligence[verification]
```

The first implementation candidate is the Apache-2.0 `http-message-signatures` package (PyPI release 2.0.1 at design time), which itself uses `cryptography` and Structured Fields support. It is actively maintained and its PyPI release uses Trusted Publishing with provenance attestations.

ATI MUST wrap the dependency behind its own adapter rather than expose third-party classes in public ATI APIs. This preserves replaceability and keeps Web Bot Auth draft changes out of the stable domain model.

ATI MUST follow RFC 9421's "see what is signed" rule: downstream logic may trust only the covered components returned by successful verification, never the unsigned request values adjacent to a valid signature.

Multiple-signature handling is opt-in and label/tag-aware to avoid signature confusion.

### 10.3 Proposed modules

```text
identity/
  crypto/
    verifier.py
    rfc9421.py
    web_bot_auth.py
    key_resolver.py
    directory.py
    agent_card.py
    replay.py
```

### 10.4 Web Bot Auth profile

For a request to count as Web Bot Auth evidence, ATI verifies the active profile's requirements, including at minimum:

- valid RFC 9421 signature;
- expected Web Bot Auth `tag`;
- `created` and `expires` policy;
- key identifier/thumbprint consistency;
- required covered derived component such as `@authority` or `@target-uri` according to the active profile;
- `Signature-Agent` covered by the signature when it is used for discovery;
- algorithm is explicitly allowed by ATI policy;
- key is active for the relevant time window.

A cryptographically valid signature that fails application-profile requirements is not a verified Web Bot Auth identity.

### 10.5 Key directory

The directory adapter understands the active HTTP Message Signatures Directory profile:

- JWKS shape;
- HTTPS directory discovery;
- key validity fields when present;
- key rotation with overlapping old/new keys;
- cache freshness;
- directory response binding/signatures where supported by the profile;
- JWK thumbprints.

Directory integrity and directory-to-authority binding are separate checks from request-signature validity.

### 10.6 Safe `Signature-Agent` discovery

An attacker controls request headers. Automatically fetching arbitrary `Signature-Agent` URLs would create an SSRF-capable network primitive.

Therefore V1 defaults to **`registry_only` discovery**:

- directories already associated with a curated provider/registry may be fetched;
- arbitrary unknown `Signature-Agent` URLs are parsed but not automatically fetched;
- their result is `UNAVAILABLE` with an explanation that discovery is not trusted yet.

A later experimental `public_https` policy may permit unknown discovery only after a hardened fetcher is implemented with, at minimum:

- HTTPS only;
- no embedded credentials;
- no loopback, private, link-local, multicast, unspecified or otherwise non-public destination addresses;
- redirect revalidation on every hop;
- strict timeout and response-size limits;
- TLS certificate validation;
- media-type validation;
- bounded redirects;
- DNS-rebinding-resistant connection policy.

This safety policy is intentionally stricter than generic URI support in evolving drafts.

### 10.7 Replay protection

Signature validity and replay safety are distinct.

V1 enforces a bounded validity window using `created`/`expires`. Nonces are exposed as verification metadata when present.

A process-local bounded replay cache may reject repeated `(keyid, nonce)` combinations during the signature validity window when replay protection is enabled. Persistent/distributed nonce storage is out of scope for V1 offline analysis and belongs to a future real-time sensor.

## 11. Signature Agent Card metadata

ATI should be able to parse a versioned subset of the emerging Signature Agent Card, but self-declared metadata does not become authentication evidence by itself.

Useful fields include:

- client name and URI;
- contact information;
- expected User-Agent;
- RFC 9309 robots product token/compliance;
- `trigger` (`crawler` vs user-triggered `fetcher`);
- purpose;
- targeted content;
- rate-control mechanism and expected rate;
- known URL patterns;
- JWKS URI;
- IP-list URI;
- embedded keys where allowed by the active profile.

These fields provide future value to ATI:

- `trigger` can refine the crawler/fetcher taxonomy;
- purpose can improve intent classification;
- known URLs and expected rate can become contextual behavioral evidence after calibration;
- robots metadata can support an operator policy view;
- `jwks_uri` and `ips_uri` can unify cryptographic and network discovery.

For V1, these fields are recorded as `self_asserted` or `authority_bound` metadata and MUST NOT automatically lower `risk_score`.

## 12. Evidence-source cache and provenance

A shared cache layer serves range documents, key directories and Agent Cards.

Proposed modules:

```text
identity/
  sources/
    models.py
    cache.py
    fetcher.py
    manifest.py
    trust.py
```

Each cached object stores metadata, not secrets:

- canonical source URI;
- source type;
- provider/authority;
- retrieval timestamp;
- source-provided creation timestamp;
- freshness/expiry;
- ETag / Last-Modified;
- SHA-256 digest;
- content type;
- parser/profile version;
- validation status.

Cache content lives outside project output by default, e.g. a platform-appropriate user cache directory. Detection output references source digests and timestamps rather than embedding full remote documents.

## 13. Offline, live and hybrid operation

Network activity must never be a surprise.

Existing `ati analyze` behavior remains offline and unchanged unless identity verification is explicitly requested.

V1 defines three verification modes:

- `offline`: only local cached/snapshotted sources; no DNS or HTTP network calls;
- `live`: resolver and official-source fetching allowed according to policy;
- `hybrid`: use fresh cache first and fetch/resolve when required.

CLI names are finalized during implementation planning, but the behavioral contract is fixed: network verification requires an explicit opt-in path.

## 14. Verification manager and parallel execution

`VerificationManager` receives a claim, privacy-safe event and ephemeral context.

It discovers applicable verifiers from capabilities, then runs independent methods concurrently with a bounded executor:

- CIDR lookup can run independently from FCrDNS;
- cryptographic verification can run independently when key material is already cached;
- source refreshes are deduplicated per source URI;
- one verifier timeout cannot block all verification indefinitely.

Concurrency is bounded and deterministic aggregation order is preserved in serialized evidence.

No verifier mutates shared identity state. All methods return immutable evidence, and only `IdentityResolver` creates the final result.

## 15. Identity resolution policy

The resolver is explicit and testable.

### 15.1 Examples

**UA claim only**

- final state: `CLAIMED`;
- low identity confidence.

**UA claim + official provider-specific range match**

- may become `VERIFIED` when the provider documents that range as authoritative for that crawler/service;
- evidence records the exact source digest and range/service match.

**UA claim + documented FCrDNS pass**

- may become `VERIFIED` under that provider's documented policy.

**Valid RFC 9421 signature but no trustworthy provider binding**

- authentication evidence passes;
- real-world provider identity remains `INDETERMINATE`/claimed until the key-directory authority or registry binds it.

**Valid Web Bot Auth request + trusted/bound key directory**

- final state: `VERIFIED`.

**UA says provider A; bound cryptographic identity says provider B**

- final state: `CONFLICTED`;
- both pieces of evidence remain visible.

**Published range does not match but cryptographic identity verifies**

- do not automatically mark malicious;
- preserve the network mismatch and cryptographic success;
- resolver outcome depends on provider policy and whether the range was documented as mandatory for that specific agent.

**DNS/network timeout**

- method outcome: `UNAVAILABLE`;
- no negative risk implication.

## 16. Integration with existing scoring

Verification produces normal ATI `Evidence` records only after the resolver interprets method results.

Identity evidence may move `identity_confidence` strongly. It does not directly alter the other three dimensions.

The final discrete `verification_state` remains authoritative for the categorical result, while `identity_confidence` remains the continuous explainable score.

This avoids pretending that a cryptographic result and a probabilistic behavioral score are the same concept.

## 17. Backward compatibility

V1 is additive.

- `ati analyze` without explicit verification retains V0 no-network behavior.
- Existing V0 JSON consumers must continue to parse output.
- `Detection` gains an optional verification payload; serialization should omit it when verification is disabled so default V0 output remains stable.
- `VerificationState.CONFLICTED` is an enum extension, not a reinterpretation of existing values.
- Existing `RequestEvent` remains privacy-minimized and does not gain raw IP/header secrets.

## 18. Proposed public module map

```text
src/agent_traffic_intelligence/
  identity/
    __init__.py
    models.py
    manager.py
    resolver.py
    policy.py
    context.py
    network/
      source_address.py
      cidr.py
      fcrdns.py
      verifier.py
      formats/
        jafar.py
        legacy_prefixes.py
      providers/
        base.py
        openai.py
        google.py
        perplexity.py
        anthropic.py
    crypto/
      verifier.py
      rfc9421.py
      web_bot_auth.py
      key_resolver.py
      directory.py
      agent_card.py
      replay.py
    sources/
      models.py
      cache.py
      fetcher.py
      manifest.py
      trust.py
```

This layout may be reduced during implementation if a file would contain only trivial forwarding code. The important boundaries are manager/resolver, network, crypto, and external-source provenance.

## 19. Documentation additions

V1 should add or materially update:

- `docs/identity-verification.md` — operator model and result interpretation;
- `docs/web-bot-auth.md` — supported RFC/draft profile and limitations;
- `docs/provider-verification.md` — provider capability table and official sources;
- `docs/source-trust-policy.md` — source hierarchy, self-asserted vs authority-bound metadata;
- `docs/privacy-network-data.md` — ephemeral raw address/header handling;
- `docs/standards-status.md` — tracked RFCs/drafts with implemented revision/date;
- `docs/threat-model.md` — SSRF, signature confusion, replay, stale key/range data, DNS spoofing/rebinding, proxy-header spoofing;
- `SECURITY.md` — operational warnings for live verification;
- ADR: ephemeral verification context;
- ADR: optional crypto dependency boundary;
- ADR: no automatic fetch of unknown `Signature-Agent` URLs.

Provider docs must distinguish current facts from assumptions. Absence of a published method is recorded explicitly rather than inferred.

## 20. Testing strategy

### 20.1 Deterministic unit tests

No unit test depends on live Internet or real DNS.

Use fake resolver/fetcher seams and test:

- IPv4 and IPv6 CIDR matches;
- IPv4-mapped IPv6 handling;
- malformed/overlapping ranges;
- JAFAR unknown-field compatibility;
- creation/freshness parsing;
- provider capability differences;
- FCrDNS reverse + forward confirmation;
- PTR-only spoof attempts;
- proxy header spoofing;
- unavailable DNS semantics;
- resolver conflict rules;
- serialization privacy guarantees.

### 20.2 RFC 9421 / crypto tests

Include standards-derived test vectors and independent negative vectors for:

- valid signature;
- modified covered component;
- valid signature over the wrong/insufficient component set;
- stale/future timestamps;
- wrong tag;
- key-id/thumbprint mismatch;
- unsupported algorithm;
- duplicate/ambiguous labels;
- multiple-signature confusion;
- malformed Structured Fields;
- key rotation overlap;
- replayed nonce;
- unsigned `Signature-Agent` substitution.

Do not copy third-party fixture corpora without license review. Test expectations should derive from RFC/draft requirements.

### 20.3 Source-fetch security tests

Test that live-source policy rejects or safely handles:

- non-HTTPS sources where policy requires HTTPS;
- loopback/private/link-local destinations;
- redirect to disallowed destinations;
- oversized response bodies;
- wrong media type;
- excessive redirects;
- malformed JSON/JWKS;
- stale cached sources;
- unsupported future major format versions.

### 20.4 Property/fuzz testing

A dev-only property-testing dependency may be introduced for parsers and normalization if it improves confidence without affecting runtime dependencies. Fuzzing is especially useful for CIDR/JAFAR parsing, Structured Fields boundaries, URI handling, and resolver state combinations.

## 21. CI and source-health separation

Deterministic PR CI remains hermetic:

- core install with zero runtime dependencies;
- verification-extra install;
- Ruff;
- Mypy;
- tests and coverage;
- package build/install smoke;
- CLI smoke;
- CodeQL;
- dependency review.

Live external-source checks belong in a separate scheduled/manual workflow, not merge-blocking PR CI. It may check:

- official provider endpoints reachable;
- schema still parseable;
- source digest/freshness changed;
- IETF draft revision changed;
- provider capability/documentation changed.

A source-health failure must not look like a deterministic product-test failure.

Future automation may open a review PR when curated provider metadata or tracked standards versions change; it must not silently rewrite trust policy on `main`.

## 22. Development parallelism

Implementation is parallel after one serialized contract slice.

### Slice 0 — shared contracts (serialized)

Freeze:

- `VerificationContext`;
- `VerificationEvidence`;
- method outcomes;
- resolver API;
- cache/source interfaces;
- compatibility behavior.

### Track A — network verification

Owns only `identity/network/**` and its tests.

### Track B — cryptographic verification

Owns only `identity/crypto/**` and its tests.

### Track C — source/cache/provenance

Owns `identity/sources/**` after the shared source interface is frozen.

### Track D — docs/evaluation fixtures

Owns documentation, provider capability tables, schemas and integration fixtures without changing core interfaces.

### Integration — serialized

A single integration owner connects tracks to `Detector`, CLI and serialization, resolves merge overlap, and runs the full verification matrix.

Parallel writers must not edit the same interface files simultaneously.

## 23. Non-goals for V1

- Production blocking/challenge/rate-limit policy.
- Claiming a provider from ASN/cloud hosting alone.
- Identifying an exact LLM/model from traffic.
- Treating Agent Card metadata as verified solely because it is published.
- Persistent distributed replay databases.
- Browser JavaScript fingerprint collection.
- ML calibration or anomaly clustering.
- Automatically fetching arbitrary unknown `Signature-Agent` URLs.
- Anonymous/pseudonymous bot authorization protocols; these may be studied for a later phase.

## 24. Acceptance criteria

V1 is complete only when all of the following are demonstrated:

1. Existing V0 default behavior remains compatible and offline.
2. Raw source IP and signature-sensitive header material never appear in serialized detections.
3. OpenAI, Google and Perplexity official-range adapters work from deterministic fixtures based on their documented formats.
4. Anthropic correctly reports lack of published network verification rather than fabricating a failure/pass.
5. Google-style FCrDNS is tested with reverse-and-forward confirmation.
6. RFC 9421 signature verification passes standards-derived valid vectors and fails tampered/insufficiently-covered vectors.
7. Web Bot Auth profile checks validate tag, time window, key binding and required covered components.
8. Unknown `Signature-Agent` discovery cannot trigger arbitrary outbound fetches under the default policy.
9. Network and cryptographic verification can execute independently/concurrently and produce deterministic evidence ordering.
10. Conflicting strong evidence results in `CONFLICTED` without discarding either source.
11. External source snapshots carry freshness and SHA-256 provenance.
12. Core install remains usable without the crypto extra.
13. Verification-extra CI is green on supported Python versions.
14. Live source-health monitoring is separated from deterministic PR CI.
15. Documentation clearly distinguishes RFC requirements, Internet-Draft behavior, provider facts and ATI policy choices.

## 25. Primary references reviewed on 2026-08-14

Stable standards:

- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9309 Robots Exclusion Protocol: https://www.rfc-editor.org/rfc/rfc9309.html
- RFC 9111 HTTP Caching: https://www.rfc-editor.org/rfc/rfc9111.html

Active Web Bot Auth / related drafts:

- Working group: https://datatracker.ietf.org/wg/webbotauth/
- Web Bot Auth architecture: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
- HTTP Message Signatures Directory: https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
- JAFAR IP range format: https://datatracker.ietf.org/doc/draft-illyes-webbotauth-jafar/
- Signature Agent Card / registry: https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/
- Web Bot Auth use cases: https://datatracker.ietf.org/doc/draft-nottingham-webbotauth-use-cases/
- Crawler best practices: https://datatracker.ietf.org/doc/draft-illyes-webbotauth-cbcp/

Provider sources:

- OpenAI SearchBot ranges: https://openai.com/searchbot.json
- OpenAI GPTBot ranges: https://openai.com/gptbot.json
- OpenAI AdsBot ranges: https://openai.com/adsbot.json
- OpenAI crawler guidance: https://help.openai.com/en/articles/20001243-advertiser-guidance-for-allowing-openai-web-crawlers
- Google verification guidance: https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
- Google crawler catalog: https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
- Perplexity crawler documentation: https://docs.perplexity.ai/docs/resources/perplexity-crawlers
- Anthropic crawler documentation: https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
- Cloudflare Web Bot Auth integration notes: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/

Implementation references, not sources of identity truth:

- https://github.com/thibmeu/http-message-signatures-directory
- https://github.com/pyauth/http-message-signatures
- https://github.com/HumanSecurity/human-verified-ai-agent

## 26. Research-derived future opportunities

The following are deliberately deferred but the V1 contracts should not block them:

- a local curated Signature Agent registry with authority-bound metadata;
- controlled consumption of Agent Card `trigger`, purpose, known URLs and rate expectations as contextual features;
- provider change detection and standards-draft drift alerts;
- anonymous/pseudonymous authenticated bot classes for reputation/rate-limit use cases;
- real-time Go/Rust sidecar sharing the same evidence/result schema;
- a conformance CLI that validates third-party JAFAR files, key directories and Agent Cards;
- export adapters for Nginx/Envoy/Cloudflare policy engines after shadow-mode false-positive targets are met.
