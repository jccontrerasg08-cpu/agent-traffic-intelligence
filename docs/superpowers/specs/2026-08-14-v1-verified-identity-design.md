# V1 Verified Identity Design

**Status:** Draft for written review; conceptual architecture approved
**Date:** 2026-08-14
**Branch:** `design/v1-verified-identity`

## 1. Objective

V1 adds verifiable machine identity to Agent Traffic Intelligence (ATI) while preserving the V0 invariants:

- observe-only operation;
- no enforcement side effects;
- four independent outputs: `automation_score`, `ai_score`, `identity_confidence`, and `risk_score`;
- explainable evidence for every identity decision;
- no raw client IPs, credentials, request bodies, cookie values, or query-string values in serialized detections;
- no claim that an exact foundation model can be inferred from network traffic without explicit evidence;
- existing `ati analyze` behavior remains offline and backward compatible unless identity verification is explicitly enabled.

V1 develops two verification tracks in parallel behind one common interface:

1. **Network identity** — official IP ranges plus provider-documented forward-confirmed reverse DNS (FCrDNS).
2. **Cryptographic identity** — RFC 9421 HTTP Message Signatures plus the emerging Web Bot Auth directory and `Signature-Agent` conventions.

The tracks are independent. One may succeed while another is unavailable. Their evidence is resolved centrally instead of being collapsed into a single `bot=true` flag.

## 2. Research conclusions

The Web Bot Auth ecosystem is active and changed materially during 2026. ATI should track standards instead of inventing equivalent private protocols.

As reviewed on 2026-08-14:

- **RFC 9421** is the stable standards-track baseline for HTTP Message Signatures.
- **`draft-meunier-http-message-signatures-directory-05`** defines an HTTP Message Signatures key directory and `Signature-Agent` discovery conventions.
- **`draft-meunier-web-bot-auth-architecture-05`** defines the current Web Bot Auth architecture profile.
- **`draft-illyes-webbotauth-jafar-00`** defines a JSON format for publishing IP ranges of automated HTTP clients.
- **`draft-meunier-webbotauth-registry-02`** defines the emerging Signature Agent Card and registry metadata.
- **`draft-nottingham-webbotauth-use-cases-02`** documents bot-authentication use cases.
- **`draft-illyes-webbotauth-cbcp-00`** documents crawler best practices.

Internet-Drafts are works in progress. ATI MUST isolate draft-specific parsing and rules behind versioned profiles so a draft revision cannot silently change ATI's stable domain model.

The project also reviewed current public implementations and examples, including:

- `thibmeu/http-message-signatures-directory` for the active draft source tree;
- `pyauth/http-message-signatures` for maintained Python RFC 9421 support;
- `HumanSecurity/human-verified-ai-agent` for separation of key management, signing, and orchestration.

These are research and interoperability references, not identity authorities. ATI will not copy their implementation code.

## 3. Current provider facts and source hierarchy

Identity evidence has an explicit trust hierarchy. A source can be authoritative for one property and non-authoritative for another.

### 3.1 Protocol authority

1. Published RFCs.
2. Version-pinned IETF Internet-Drafts, explicitly labeled work in progress.

### 3.2 Provider authority

3. Provider-owned documentation.
4. Provider-owned machine-readable endpoints.
5. Provider-published DNS naming rules.

### 3.3 Current provider snapshot

The following facts were re-verified during the spec self-review on 2026-08-14:

- **OpenAI** publishes crawler-specific JSON range files for `OAI-SearchBot`, `GPTBot`, and `OAI-AdsBot` at `searchbot.json`, `gptbot.json`, and `adsbot.json`. These currently use a `creationTime` plus `prefixes` structure.
- **Google** publishes separate CIDR JSON sets for common crawlers, special crawlers, user-triggered fetchers, and user-triggered agents. Google also documents reverse-DNS masks and explicitly requires reverse lookup followed by forward confirmation for manual DNS verification.
- **Perplexity** publishes separate current IP lists for `PerplexityBot` and `Perplexity-User` and recommends combining User-Agent and source IP.
- **Anthropic** now publishes crawler IP ranges at `https://claude.com/crawling/bots.json`, linked from its current crawler documentation. The file observed during this review has `creationTime` `2026-08-13T20:38:01Z` and a `prefixes` array. This is provider-level crawler infrastructure evidence; the current document does not, by itself, distinguish `ClaudeBot`, `Claude-SearchBot`, and `Claude-User` at the individual-agent level.
- **Cloudflare** has deployed signed agents visible in its bot directory and documents production Web Bot Auth integration. These provide useful real-world interoperability targets for ATI's cryptographic track.

This provider snapshot is documentation, not hard-coded truth. Runtime verification uses versioned source profiles and freshness metadata.

## 4. Core semantic model

V1 distinguishes concepts that must not be conflated:

1. **Claim** — what a request says it is, for example `User-Agent: GPTBot`.
2. **Authentication evidence** — evidence that the request controls an expected network origin or cryptographic key.
3. **Binding evidence** — evidence connecting that authenticated network/key identity to a provider or specific agent.
4. **Metadata** — purpose, trigger, robots behavior, expected rate, known URLs, and similar Agent Card fields.
5. **Risk** — observed behavior that is abusive or operationally dangerous.

A valid signature proves possession of a key; it does not automatically prove a friendly display name belongs to a real-world company. Likewise, a verified provider does not imply a specific agent was verified, and a verified identity does not imply low risk.

## 5. Verification scope

Every positive or negative identity assertion carries a binding scope:

- `KEY` — proves control of a cryptographic key only;
- `PROVIDER` — binds evidence to an operator/provider but not a specific agent;
- `AGENT` — binds evidence to the specific claimed automated agent/product.

This distinction prevents overclaiming. For example, Anthropic's current shared crawler IP list can establish provider-level evidence, but it does not alone prove whether the request is `ClaudeBot` or `Claude-User`.

`VerificationEvidence` therefore includes `binding_scope`, `authority`, and `subject` fields. The final verification payload separately exposes provider-level and agent-level resolution.

## 6. Architecture

```text
raw log record / trusted edge event
          |
          +-------------------------------+
          |                               |
          v                               v
 privacy normalizer               VerificationContext
          |                        ephemeral / non-exportable
          v                               |
   RequestEvent                           |
          |                               |
          +---------------+---------------+
                          v
                 IdentityClaim matcher
                          |
                          v
                 VerificationManager
                 /                  \
                /                    \
       network verification      crypto verification
       - source provenance       - RFC 9421
       - official ranges         - Web Bot Auth profile
       - FCrDNS                  - Signature-Agent
       - provider profile        - key directory/JWKS
                \                    /
                 \                  /
                  +--------+-------+
                           v
                 VerificationEvidence[]
                           |
                           v
                  IdentityResolver
                           |
             +-------------+-------------+
             |             |             |
          verified      conflicted    claimed/failed
             |             |             |
             +-------------+-------------+
                           v
                  explainable Detection
```

## 7. Privacy-preserving ingestion boundary

### 7.1 Problem

V0 deliberately pseudonymizes and discards raw client addresses while creating `RequestEvent`. Network verification needs the source address. Cryptographic verification may need the original authority, request target, and selected covered headers.

Putting those fields back into `RequestEvent` would break the V0 privacy contract.

### 7.2 Decision: ephemeral `VerificationContext`

An input adapter produces two logical views:

- a serializable, privacy-minimized `RequestEvent`;
- a non-serializable `VerificationContext` used only by verification.

`VerificationContext` may contain only what verification requires:

- observed transport peer address;
- trusted edge-asserted client address when configured;
- provenance of the selected source address;
- original authority/host;
- HTTP method and request-target components needed by RFC 9421;
- only headers necessary to reconstruct covered signature components;
- `Signature`, `Signature-Input`, and `Signature-Agent` when present;
- adapter trust metadata.

It MUST NOT appear in:

- `Detection.to_dict()`;
- exported JSONL;
- normal logs;
- exception text containing raw values;
- persistent evidence manifests;
- shareable cache keys.

After verification, only privacy-safe derived facts survive, such as provider, agent, method, matched source digest, binding scope, and freshness timestamps.

## 8. Source-address provenance and proxy trust

`remote_addr` does **not** automatically mean end-user/client IP. It normally represents the directly observed transport peer or whatever the producing edge server defines it to mean.

ATI models source provenance explicitly:

- `direct_peer` — address of the directly connected peer;
- `trusted_edge_client` — client address asserted by a specifically configured trusted edge/CDN adapter;
- `forwarded_untrusted` — forwarded value present but not trusted;
- `unknown` — provenance cannot be established.

Forwarded headers such as `X-Forwarded-For`, `Forwarded`, and vendor-specific client-IP headers MUST NOT be trusted by default.

A trusted-proxy policy may walk a forwarded chain only if:

1. the directly connected peer is in an explicitly configured trusted-proxy set; and
2. the adapter defines the provider-specific forwarding semantics.

Network identity verification does not return a positive result from `forwarded_untrusted` provenance.

IPv4 and IPv6 are required. IPv4-mapped IPv6 addresses are normalized carefully before matching.

## 9. Verification result model

### 9.1 Final identity states

Extend `VerificationState` with:

- `NONE`
- `CLAIMED`
- `VERIFIED`
- `FAILED`
- `CONFLICTED`

### 9.2 Per-method outcomes

Each verifier returns one of:

- `PASS`
- `MISMATCH`
- `UNAVAILABLE`
- `INDETERMINATE`
- `STALE`
- `ERROR`

`ERROR` means the verifier failed to execute reliably; it never means the client is malicious.

### 9.3 Verification evidence

Each immutable `VerificationEvidence` record contains at least:

- verification method;
- outcome;
- binding scope;
- claimed provider/agent where applicable;
- authenticated authority/subject where known;
- human-readable explanation;
- official source URI or stable source identifier;
- source format and parser/profile version;
- source `retrieved_at` and `expires_at` where known;
- SHA-256 digest of source material where applicable;
- privacy-safe structured details;
- optional contribution to `identity_confidence` only.

A verifier never changes `automation_score`, `ai_score`, or `risk_score` merely because identity authentication passed or failed.

## 10. Provider verification profiles

Most provider behavior should be **data-driven**, not one Python module per company.

V1 adds a versioned, schema-validated provider verification profile resource containing data such as:

- provider identifier;
- related curated agent tokens;
- official range source URLs;
- source format profile;
- binding scope (`PROVIDER` or `AGENT`);
- which agents a source applies to;
- documented FCrDNS hostname patterns;
- whether absence from a published source is authoritative negative evidence or only indeterminate;
- trusted Signature-Agent/key-directory origins where curated;
- official documentation URL;
- last human verification date.

Simple source changes therefore update data and provenance instead of application logic. Provider-specific Python adapters are introduced only when documented behavior genuinely cannot be represented by the profile schema.

Proposed files:

```text
src/agent_traffic_intelligence/identity/
  profiles.py
  verification_profiles.json
```

The existing `agents.json` remains the User-Agent claim registry. V1 does not overload it with network or crypto policy.

## 11. Network verification track

Proposed modules:

```text
identity/network/
  source_address.py
  ranges.py
  fcrdns.py
  verifier.py
  formats/
    jafar.py
    prefixes_v1.py
```

### 11.1 Normalized range model

All external IP publications normalize into `PublishedRangeSet` objects independent of source JSON shape.

Supported formats:

1. the pinned JAFAR profile;
2. provider documents using `creationTime` plus `prefixes` with `ipv4Prefix` / `ipv6Prefix`;
3. narrowly scoped special adapters only if required by official provider formats.

Unknown fields are ignored where the source format specifies forward compatibility. Invalid prefixes surface diagnostics instead of being silently trusted.

For overlapping prefixes with different metadata, the most-specific matching network wins, consistent with the current JAFAR design.

### 11.2 Source freshness

Range sources preserve:

- publisher `creationTime` where supplied;
- retrieval time;
- `ETag`;
- `Last-Modified`;
- `Cache-Control` freshness;
- content type;
- SHA-256 digest;
- source/profile version;
- validation result.

Conditional HTTP requests use `If-None-Match` and/or `If-Modified-Since` when live source refresh is enabled.

Polling respects provider guidance and HTTP caching. External-source health checks are never merge-blocking deterministic PR tests.

### 11.3 FCrDNS

FCrDNS is provider-policy driven:

1. reverse-resolve the selected trusted source address;
2. require a hostname matching a provider-documented suffix/pattern;
3. forward-resolve that hostname;
4. require the original address to appear in the returned A/AAAA set.

PTR alone never verifies identity.

DNS timeout, NXDOMAIN, temporary failure, or absence of a documented provider policy produces `UNAVAILABLE` or `INDETERMINATE`, not `FAILED`.

### 11.4 Current provider behavior

- **Google** — range verification plus documented FCrDNS patterns; category-specific range sources are represented explicitly.
- **OpenAI** — crawler-specific official range sources; no undocumented rDNS rule is inferred.
- **Perplexity** — separate official `PerplexityBot` and `Perplexity-User` range sources.
- **Anthropic** — current `claude.com/crawling/bots.json` is supported as provider-level crawler infrastructure evidence unless/until Anthropic publishes finer-grained service binding.

## 12. Negative-evidence semantics

A range miss is not universally equivalent to an identity failure.

Every source profile therefore defines its negative semantics:

- `authoritative_negative` — official documentation states the list defines the valid population for this binding;
- `positive_only` — a match is useful positive evidence, but a miss is not enough to disprove the claim;
- `unknown` — ATI lacks enough documentation to interpret a miss.

This policy is versioned and sourced. It prevents ATI from turning a provider's incomplete or operational list into an unsupported accusation.

## 13. Cryptographic verification track

Proposed modules:

```text
identity/crypto/
  verifier.py
  rfc9421.py
  web_bot_auth.py
  key_resolver.py
  directory.py
  agent_card.py
  replay.py
```

### 13.1 Stable protocol boundary

RFC 9421 defines HTTP Message Signature canonicalization and verification. ATI MUST NOT invent a signature format or hand-roll canonicalization if a suitable audited implementation is available.

The leading implementation candidate reviewed is the Apache-2.0 `pyauth/http-message-signatures` package. ATI wraps it behind its own protocol adapter rather than exposing third-party classes in public ATI APIs.

The base V0 installation keeps zero third-party runtime dependencies. Cryptographic verification is enabled through an optional extra:

```text
agent-traffic-intelligence[verification]
```

The implementation plan will pin a compatible major version and add supply-chain checks before adoption.

### 13.2 “See what is signed”

Downstream identity logic trusts only request components proven covered by the successfully verified RFC 9421 signature.

A valid signature adjacent to an unsigned `Signature-Agent`, authority, or identity-bearing header MUST NOT cause ATI to trust that unsigned value.

Multiple signatures are label-aware. ATI does not simply accept “any valid signature” without binding the selected signature input, tag, key, and covered components.

## 14. Standards profiles

Web Bot Auth drafts and deployed implementations can temporarily differ. ATI therefore introduces a `StandardsProfile` boundary.

A profile fixes:

- RFC/draft identifier and revision;
- expected signature `tag`;
- required covered components;
- time-window rules;
- supported algorithms;
- `Signature-Agent` encoding/discovery rules;
- key-directory media type and validation rules;
- Agent Card revision where enabled.

Initial profiles should include:

- `ietf-current-2026-08-14` — pinned to the current IETF drafts reviewed above;
- an interoperability profile only if needed for a deployed implementation that has not yet moved to the latest draft.

A profile change requires tests and a documented source update; it is never silently pulled from the Internet into running policy.

## 15. Web Bot Auth verification

For a request to produce Web Bot Auth `PASS` evidence, ATI validates at minimum:

- RFC 9421 signature validity;
- expected profile `tag`;
- `created` and `expires` policy;
- key identifier/thumbprint consistency;
- required covered derived component such as `@authority` or `@target-uri` according to the active profile;
- coverage of `Signature-Agent` when that field participates in discovery/binding;
- algorithm allowlist;
- key validity for the request time;
- directory-to-authority binding required by the active profile.

A cryptographically valid RFC 9421 signature that does not satisfy the Web Bot Auth application profile is not a verified Web Bot Auth identity.

## 16. Key directory

The directory adapter handles the pinned HTTP Message Signatures Directory profile:

- JWKS parsing;
- HTTPS discovery;
- JWK thumbprints;
- key validity metadata where present;
- overlapping key rotation;
- freshness/caching;
- directory response signatures/binding when required;
- multiple keys without label confusion.

Directory integrity, key possession, and directory-to-provider binding are separate facts and separate evidence.

ATI stores public keys only. Private signing keys are never needed by the verifier and MUST NOT appear in repository fixtures except obviously synthetic test-only keys generated specifically for tests.

## 17. Safe `Signature-Agent` discovery

An attacker controls request headers. Automatically fetching arbitrary `Signature-Agent` URLs would create an SSRF-capable network primitive.

V1 therefore defaults to **`registry_only` discovery**:

- directories associated with curated provider/agent profiles may be fetched when network mode permits it;
- unknown `Signature-Agent` URLs are parsed but not fetched automatically;
- result: `UNAVAILABLE`, with evidence explaining the discovery policy.

A future experimental `public_https` discovery mode is out of scope until ATI has a hardened network fetcher that enforces all of:

- HTTPS only;
- no embedded credentials;
- no loopback, private, link-local, multicast, unspecified, or otherwise non-public destination;
- redirect revalidation on every hop;
- strict connection/read timeout;
- bounded response size;
- TLS certificate validation;
- media-type validation;
- bounded redirects;
- DNS-rebinding-resistant destination validation.

## 18. Replay handling

Signature validity and replay safety are different concepts.

V1 validates the profile's `created`/`expires` window. Nonces are exposed as privacy-safe verification metadata when present.

When replay checking is enabled, a bounded in-process cache may reject repeated `(keyid, nonce)` combinations during their validity window.

Persistent/distributed replay databases belong to a future real-time sensor and are not required for offline V1 analysis.

## 19. Signature Agent Card

ATI parses a pinned subset of the emerging Signature Agent Card, including where available:

- client name/URI;
- contact data;
- expected User-Agent;
- RFC 9309 product token/compliance;
- trigger (`crawler` vs user-triggered `fetcher`);
- purpose;
- targeted content;
- rate-control and expected rate;
- known URL patterns;
- `jwks_uri`;
- `ips_uri`;
- embedded public keys where allowed.

Metadata receives an explicit trust class:

- `self_asserted`;
- `authority_bound`.

Self-asserted purpose or friendliness never reduces `risk_score`. Agent Card data becomes useful context only after authority/binding is established and later behavioral calibration validates how it should influence detection.

## 20. External-source cache and provenance

A shared source subsystem serves IP lists, key directories, Agent Cards, and versioned standards metadata.

Proposed modules:

```text
identity/sources/
  models.py
  cache.py
  fetcher.py
  manifest.py
  trust.py
```

Each cached source records:

- canonical URI;
- source type;
- provider/authority;
- binding scope;
- retrieval timestamp;
- source-provided creation timestamp;
- freshness/expiry;
- ETag / Last-Modified;
- SHA-256 digest;
- content type;
- parser/profile version;
- validation status.

Cache objects are content-addressed where practical. Detection output references digest/timestamps rather than embedding entire remote documents.

Cache data lives outside normal project output by default.

## 21. Offline, live, and hybrid modes

Network activity must never be surprising.

V1 defines:

- `offline` — local snapshots/cache only; no DNS or HTTP;
- `live` — DNS and approved official-source fetching allowed under policy;
- `hybrid` — fresh cache first, live refresh/resolve only when required.

Default `ati analyze` remains the existing V0 offline path.

Exact CLI contract for V1:

```text
ati analyze INPUT --verify-identity --verification-mode offline|hybrid|live
ati sources status
ati sources refresh [--provider PROVIDER]
ati sources validate
```

Rules:

- `--verify-identity` is explicit opt-in;
- verification mode defaults to `offline` when verification is enabled;
- `sources refresh` is explicitly network-capable;
- normal analysis never refreshes trust policy itself;
- provider/source updates are inspectable and provenance-bearing.

## 22. Verification manager and concurrency

`VerificationManager` receives:

- an `IdentityClaim`;
- privacy-safe `RequestEvent`;
- ephemeral `VerificationContext`;
- verification policy/profile;
- source/cache interfaces.

Independent verification methods run concurrently with bounded concurrency:

- range lookup;
- FCrDNS;
- RFC 9421 verification;
- cached directory validation.

Source refreshes are deduplicated by canonical source identity. One timeout cannot block all verification indefinitely.

Verifiers never mutate shared identity state. They return immutable evidence. A single `IdentityResolver` produces the final resolution in deterministic evidence order.

## 23. Identity resolution policy

Resolution is explicit and testable.

### 23.1 Provider vs agent

- `PROVIDER`-scope `PASS` sets `provider_verified=true` but does not by itself mark the exact agent verified.
- `AGENT`-scope `PASS` can set `agent_verified=true` when its authority is trusted.
- `KEY`-scope `PASS` proves key possession only until a trusted directory/profile binds that key to a provider/agent.

### 23.2 Final state rules

`VERIFIED` requires an authority-bound `AGENT`-scope positive result, or an equivalent cryptographic chain that binds the request key to the exact agent identity.

`CLAIMED` remains appropriate when:

- only User-Agent evidence exists; or
- only provider-level identity is verified while the exact agent remains a claim.

`FAILED` requires an applicable authoritative identity check to contradict the claim under a profile whose negative semantics permit that conclusion. Timeouts, stale data, unsupported methods, and missing data never produce `FAILED`.

`CONFLICTED` is returned when strong authority-bound evidence cannot be reconciled, for example:

- User-Agent/provider A with an agent-bound cryptographic identity for provider B;
- two agent-bound cryptographic identities disagree;
- a mandatory authoritative agent-level source contradicts a different agent-level `PASS`.

### 23.3 Example outcomes

**UA only** → `CLAIMED`.

**Anthropic UA + shared Anthropic crawler-range match** → provider verified; exact agent remains `CLAIMED` unless another method binds it.

**Google crawler claim + agent/category-authoritative range or documented FCrDNS policy that binds the claim** → may reach `VERIFIED` according to the provider profile.

**Valid RFC 9421 signature without trusted key-to-agent binding** → key authenticated, identity not yet `VERIFIED`.

**Valid Web Bot Auth chain with trusted/bound directory** → `VERIFIED`.

**Range miss with `positive_only` source** → `INDETERMINATE`, not failure.

**DNS timeout** → `UNAVAILABLE`, no risk penalty.

**Valid crypto identity plus optional network miss** → keep both evidence items; crypto may still verify if the network list was not authoritative-negative.

## 24. Scoring integration

The final discrete verification resolution and continuous `identity_confidence` remain distinct.

Verification evidence may move `identity_confidence` strongly, but:

- identity evidence does not directly change `risk_score`;
- identity evidence does not directly change `automation_score` or `ai_score` beyond existing claim/taxonomy evidence;
- multiple correlated verification methods are not naively multiplied as if statistically independent;
- provider-only verification is capped below exact agent verification by scoring policy.

The exact numeric weights/caps are implementation-plan details and require tests; the semantic ordering above is fixed.

## 25. Backward compatibility and schema evolution

V1 is additive.

- `ati analyze` without verification flags preserves V0 behavior.
- `RequestEvent` remains privacy-minimized and does not gain raw addresses or secret headers.
- `VerificationState.CONFLICTED` is an enum extension.
- `Detection` gains an optional `verification` payload.
- When verification is disabled, default V0 serialization remains unchanged.
- The verification payload has its own explicit schema version.

Proposed verification payload shape:

```json
{
  "schema_version": 1,
  "state": "verified",
  "provider_verified": true,
  "agent_verified": true,
  "provider": "example",
  "agent": "ExampleBot",
  "methods": [],
  "conflicts": []
}
```

No raw IP, full signature value, Authorization/Cookie value, or private key is permitted in this payload.

## 26. Proposed module map

```text
src/agent_traffic_intelligence/
  identity/
    __init__.py
    context.py
    models.py
    manager.py
    resolver.py
    policy.py
    profiles.py
    standards.py
    verification_profiles.json
    network/
      source_address.py
      ranges.py
      fcrdns.py
      verifier.py
      formats/
        jafar.py
        prefixes_v1.py
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

Files should be collapsed if implementation would otherwise create trivial forwarding modules. The required architectural boundaries are contracts/resolution, provider profiles, network verification, cryptographic verification, and external-source provenance.

## 27. Documentation set

V1 adds or materially updates:

- `docs/identity-verification.md` — operator mental model and result interpretation;
- `docs/provider-verification.md` — provider capability/source matrix and binding scope;
- `docs/web-bot-auth.md` — supported RFC/draft profiles and limitations;
- `docs/standards-status.md` — exact tracked RFC/draft revisions and review dates;
- `docs/source-trust-policy.md` — hierarchy, negative semantics, and authority rules;
- `docs/source-refresh.md` — cache, freshness, conditional requests, and offline/live behavior;
- `docs/privacy-network-data.md` — ephemeral source-address/header handling;
- `docs/conformance.md` — what ATI validates and what it deliberately does not claim;
- `docs/threat-model.md` — SSRF, replay, signature confusion, stale sources, DNS spoofing/rebinding, proxy spoofing, source compromise;
- `SECURITY.md` — live verification and key/source compromise operational warnings;
- ADR: ephemeral `VerificationContext`;
- ADR: optional crypto dependency boundary;
- ADR: registry-only `Signature-Agent` fetching;
- ADR: provider-vs-agent binding scope.

Provider documentation MUST distinguish current facts from assumptions and record source dates.

## 28. Testing strategy

No deterministic unit/integration test depends on live Internet or real DNS.

### 28.1 Network tests

Test at minimum:

- IPv4 and IPv6 CIDR matches;
- IPv4-mapped IPv6 normalization;
- malformed and overlapping ranges;
- most-specific match behavior;
- JAFAR unknown-field forward compatibility;
- `creationTime` and freshness parsing;
- source negative semantics;
- provider-vs-agent binding scope;
- FCrDNS reverse + forward confirmation;
- PTR-only spoof attempts;
- proxy/forwarded-header spoofing;
- unavailable DNS behavior;
- stale source behavior;
- privacy-safe serialization.

Provider fixtures include deterministic snapshots modeled from current official OpenAI, Google, Perplexity, and Anthropic formats, with source URL/date/digest metadata.

### 28.2 RFC 9421 / Web Bot Auth tests

Use standards-derived vectors plus independently created negative cases for:

- valid signature;
- modified covered component;
- valid signature over insufficient/wrong components;
- stale or implausibly future timestamps;
- wrong tag;
- key-id/thumbprint mismatch;
- unsupported algorithm;
- duplicate/ambiguous labels;
- multiple-signature confusion;
- malformed Structured Fields;
- key rotation overlap;
- replayed nonce;
- unsigned `Signature-Agent` substitution;
- directory-authority mismatch;
- valid key possession without provider/agent binding.

Do not copy third-party fixture corpora without license review.

### 28.3 Source-fetch security tests

Live-source policy tests reject or safely handle:

- disallowed scheme;
- embedded credentials;
- loopback/private/link-local/multicast/unspecified destinations;
- redirects to a disallowed address;
- excessive redirects;
- oversized responses;
- wrong content type;
- malformed JSON/JWKS;
- stale cache;
- unsupported future major source versions.

### 28.4 Property/fuzz tests

A dev-only property-testing dependency such as Hypothesis may be adopted for parsers/state combinations without affecting runtime dependencies.

High-value fuzz/property targets:

- CIDR normalization;
- JAFAR/prefix document parsing;
- Structured Fields boundaries;
- URI parsing and discovery policy;
- resolver state combinations;
- serialization privacy invariants.

## 29. Real-world interoperability fixtures

V1 should include at least one **offline** fixture based on a currently deployed signed-agent/key-directory example, such as a Cloudflare-published signed agent, with retrieval date and digest.

The fixture is for interoperability/conformance testing only. CI does not contact the live directory.

A scheduled source-health job may report when the live directory or profile has changed so the fixture can be reviewed deliberately.

## 30. CI and source-health separation

Deterministic PR CI remains hermetic and covers two installation modes:

### Core matrix

- zero third-party runtime dependency install;
- Ruff;
- Mypy;
- V0/V1 non-crypto tests;
- coverage;
- package build/install smoke;
- CLI smoke.

### Verification-extra matrix

- install `[verification]`;
- RFC 9421/Web Bot Auth tests;
- all relevant type/lint checks;
- dependency/supply-chain validation.

Security automation continues with CodeQL and dependency review. A Python dependency vulnerability check may be added for the verification extra.

### Scheduled/manual source-health workflow

External network checks are separated from PR CI and may check:

- official endpoints reachable;
- source schema still parseable;
- source digest/freshness changed;
- current IETF draft revision changed;
- provider documentation/capability changed;
- curated Signature-Agent directory changed.

A source-health failure is not reported as a deterministic product-test failure.

Automation may open a review PR for source/profile changes; it MUST NOT silently rewrite trust policy on `main`.

## 31. Parallel implementation plan boundary

Implementation becomes parallel only after shared contracts are frozen.

### Slice 0 — shared contracts (serialized)

Freeze and test:

- `VerificationContext`;
- `VerificationEvidence` and binding scope;
- method outcomes;
- provider profile schema;
- `StandardsProfile`;
- resolver API/rules;
- source/cache interfaces;
- backward-compatibility behavior.

### Track A — network

Owns `identity/network/**`, provider profile network fields, and dedicated tests.

### Track B — cryptographic

Owns `identity/crypto/**`, verification-extra dependency integration, and dedicated tests.

### Track C — sources/provenance

Owns `identity/sources/**`, cache/freshness logic, and source manifests after shared interfaces freeze.

### Track D — docs/conformance

Owns documentation, schema files, provider capability matrix, deterministic provider fixtures, and signed-agent interoperability fixtures.

### Integration — serialized

One integration owner connects tracks to `Detector`, CLI, serialization, and scoring, resolves overlap, and runs the full matrix.

Parallel writers do not edit the same shared contract or schema simultaneously.

## 32. Non-goals for V1

- production blocking, challenge, or rate-limit enforcement;
- provider attribution from ASN/cloud hosting alone;
- exact LLM/model attribution from network traffic;
- treating Agent Card metadata as trusted solely because it is published;
- arbitrary automatic fetching of unknown `Signature-Agent` URLs;
- persistent distributed replay databases;
- browser JavaScript fingerprint collection;
- ML calibration or anomaly clustering;
- authentication of the end user behind an AI agent;
- anonymous/pseudonymous bot authorization protocols.

## 33. Acceptance criteria

V1 is complete only when all of the following are freshly demonstrated:

1. Existing V0 default analysis remains offline and backward compatible.
2. Raw source IPs and signature-sensitive values never appear in serialized detections or normal logs.
3. Source-address provenance prevents untrusted forwarded headers from driving positive verification.
4. Official-format adapters work from deterministic OpenAI, Google, Perplexity, and Anthropic fixtures.
5. Anthropic's shared crawler range fixture produces provider-scope evidence without falsely verifying an exact Claude agent.
6. Google-style FCrDNS passes only after reverse and forward confirmation.
7. Provider source profiles preserve official source URI, review date, binding scope, negative semantics, freshness, and SHA-256 provenance.
8. RFC 9421 verification passes valid standards-derived vectors and rejects tampered/insufficiently-covered vectors.
9. Web Bot Auth profile validation checks tag, validity window, key identity, covered components, directory binding, and algorithm policy.
10. Unknown `Signature-Agent` input cannot trigger arbitrary outbound requests under the default policy.
11. At least one current deployed signed-agent directory is represented by an offline interoperability fixture.
12. Network and cryptographic methods can execute independently/concurrently with deterministic evidence ordering.
13. Provider-level `PASS` is distinguishable from exact-agent `PASS`.
14. Conflicting strong authority-bound evidence results in `CONFLICTED` without discarding either source.
15. Timeouts, stale data, unsupported methods, and source errors cannot become risk penalties or false identity failures.
16. External source snapshots carry freshness, profile version, and SHA-256 provenance.
17. Core installation remains usable with zero third-party runtime dependencies.
18. Verification-extra installation and tests are green on all supported Python versions.
19. Live source-health monitoring remains separate from deterministic PR CI.
20. Documentation clearly distinguishes RFC requirements, Internet-Draft behavior, provider facts, self-asserted metadata, and ATI policy choices.

## 34. Primary references reviewed on 2026-08-14

### Stable standards

- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9309 Robots Exclusion Protocol: https://www.rfc-editor.org/rfc/rfc9309.html
- RFC 9111 HTTP Caching: https://www.rfc-editor.org/rfc/rfc9111.html

### Active IETF work

- Web Bot Auth WG: https://datatracker.ietf.org/wg/webbotauth/
- Web Bot Auth architecture: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
- HTTP Message Signatures Directory: https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
- JAFAR: https://datatracker.ietf.org/doc/draft-illyes-webbotauth-jafar/
- Signature Agent Card / registry: https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/
- Web Bot Auth use cases: https://datatracker.ietf.org/doc/draft-nottingham-webbotauth-use-cases/
- Crawler best practices: https://datatracker.ietf.org/doc/draft-illyes-webbotauth-cbcp/

### Provider sources

- OpenAI SearchBot ranges: https://openai.com/searchbot.json
- OpenAI GPTBot ranges: https://openai.com/gptbot.json
- OpenAI AdsBot ranges: https://openai.com/adsbot.json
- OpenAI crawler guidance: https://help.openai.com/en/articles/20001243-advertiser-guidance-for-allowing-openai-web-crawlers
- Google verification: https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
- Google crawler catalog: https://developers.google.com/crawling/docs/crawlers-fetchers/overview-google-crawlers
- Perplexity crawler documentation: https://docs.perplexity.ai/docs/resources/perplexity-crawlers
- Anthropic crawler documentation: https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
- Anthropic crawler ranges: https://claude.com/crawling/bots.json
- Cloudflare Web Bot Auth: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/

### Implementation references, not identity truth

- https://github.com/thibmeu/http-message-signatures-directory
- https://github.com/pyauth/http-message-signatures
- https://github.com/HumanSecurity/human-verified-ai-agent

## 35. Deferred opportunities

V1 contracts should not block later work on:

- a local curated Signature Agent registry with authority-bound metadata;
- a conformance CLI for JAFAR, key directories, Agent Cards, and Web Bot Auth requests;
- standards/provider drift alerts and review PRs;
- contextual use of authority-bound Agent Card purpose/rate/known-URL metadata after calibration;
- anonymous/pseudonymous authenticated-bot classes for reputation/rate-limit systems;
- a real-time Go/Rust sidecar sharing the same evidence/result schema;
- Nginx/Envoy/Cloudflare policy export adapters after shadow-mode false-positive targets are met;
- ML calibration, unknown-agent clustering, and concept-drift monitoring in V2.
