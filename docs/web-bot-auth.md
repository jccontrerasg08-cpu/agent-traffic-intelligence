# Web Bot Auth Support

ATI treats RFC 9421 HTTP Message Signatures as the stable cryptographic primitive and the evolving Web Bot Auth documents as versioned application profiles. The exact Internet-Draft revisions implemented by ATI are recorded in `StandardsProfile` and summarized in [`standards-status.md`](standards-status.md).

## Verification chain

A cryptographically valid request is not automatically a verified bot. ATI independently checks:

1. RFC 9421 signature validity.
2. `tag="web-bot-auth"` selection to prevent signature confusion.
3. `created` / `expires` under a bounded ATI validity window.
4. Required signed request components such as `@authority` / `@target-uri`.
5. JWK/key compatibility and active key lifetime where the source format defines one.
6. The discovery/source policy that made the key available.
7. Signed `Signature-Agent` binding when the request uses it.
8. Optional bounded nonce replay detection.
9. Provider/agent authority binding separately from mere key possession.

Only components returned as covered by successful RFC 9421 verification are trusted. Authentication directly affects identity evidence; it does not by itself lower `risk_score` or change automation/AI classification.

## Current `Signature-Agent` profile

The current ATI IETF profile parses `Signature-Agent` as a Structured Fields dictionary and recognizes three explicit discovery types:

- `directory` — the default when `type` is absent;
- `jwks_uri` — a generic RFC 7517 JWK Set;
- `cimd` — Client ID Metadata / Signature Agent Card discovery.

ATI does **not** infer a discovery mechanism from URI path, content type, or response body. Unknown types are unsupported, and malformed current-profile input is not retried as a different legacy syntax.

ATI also keeps a separate `cloudflare-legacy` parser profile for Cloudflare's currently documented deployed structured-string `Signature-Agent` format. Legacy compatibility is opt-in through declarative provider/source configuration; it is not a fallback from the current protocol parser.

## Discovery safety

Normal `ati analyze` never treats a request-controlled URL as an instruction to contact the network.

Configured `directory`, `jwks_uri`, and `cimd` sources are resolved from the local source cache. Remote material must have been obtained through an explicit source-refresh path and must be allowed by the source trust policy. For CIMD that delegates to a nested `jwks_uri`, both the card URI and the nested key URI must be explicitly trusted; the presence of a cached document alone is not authorization.

This means the request-time verification path remains hermetic:

- no arbitrary outbound fetch from `Signature-Agent`;
- no redirects to request-controlled destinations;
- no implicit network access from normal analysis;
- stale, missing, malformed, or unsupported discovery stays neutral/unavailable rather than becoming an identity failure.

## Inline `data:` directories

ATI supports bounded offline `data:` only for `type=directory` with the HTTP Message Signatures Directory JSON media type. Percent-encoded and base64 forms are parsed under a strict size limit.

An inline directory can prove **key possession**, but ATI does not treat a self-contained request-controlled key as proof that a provider or named agent owns that key. Successful inline verification is therefore forced to `BindingScope.KEY`; provider/agent identity remains only claimed until some independent authority-bound chain proves it.

Inline payloads are not persisted in verification evidence. ATI reports a redacted internal source identifier instead of serializing the `data:` URI or its key material. `data:` is not accepted as `jwks_uri` or `cimd` discovery.

## Remote key authority binding

Request-signature verification and source-authority verification are separate layers. A copied public key can still validate a request, so key possession alone does not prove that the copied directory/card URL endorses it.

ATI can persist a privacy-safe `KeyAuthorityBinding` when a directory response is itself successfully verified. The binding records derived facts such as key thumbprint, authority, body digest, verification/expiry time, and profile; raw response signatures are not persisted.

Each configured crypto source declares a response-binding policy:

- `strict_current` — provider/agent scope requires a current matching authority binding; otherwise a successful request signature is downgraded to `KEY` scope.
- `deployed_compatible` — an explicitly configured direct-HTTPS source may keep its configured identity scope for interoperability with documented deployed implementations that do not yet require the stricter response-binding chain.

A `304 Not Modified` may preserve an existing valid cryptographic binding, but it does not renew that binding's cryptographic timestamp or expiry.

## Replay and operational failures

`created` and `expires` are always checked. A nonce can be tracked in the bounded in-process replay cache when configured. ATI does not claim distributed replay prevention.

Timeouts, stale caches, unsupported draft/profile versions, missing optional dependencies, DNS/HTTP failures, and parse execution errors do not automatically mean malicious behavior. They produce neutral/operational verification outcomes and do not directly raise risk.

## Standards drift

Run:

```console
ati standards health
```

to compare ATI's pinned Internet-Draft revisions with the IETF Datatracker directly. The command is explicitly network-capable; it does not rewrite the pins. The scheduled/manual source-health workflow invokes the same check, while normal PR CI remains hermetic.
