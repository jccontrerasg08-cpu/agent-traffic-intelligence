# Source Refresh and Freshness

ATI keeps external identity-source refresh separate from deterministic request analysis. `ati analyze` never downloads identity sources implicitly.

- `offline`: use packaged/local cache only; no DNS or HTTP.
- `hybrid`: use a fresh cache plus provider-documented DNS verification where configured; source refresh remains explicit.
- `live`: currently has the same verifier availability as `hybrid`; source downloads remain an explicit `ati sources refresh` operation.

## Commands

Inspect configured source state:

```console
ati sources status
```

Refresh configured official provider sources explicitly:

```console
ati sources refresh
ati sources refresh --provider google
```

Validate the local cache without network access:

```console
ati sources validate
```

Check the exact Internet-Draft revisions implemented by ATI directly against the IETF Datatracker:

```console
ati standards health
```

`ati standards health` is network-capable, but it is read-only: it reports revision/state drift and never rewrites `StandardsProfile` or provider trust policy.

## Refresh safety

Provider source refresh uses the hardened HTTPS fetcher. It:

- validates the configured URL before connecting;
- rejects loopback, private, link-local, multicast, unspecified, reserved and other non-public addresses;
- re-resolves and revalidates redirect targets when redirects are allowed for that source path;
- pins each connection to an approved resolved public address while preserving TLS hostname verification;
- limits redirects, response size and supported media types;
- validates the fetched document before replacing the previous cache entry;
- uses ETag/Last-Modified conditional requests when cached validators are available;
- never accepts a request-controlled `Signature-Agent` URI as authority to refresh a source.

Client-ID/CIMD retrieval has an even stricter contract: exact `200`, no redirects, HTTPS, and exact character-for-character `client_id` equality with the requested identifier.

## Cache and provenance

The source cache is content-addressed by SHA-256. URLs never become filesystem paths, and manifest writes are atomic. Source documents retain privacy-safe provenance such as canonical URI, provider, binding scope, retrieval time, source creation time where published, freshness, validators, SHA-256, parser profile, validation status, and acquisition mode.

Raw response signatures are not persisted. When ATI successfully verifies a signed key-directory response, it may retain a derived `KeyAuthorityBinding` containing the key thumbprint, authority, body digest, verification/expiry time, and profile.

A `304 Not Modified` can preserve an existing still-valid authority binding; it does not renew the original cryptographic verification time or expiry.

## Dynamic discovery is cache-only at request time

`directory`, `jwks_uri`, and `cimd` discovery used while analyzing traffic resolves from the local cache. A request does not cause an arbitrary outbound fetch.

For a CIMD card that delegates key discovery to a nested `jwks_uri`, both the card URI and the nested JWK Set URI must be explicitly authorized by the source trust policy. Cached content is not an allowlist.

Inline `data:` directories are a separate bounded offline path. They are accepted only as directory discovery, are never fetched, and can authenticate only `KEY` scope unless an independent authority-bound chain exists.

## Response-binding policy

Configured crypto sources declare one of two authority-binding policies:

- `strict_current`: provider/agent scope requires a current matching cryptographic `KeyAuthorityBinding`; otherwise successful request authentication is downgraded to `KEY` scope.
- `deployed_compatible`: explicitly configured direct-HTTPS material may retain its configured identity scope for documented deployed interoperability.

Do not change this policy merely because an upstream endpoint is reachable. Policy changes require primary-source review, tests, and an explicit repository change.

## Scheduled/manual health

`.github/workflows/source-health.yml` is intentionally schedule/manual-only and read-only. It:

1. runs `ati standards health` against the constrained Datatracker API;
2. refreshes configured official identity sources;
3. validates the resulting cache offline;
4. prints provenance-safe source status.

Scheduled source-health checks belong outside merge-blocking PR CI. A standards revision/state change returns a review-required failure instead of silently updating pins. Provider/schema drift should likewise produce a reviewable failure or follow-up change, not an automatic trust-policy rewrite. PR CI remains hermetic and does not depend on live provider or IETF endpoints.
