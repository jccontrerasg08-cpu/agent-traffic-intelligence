# ADR 0009: A range snapshot vouches for a fixed period, not for its HTTP freshness

## Status

Accepted.

## Context

Official IP-range verification answers one question: *was this request's source address
in the provider's published list when the request was made?* ATI answers it from a
snapshot of the list taken by `ati sources refresh`, and must decide how long that
snapshot may keep answering.

ATI used the response's HTTP `Cache-Control: max-age` for that decision. Measured on
2026-10-05, no configured provider sends a header that means what ATI needed:

| Provider | Range lists | Header | Effect |
|---|---|---|---|
| OpenAI | 3 | `public, max-age=0, must-revalidate` | expired on arrival, so verification **never** passed |
| Google | 5 | `no-cache, must-revalidate` | no expiry, so a snapshot of any age **always** vouched |
| Perplexity | 2 | none | no expiry, as above |

Both failures came from one mistake. HTTP freshness tells a cache when it must revalidate
before reusing a response. It says nothing about how long a published list of addresses
remains true.

## Decision

- A cached **IP-range snapshot** may verify requests for `RANGE_SNAPSHOT_VALIDITY`
  (7 days) after ATI retrieved it, whatever its HTTP headers say. Seven days matches the
  weekly scheduled refresh in `.github/workflows/source-health.yml`. A `304 Not Modified`
  renews the period, because the provider has confirmed the list is unchanged.
- A **key directory** keeps HTTP freshness. A directory's `max-age` is how a signer
  announces key rotation, which is exactly the question being asked.
- A snapshot past its period gives a neutral `stale` outcome, never an identity failure.

## Consequences

- OpenAI verification works. In an end-to-end run against the live lists, a request from a
  published GPTBot address resolves to `verified` with an identity confidence of 0.94, and
  the same User-Agent from an unlisted address stays `claimed` at 0.06.
- Google and Perplexity snapshots now stop vouching after 7 days instead of never.
  Operators who analyse traffic continuously must refresh at least weekly.
- The period is ATI policy, stated in one constant, not something inferred from a
  provider's CDN configuration.
- What remains open: a snapshot is not checked against requests made long *before* it
  was retrieved, when an address may have belonged to someone else. Analysing old logs
  against a new snapshot carries that risk, and ATI does not yet bound it.

Implemented in `identity/source_service.py` (`_expires_at`); tests in
`tests/identity/sources/test_source_service.py` and `tests/identity/test_configured.py`.
