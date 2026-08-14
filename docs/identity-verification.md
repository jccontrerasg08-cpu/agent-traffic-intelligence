# Identity Verification

V1 adds evidence-backed identity verification without changing ATI's observe-only security posture.

## Read the outputs separately

ATI keeps four probabilistic scores independent from the categorical identity result. `identity_confidence` answers how much evidence supports the claimed identity; it is not a substitute for `verification.state`, and neither field automatically lowers `risk_score`.

The verification payload distinguishes:

- `CLAIMED`: the request presents an identity claim, but exact-agent authentication is not established.
- `VERIFIED`: trusted `AGENT`-scope evidence binds the request to the exact claimed agent.
- `FAILED`: an applicable authoritative identity check contradicts the claim.
- `CONFLICTED`: strong authority-bound evidence disagrees and ATI refuses to hide the conflict.

`provider_verified=true` can coexist with `CLAIMED` when evidence proves an operator/provider but not the exact product or agent.

## Evidence scope

- `KEY`: proves control of a public-key identity only.
- `PROVIDER`: binds evidence to an operator/provider.
- `AGENT`: binds evidence to the exact claimed automated agent.

A verified key is not automatically a verified company. A provider IP range is not automatically proof of a particular bot unless the provider source has agent-level semantics.

## Operational failure is neutral

DNS timeout, unavailable optional dependencies, stale snapshots, unsupported verification methods and verifier exceptions produce `UNAVAILABLE`, `STALE`, `INDETERMINATE` or `ERROR`. They do not become identity failure or risk penalties by themselves.

## Default mode

Normal `ati analyze` remains the V0 offline path. Verification and any future live source refresh are opt-in. Serialized results never contain raw source IPs, full signature values, Authorization/Cookie values, request bodies or query-string values.
