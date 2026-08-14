# Identity Verification

V1 adds evidence-backed identity verification without changing ATI's observe-only posture.

## Read the outputs separately

ATI keeps `automation_score`, `ai_score`, `identity_confidence`, and `risk_score` independent from the categorical identity result. `identity_confidence` expresses how much evidence supports a claim; it is not a substitute for `verification.state`, and neither field automatically lowers `risk_score`.

- `CLAIMED`: an identity is asserted but exact-agent authentication is not established.
- `VERIFIED`: trusted `AGENT`-scope evidence binds the request to the exact claimed agent.
- `FAILED`: an applicable authoritative check contradicts the claim.
- `CONFLICTED`: strong authority-bound evidence disagrees and ATI preserves that conflict.

`provider_verified=true` can coexist with `CLAIMED` when evidence proves an operator/provider but not the exact product.

## Binding scopes

- `KEY`: control of a cryptographic key only.
- `PROVIDER`: evidence bound to an operator/provider.
- `AGENT`: evidence bound to the exact automated agent.

A verified key is not automatically a verified company. A provider IP range is not automatically proof of a particular bot unless that source is agent-scoped.

## Operational failure is neutral

DNS timeouts, unavailable optional dependencies, stale snapshots, unsupported methods, and verifier exceptions do not become identity failures or risk penalties by themselves.

## Privacy and defaults

Normal `ati analyze` remains the V0 offline path. Raw source IPs, full signature values, Authorization/Cookie values, request bodies, and query-string values are never serialized in detections.
