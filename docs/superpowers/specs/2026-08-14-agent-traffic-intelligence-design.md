# Agent Traffic Intelligence Design

**Status:** Approved for repository bootstrap
**Date:** 2026-08-14

## Goal

Build a self-hosted, vendor-neutral system that observes HTTP/server traffic and estimates four distinct quantities:

1. `automation_score`: likelihood that traffic is automated.
2. `ai_score`: likelihood that automated traffic is related to an AI crawler, AI search indexer, or user-triggered AI agent.
3. `identity_confidence`: confidence that a claimed bot/agent identity is authentic.
4. `risk_score`: likelihood that the observed behavior is abusive or operationally risky.

The project must not claim to identify an exact foundation model from network traffic unless explicit, verifiable evidence exists.

## V0 scope

V0 is intentionally passive and offline:

- Read JSONL edge/origin access logs.
- Normalize each request into a privacy-minimized event schema.
- Classify well-known agents by an auditable registry.
- Extract request and session-level behavioral features.
- Produce explainable evidence and four independent scores.
- Emit JSONL detections and summary metrics.
- Never block, challenge, rate-limit, or mutate production traffic.
- Store no request/response bodies, cookies, authorization values, or raw IPs in project output.

## Architecture

```text
edge/origin JSONL
      |
      v
  parser/normalizer
      |
      +--> privacy transform
      |
      v
 request event ---------> identity registry
      |                         |
      v                         v
 request features         identity evidence
      |                         |
      +----------+--------------+
                 v
           rule engine
                 |
                 v
       explainable evidence
                 |
                 v
         scoring engine
                 |
                 v
        detection JSONL
                 |
                 v
        evaluation/dataset
```

Future versions add a real-time reverse proxy/sidecar, TLS/JA4 input adapters, verified-agent cryptographic identity, ML adapters, anomaly discovery, and optional remediation.

## Design principles

### Observe before enforce

The detector must prove value and estimate false-positive rates before it can affect requests. Enforcement is a separate future component.

### Evidence, not a single opaque boolean

Every decision carries machine-readable evidence with source, strength, reason, and affected score dimensions.

### Identity is not risk

A verified crawler can be automated and AI-related while low-risk. A browser automation session can be high-risk without being AI-related.

### Network identity is probabilistic unless verified

User-Agent strings are claims. Stronger identity can come from official IP ranges, forward-confirmed reverse DNS, or cryptographic agent authentication. V0 records the claim and leaves stronger verification to adapters.

### Privacy by default

Raw IPs, cookies, authorization headers, request/response bodies, and query-string values are not written to normalized output. Client correlation uses keyed hashing when a raw address must be ingested.

### License isolation

External projects are research references. No third-party implementation is copied into this repository unless its license, attribution requirements, and compatibility are reviewed and documented.

## Score model

For dimension `d`, evidence is combined in log-odds space:

`z_d = intercept_d + sum(weight_i,d * strength_i)`

`score_d = sigmoid(z_d)`

This keeps scores bounded and makes each contribution inspectable. V0 ships conservative hand-authored baselines. Learned calibration can replace weights later without changing the event contract.

## Event contract

A normalized request contains:

- event timestamp and request identifier
- privacy-preserving client identifier
- method, normalized path, status, bytes
- HTTP protocol
- User-Agent string or normalized family where available
- selected non-sensitive header presence booleans
- optional upstream-provided network fingerprints such as JA4
- source adapter metadata

A detection contains:

- actor type and provider if known
- claimed identity and verification state
- the four scores
- ordered evidence list
- feature snapshot used for the decision
- detector/ruleset version

## Failure modes

- Spoofed known User-Agent: identity remains unverified and cannot alone produce high identity confidence.
- Residential proxies: ASN/IP reputation is supporting evidence only.
- Browser automation with realistic TLS: behavior and optional browser telemetry must carry more weight.
- Distributed low-and-slow scraping: request-local rules will miss it; later aggregation across fingerprints/routes is required.
- Real-browser agents: automation may be indistinguishable at a single-request level; session and cross-context features become necessary.
- New agent families: known-signature classification fails; anomaly/cluster stages handle this in later versions.
- NAT/shared IP: never treat IP alone as a human identity.

## V1 and later

- Real-time sidecar/reverse-proxy sensor, preferably Go or Rust.
- Inputs from Nginx, Envoy, HAProxy, Traefik, Cloudflare logs, Zeek, and Suricata.
- Web Bot Auth / HTTP Message Signature verification.
- Official bot IP/rDNS verifier adapters with cached, signed/hashed registries.
- Gradient-boosted tabular classifier and calibrated probabilities.
- River-based streaming/drift experiments.
- Unknown-agent clustering/anomaly detection.
- Optional JavaScript/browser-signal collector, isolated from the server baseline.
- Remediation policy engine only after shadow-mode evaluation.
