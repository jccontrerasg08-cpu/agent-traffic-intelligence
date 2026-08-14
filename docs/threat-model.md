# Threat Model

## Protected asset

Reliable classification and observability of traffic reaching a web property or API without exposing sensitive request data.

## Adversaries and difficult cases

### Spoofed known User-Agent

An attacker can send `GPTBot`, `ClaudeBot`, `Googlebot`, or any other token. V0 therefore records a claim but keeps identity confidence low. Future verifier adapters combine official network material, forward-confirmed reverse DNS where appropriate, or cryptographic signatures.

### Residential and rotating proxies

IP reputation and ASN are supporting evidence only. Shared/NAT/residential IPs must not be treated as identity.

### TLS impersonation

Advanced clients can reproduce common TLS fingerprints. JA4-like fingerprints are evidence, not proof, and must be combined with request/session behavior.

### Real-browser automation

Playwright, Selenium, Puppeteer, browser extensions, and agentic browsers can load normal assets and execute JavaScript. Server-side single-request classification can be fundamentally ambiguous. Session and cross-context features are required, with optional browser telemetry later.

### Distributed low-and-slow scraping

Per-client rate rules can fail when traffic is spread across many clients. Future correlation needs route-level aggregates, fingerprint clusters, and change detection without assuming a shared IP means a shared actor.

### Poisoning and concept drift

Online learning can be manipulated if weak labels are accepted automatically. V0 has no online training. Future learning pipelines must separate trusted labels, delayed evaluation, model registry/reproducibility, and rollback.

## Failure policy

V0 never enforces. Future real-time sensors should default to observe/allow on detector failure unless an operator deliberately configures a separate fail-closed security policy for a known threat model.
