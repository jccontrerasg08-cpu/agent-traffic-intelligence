# Changelog

All notable changes will be documented here.

## Unreleased

### Added

- Observe-only V0 architecture, privacy-safe JSONL normalization, curated agent claims, bounded request/session features, four independent scores, and the original CLI.
- Ephemeral V1 `VerificationContext` so raw source addresses and signature material can be verified without entering persisted `RequestEvent` or detection output.
- Versioned, explainable identity verification results with provider-, agent-, and key-scoped evidence plus explicit `claimed`, `verified`, `failed`, and `conflicted` resolution states.
- Official IP-range verification and provider-documented FCrDNS support with privacy-safe evidence.
- Optional RFC 9421 / Web Bot Auth verification with JWK directories, RFC 7638 thumbprints, replay protection, Signature-Agent binding, and Google identity-vs-directory URI compatibility.
- Content-addressed external-source cache, provenance/freshness metadata, hardened HTTPS fetching, and explicit `ati sources status|refresh|validate` commands.
- Optional `verification` dependency extra and V1 CLI flags `--verify-identity` and `--verification-mode`.
- Verification JSON Schema, operator/security documentation, source-health runbook, structured issue forms, component ownership, Labeler, OpenSSF Scorecard, and scheduled read-only identity source-health checks.
- Python 3.11/3.12/3.13 core and verification CI plus wheel/sdist build and clean-install verification.

### Changed

- Provider verification profiles were re-reviewed against current primary sources; Anthropic no longer carries an IP-range source because Anthropic does not publish crawler IP ranges.
- Provider-style `prefixes-v1` documents normalize timezone-naive `creationTime` values to UTC, matching currently published OpenAI, Google, and Perplexity range documents; JAFAR remains strict about its required UTC `Z` form.
- Provider-aware verification now skips agent-scoped range sources that cannot apply to the claimed agent.
- Cryptographic verification loads the Structured Fields implementation supplied by the installed `http-message-signatures` stack, preserving compatibility with the pinned 2.x series.

### Fixed

- Source refresh no longer passes unsupported metadata into `SourceDocument` construction.
- Refreshed source documents are validated before replacing the previous cache entry, so malformed provider material cannot silently displace a known-good snapshot.
- RFC 9421 nonce handling now reads the verified signature parameter rather than a non-existent result attribute.
- HTTPS transport owns its pinned TLS connection state explicitly and Mypy-compatible verifier protocols model metadata as read-only.
- Removed the duplicate unused V1 runtime composition module in favor of the single provider-aware manager.
