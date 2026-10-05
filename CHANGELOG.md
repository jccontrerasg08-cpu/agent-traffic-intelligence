# Changelog

All notable changes will be documented here.

## Unreleased

### Added

- Observe-only V0 architecture, privacy-safe JSONL normalization, curated agent claims, bounded request/session features, four independent scores, and the original CLI.
- ATI-PF-2 baseline ladder (`ati pf2-baseline`): forward-chained temporal, leave-one-task-out and grouped-session holdouts, a constant-prevalence baseline, a dependency-free L2-regularized logistic regression, train-partition-only standardization and threshold selection, session-cluster resampling intervals, and one refit ablation per permitted feature family.
- Privacy-safe warehouse export (`ati pf2-export-bigquery`): aggregate run, metric, ablation, feature-summary and cohort tables with BigQuery schemas and DDL. The split manifest is not exportable and per-session feature rows are reduced to per-class aggregates.
- A case study, an engineering-principles map tied to concrete files, a documentation map grouped by reader intent, and ADRs 0007 (the PF-2 feature firewall) and 0008 (aggregate-only warehouse export).
- `tests/test_docs_links.py`, which fails the suite on any broken relative link in the repository's Markdown.
- Live ATI-PF-2 collection evidence recording a 24-session multi-family run through the deployed Cloudflare Worker, the reconciliation result, and the preflight's fail-closed refusal of the single-class corpus.
- Ephemeral V1 `VerificationContext` so raw source addresses and signature material can be verified without entering persisted `RequestEvent` or detection output.
- Versioned, explainable identity verification results with provider-, agent-, and key-scoped evidence plus explicit `claimed`, `verified`, `failed`, and `conflicted` resolution states.
- Official IP-range verification and provider-documented FCrDNS support with privacy-safe evidence.
- Optional RFC 9421 / Web Bot Auth verification with JWK directories, RFC 7638 thumbprints, replay protection, Signature-Agent binding, and Google identity-vs-directory URI compatibility.
- Content-addressed external-source cache, provenance/freshness metadata, hardened HTTPS fetching, and explicit `ati sources status|refresh|validate` commands.
- Optional `verification` dependency extra and V1 CLI flags `--verify-identity` and `--verification-mode`.
- Verification JSON Schema, operator/security documentation, source-health runbook, structured issue forms, component ownership, Labeler, OpenSSF Scorecard, and scheduled read-only identity source-health checks.
- Python 3.11/3.12/3.13 core and verification CI plus wheel/sdist build and clean-install verification.

### Changed

- ATI-PF-2 gains a tempo-shape feature family (two scale-free ratios of the session's pauses), optional participant-grouped splits that keep each person on one side of every holdout, and `ati pf2-simulate`, a power analysis on synthetic fixtures for planning recruitment. A boosted-stumps rung was evaluated and not adopted, because it did worse than the logistic rung. Evidence: `docs/architecture/pf2-model-improvement-evidence.md`.
- Web Bot Auth is pinned to the IETF working-group draft `draft-ietf-webbotauth-httpsig-protocol-00` (adopted 2026-09-01), which also absorbs the HTTP Message Signatures Directory draft. The review is recorded in `docs/standards-status.md`, and the draft's Appendix E.2 test vectors run against the real verifier.
- `evaluation` is a package: metrics in `evaluation.metrics`, campaign planning in `evaluation.campaign`, and the ATI-PF-2 protocol, baseline and export in `evaluation.pf2`. The public `evaluation` surface is unchanged, and `campaign_protocol` and `pf2_protocol` remain as compatibility facades. Evaluation tests moved from `tests/research` to `tests/evaluation`, so `make test-evaluation` now covers the whole area and `make test-research` covers research contracts only.
- The CLI parser, the warehouse export and the baseline ladder are split into named single-purpose functions. Behaviour is unchanged: the parser tree, a baseline report and an export are byte-identical before and after.
- Dated design specs, implementation plans and audit notes moved from `docs/` and `docs/superpowers/` into `docs/history/`, indexed and marked as historical.
- The ATI-PF-2 route mapping is public as `PF2_ROUTE_CATEGORIES`, versioned as `PF2_CATALOGUE_VERSION`, and pinned by test to the laboratory's closed catalogue.
- `pr_auc` and `expected_calibration_error` are part of the evaluation module's public surface so the ATI-PF-2 baseline reuses one metric implementation.
- Provider verification profiles were re-reviewed against current primary sources; Anthropic no longer carries an IP-range source because Anthropic does not publish crawler IP ranges.
- Provider-style `prefixes-v1` documents normalize timezone-naive `creationTime` values to UTC, matching currently published OpenAI, Google, and Perplexity range documents; JAFAR remains strict about its required UTC `Z` form.
- Provider-aware verification now skips agent-scoped range sources that cannot apply to the claimed agent.
- Cryptographic verification loads the Structured Fields implementation supplied by the installed `http-message-signatures` stack, preserving compatibility with the pinned 2.x series.

### Fixed

- Official IP-range verification for OpenAI never passed: its lists are served with `max-age=0`, so every refreshed snapshot was stale on arrival. Google and Perplexity lists had the opposite problem and never expired. A range snapshot now verifies requests for 7 days after retrieval, regardless of HTTP headers (ADR 0009).
- A Web Bot Auth signature is no longer attributed to a `Signature-Agent` member that belongs to another signer. It binds to the member under its own label, or to the single member it covers, as the working-group draft requires.
- RFC 9421 `created` and `expires` are judged at the request's time rather than the wall clock, so analysing a log older than the validity window no longer rejects every valid signature.
- Key-directory refresh no longer follows redirects or accepts a status other than 200 (or a 304 revalidation), per the draft's discovery rule.
- Source refresh no longer passes unsupported metadata into `SourceDocument` construction.
- Refreshed source documents are validated before replacing the previous cache entry, so malformed provider material cannot silently displace a known-good snapshot.
- RFC 9421 nonce handling now reads the verified signature parameter rather than a non-existent result attribute.
- HTTPS transport owns its pinned TLS connection state explicitly and Mypy-compatible verifier protocols model metadata as read-only.
- Removed the duplicate unused V1 runtime composition module in favor of the single provider-aware manager.
