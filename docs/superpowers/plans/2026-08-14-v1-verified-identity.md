# V1 Verified Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add privacy-preserving, explainable identity verification for automated and AI-originated HTTP traffic using official network ranges, provider-documented FCrDNS, RFC 9421 HTTP Message Signatures, and the current Web Bot Auth profile while preserving V0 default behavior.

**Architecture:** V1 introduces an ephemeral `VerificationContext`, immutable verification evidence, version-pinned provider/standards profiles, and one deterministic resolver. Shared contracts are frozen first; network, cryptographic, sources/provenance, and docs/fixtures then proceed on separate branches; track PRs merge into `feat/v1-verified-identity`; final integration connects them to `Detector`, CLI, schemas, scoring, CI, and source-health automation.

**Tech Stack:** Python 3.11+, standard library `ipaddress`, `socket`, `urllib`, `hashlib`, `json`, `concurrent.futures`; current dataclass/argparse architecture; optional `http-message-signatures>=2.0.1,<3`; pytest, pytest-cov, Ruff, Mypy, Hypothesis; GitHub Actions, CodeQL, Dependabot, `actions/labeler` pinned to full SHA.

> **Status update — 2026-08-16:** The V1 implementation and its V1.1 follow-on were merged through PR #8 as `b801678905cb568889ca258cfd88b4b9ad2728db`. Core and verification CI passed on Python 3.11–3.13, alongside package, CodeQL, Dependency Review, and final local validation. The historical checkboxes below remain as the original execution record; current follow-on work is defined by the post-merge evaluation roadmap.

## Global Constraints

- Default `ati analyze` remains offline and V0-compatible unless `--verify-identity` is explicitly supplied.
- Core installation keeps zero third-party runtime dependencies.
- Raw source IPs, full signature values, Authorization/Cookie values, request/response bodies, query strings, and private keys never appear in serialized detections or normal logs.
- `VerificationContext` is ephemeral and non-serializable.
- User-Agent is a claim, never proof.
- `automation_score`, `ai_score`, `identity_confidence`, and `risk_score` remain independent.
- Verification evidence may directly affect `identity_confidence` only.
- `BindingScope.KEY`, `BindingScope.PROVIDER`, and `BindingScope.AGENT` are distinct.
- Timeouts, stale sources, unsupported methods, and verifier errors never imply maliciousness and never become `FAILED` automatically.
- Internet-Draft behavior is version-pinned through `StandardsProfile`.
- Unknown `Signature-Agent` URLs are never fetched automatically under default `registry_only` policy.
- Deterministic PR CI performs no live DNS or HTTP calls.
- Live source-health checks are scheduled/manual and non-merge-blocking.
- No third-party implementation code or fixture corpus is copied without license review.
- Do not add `tj-actions/changed-files`; changed-file optimization uses GitHub-native workflow path filters or repository-owned `git diff`/Python logic.
- `actions/labeler` may be used only in a metadata-only workflow, pinned to `bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13` (`v7.0.0`), with no checkout, no PR-head code execution, `contents: read`, and `pull-requests: write` only.

## Branch topology

```text
main
  └─ design/v1-verified-identity          # approved spec + this plan
      └─ feat/v1-verified-identity        # serialized contracts/integration
          ├─ feat/v1-network              # Track A
          ├─ feat/v1-crypto               # Track B
          ├─ feat/v1-sources              # Track C
          └─ docs/v1-identity             # Track D
```

Tracks are created only after Tasks 1-4 are green on `feat/v1-verified-identity`. Each track opens a PR against `feat/v1-verified-identity`; integration happens only after track checks pass.

---

### Task 1: Freeze identity contracts

**Files:**
- Create: `src/agent_traffic_intelligence/identity/__init__.py`
- Create: `src/agent_traffic_intelligence/identity/context.py`
- Create: `src/agent_traffic_intelligence/identity/models.py`
- Create: `src/agent_traffic_intelligence/identity/policy.py`
- Create: `tests/identity/test_identity_models.py`

**Produces:**
- `VerificationMethod`: `OFFICIAL_RANGE`, `FCRDNS`, `RFC9421`, `WEB_BOT_AUTH`.
- `VerificationOutcome`: `PASS`, `MISMATCH`, `UNAVAILABLE`, `INDETERMINATE`, `STALE`, `ERROR`.
- `BindingScope`: `KEY`, `PROVIDER`, `AGENT`.
- `SourceAddressProvenance`: `DIRECT_PEER`, `TRUSTED_EDGE_CLIENT`, `FORWARDED_UNTRUSTED`, `UNKNOWN`.
- `VerificationMode`: `OFFLINE`, `HYBRID`, `LIVE`.
- `DiscoveryPolicy`: `REGISTRY_ONLY`, `PUBLIC_HTTPS`.
- immutable `VerificationContext`, `VerificationEvidence`, `VerificationResolution`, `VerificationPolicy`.

- [ ] **Step 1: Write failing tests**

```python
from datetime import UTC, datetime

from agent_traffic_intelligence.identity.context import VerificationContext
from agent_traffic_intelligence.identity.models import (
    BindingScope,
    SourceAddressProvenance,
    VerificationEvidence,
    VerificationMethod,
    VerificationOutcome,
)
from agent_traffic_intelligence.identity.policy import VerificationMode, VerificationPolicy


def test_context_is_ephemeral_and_has_no_serializer() -> None:
    context = VerificationContext(
        source_ip="203.0.113.10",
        source_address_provenance=SourceAddressProvenance.DIRECT_PEER,
        authority="example.com",
        method="GET",
        target_uri="https://example.com/docs",
        signature=None,
        signature_input=None,
        signature_agent=None,
        covered_headers={},
    )
    assert not hasattr(context, "to_dict")


def test_evidence_has_explicit_binding_scope() -> None:
    evidence = VerificationEvidence(
        method=VerificationMethod.OFFICIAL_RANGE,
        outcome=VerificationOutcome.PASS,
        binding_scope=BindingScope.PROVIDER,
        authority="anthropic",
        subject="anthropic",
        explanation="matched an official provider range",
        source_uri="https://claude.com/crawling/bots.json",
        source_profile="prefixes-v1",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        expires_at=None,
        source_sha256="a" * 64,
        details={"matched_prefix_length": 20},
    )
    assert evidence.binding_scope is BindingScope.PROVIDER


def test_policy_defaults_offline() -> None:
    policy = VerificationPolicy()
    assert policy.mode is VerificationMode.OFFLINE
    assert policy.allow_unknown_signature_agent_fetch is False
```

- [ ] **Step 2: Verify RED**

Run: `pytest tests/identity/test_identity_models.py -v`
Expected: import failure because package does not exist.

- [ ] **Step 3: Implement minimal dataclasses/enums**

Use `@dataclass(frozen=True, slots=True)`. `VerificationContext` deliberately has no serializer. `VerificationEvidence.to_dict()` serializes only privacy-safe fields. `VerificationPolicy()` defaults to offline, registry-only, max workers 4, verifier timeout 2 seconds, unknown Signature-Agent fetch disabled.

- [ ] **Step 4: Verify GREEN + V0 regression**

Run: `pytest tests/identity/test_identity_models.py tests/test_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -- src/agent_traffic_intelligence/identity tests/identity/test_identity_models.py
git commit -m "feat: define identity verification contracts"
```

---

### Task 2: Add version-pinned standards and provider profiles

**Files:**
- Create: `src/agent_traffic_intelligence/identity/standards.py`
- Create: `src/agent_traffic_intelligence/identity/profiles.py`
- Create: `src/agent_traffic_intelligence/identity/verification_profiles.json`
- Modify: `pyproject.toml`
- Create: `tests/identity/test_profiles.py`

**Produces:** `NegativeSemantics`, `StandardsProfile`, `ProviderProfile`, `RangeSourceProfile`, `FcrdnsProfile`, `CryptoProfile`, `load_provider_profiles()`, `provider_profile()`.

- [ ] **Step 1: Write failing tests**

```python
from agent_traffic_intelligence.identity.models import BindingScope
from agent_traffic_intelligence.identity.profiles import NegativeSemantics, provider_profile
from agent_traffic_intelligence.identity.standards import DEFAULT_STANDARDS_PROFILE


def test_anthropic_shared_range_is_provider_scope() -> None:
    source = provider_profile("anthropic").range_sources[0]
    assert source.uri == "https://claude.com/crawling/bots.json"
    assert source.binding_scope is BindingScope.PROVIDER
    assert source.negative_semantics is NegativeSemantics.POSITIVE_ONLY


def test_default_standards_profile_is_pinned() -> None:
    profile = DEFAULT_STANDARDS_PROFILE
    assert profile.http_message_signatures == "RFC9421"
    assert profile.web_bot_auth_architecture == "draft-meunier-web-bot-auth-architecture-05"
    assert profile.message_signatures_directory == "draft-meunier-http-message-signatures-directory-05"
    assert profile.jafar == "draft-illyes-webbotauth-jafar-00"
    assert profile.agent_card == "draft-meunier-webbotauth-registry-02"
```

- [ ] **Step 2: Verify RED** — `pytest tests/identity/test_profiles.py -v`.
- [ ] **Step 3: Implement profile parser and packaged JSON** with OpenAI, Google, Perplexity, Anthropic and Cloudflare interoperability metadata. Every external source entry records URI, reviewed date `2026-08-14`, format profile, binding scope, negative semantics, and documented DNS masks only when authoritative.
- [ ] **Step 4: Package profile data** by extending `[tool.setuptools.package-data]` with `identity/verification_profiles.json`.
- [ ] **Step 5: Verify** — `pytest tests/identity/test_profiles.py -v` and `python -m compileall -q src`.
- [ ] **Step 6: Commit** — `feat: add provider and standards profiles`.

---

### Task 3: Add ephemeral parser context without changing V0 output

**Files:**
- Modify: `src/agent_traffic_intelligence/parsers/jsonl.py`
- Modify: `tests/test_parser.py`
- Create: `tests/identity/test_parser_context.py`

**Produces:** existing `normalize_record()` unchanged; new `normalize_record_with_context()` and `iter_jsonl_with_context()`.

- [ ] **Step 1: Write failing privacy test**

```python
import json

from agent_traffic_intelligence.parsers.jsonl import normalize_record_with_context


def test_context_keeps_ephemeral_inputs_event_does_not(base_record) -> None:
    record = base_record()
    record.update({
        "host": "example.com",
        "http_signature": "sig1=:secret-material:",
        "http_signature_input": 'sig1=("@authority");created=1',
        "http_signature_agent": "https://agent.example/.well-known/http-message-signatures-directory",
    })
    event, context = normalize_record_with_context(record, hash_key=b"key", source="nginx")
    assert context.source_ip == record["remote_addr"]
    assert context.signature is not None
    serialized = json.dumps(event.to_dict())
    assert str(record["remote_addr"]) not in serialized
    assert "secret-material" not in serialized
```

- [ ] **Step 2: Verify RED**.
- [ ] **Step 3: Implement paired normalization**. Keep raw address/signature headers only in context. Never store Authorization/Cookie values. Direct `remote_addr` provenance is `DIRECT_PEER`; a pre-pseudonymized client with no trusted source address is `UNKNOWN`.
- [ ] **Step 4: Verify** — `pytest tests/test_parser.py tests/identity/test_parser_context.py -v`.
- [ ] **Step 5: Commit** — `feat: add ephemeral verification context`.

---

### Task 4: Add source/provenance contracts and offline cache

**Files:**
- Create: `identity/sources/models.py`
- Create: `identity/sources/cache.py`
- Create: `identity/sources/manifest.py`
- Create: `identity/sources/trust.py`
- Create: `tests/identity/sources/test_cache.py`
- Create: `tests/identity/sources/test_trust.py`

**Produces:** `SourceMetadata`, `SourceDocument`, `SourceCache`, `SourceTrustPolicy`.

- [ ] **Step 1: RED test** that `SourceDocument.from_bytes()` computes SHA-256, `SourceCache.put/get` round-trips atomically, and no filesystem path is derived from raw URI text.
- [ ] **Step 2: RED test** that registry-only trust approves only canonical provider-profile URIs and rejects unknown Signature-Agent URI.
- [ ] **Step 3: Implement** SHA-256 content files + atomic JSON manifest (`tempfile` and `os.replace`). Canonicalize HTTPS URIs; never use URI text as filesystem path.
- [ ] **Step 4: Verify** — `pytest tests/identity/sources -v`.
- [ ] **Step 5: Commit** — `feat: add identity source cache and provenance`.

**Parallel gate:** Create `feat/v1-network`, `feat/v1-crypto`, `feat/v1-sources`, and `docs/v1-identity` from this commit. Shared contract files are frozen until Task 12 integration.

---

### Task 5: Track A — parse published IP formats and match CIDRs

**Files:**
- Create: `identity/network/formats/prefixes_v1.py`
- Create: `identity/network/formats/jafar.py`
- Create: `identity/network/ranges.py`
- Modify: `pyproject.toml` dev extras (`hypothesis>=6`)
- Create: `tests/identity/network/test_range_formats.py`
- Create: `tests/identity/network/test_ranges.py`

**Produces:** `PublishedRangeSet`, `RangeMatch`, `parse_prefixes_v1()`, `parse_jafar()`.

- [ ] **Step 1: RED tests** for IPv4, IPv6, IPv4-mapped IPv6, malformed prefixes, unknown JAFAR fields, and most-specific-prefix wins.
- [ ] **Step 2: Add Hypothesis property**: any generated address inside a normalized test network matches that network; raw queried address never appears in serialized evidence.
- [ ] **Step 3: Implement** with `ipaddress.ip_network(..., strict=False)` and typed `RangeFormatError`.
- [ ] **Step 4: Verify** — `pytest tests/identity/network/test_range_formats.py tests/identity/network/test_ranges.py -v`.
- [ ] **Step 5: Commit** — `feat: parse and match published bot ranges`.

---

### Task 6: Track A — official provider-range verifier and fixtures

**Files:**
- Create minimal synthetic-format fixtures under `tests/fixtures/identity/providers/` for OpenAI GPTBot/SearchBot/AdsBot, Google crawlers/user-triggered agents, Perplexity Bot/User, Anthropic bots.
- Create fixture `manifest.json` with real official URI/review date/observed format and SHA-256 of each synthetic fixture.
- Create: `identity/network/verifier.py`
- Create: `tests/identity/network/test_verifier.py`

- [ ] **Step 1: Build fixtures** using documentation-reserved ranges only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Do not copy current provider range datasets into the repo.
- [ ] **Step 2: RED tests**: Anthropic range `PASS` is `PROVIDER` scope; positive-only miss is `INDETERMINATE`; provider/agent-specific source may be `AGENT` scope only when profile says so.
- [ ] **Step 3: Implement** `OfficialRangeVerifier.verify(...) -> VerificationEvidence`; evidence may include match boolean, prefix length, service/category, source digest, never raw IP.
- [ ] **Step 4: Verify** — `pytest tests/identity/network -v`.
- [ ] **Step 5: Commit** — `feat: verify official provider ranges`.

---

### Task 7: Track A — provider-documented FCrDNS

**Files:** `identity/network/fcrdns.py`, `tests/identity/network/test_fcrdns.py`.

**Produces:** `DnsResolver` protocol, `SocketDnsResolver`, `FcrdnsVerifier`.

- [ ] **Step 1: RED tests** for reverse+forward pass, PTR-only spoof, suffix-boundary mismatch, forward mismatch, timeout/NXDOMAIN -> `UNAVAILABLE`, provider with no policy -> `UNAVAILABLE`.
- [ ] **Step 2: Implement**: normalize hostnames, require documented suffix boundary, forward-resolve candidate, require original normalized address in A/AAAA results.
- [ ] **Step 3: Verify** — `pytest tests/identity/network/test_fcrdns.py -v`.
- [ ] **Step 4: Commit** — `feat: add forward-confirmed reverse DNS verification`.

Open PR `feat/v1-network` -> `feat/v1-verified-identity` after the full network suite passes.

---

### Task 8: Track B — optional RFC 9421 adapter

**Files:**
- Modify `pyproject.toml` with extra `verification = ["http-message-signatures>=2.0.1,<3"]`.
- Create `identity/crypto/rfc9421.py`.
- Create `tests/identity/crypto/test_rfc9421_adapter.py`.
- Modify `THIRD_PARTY_NOTICES.md`.

**Produces:** ATI-owned `Rfc9421Result` and `Rfc9421Verifier`; no third-party type escapes the adapter.

- [ ] **Step 1: RED test**: missing optional dependency returns `UNAVAILABLE`/actionable error, never crashes core install.
- [ ] **Step 2: RED vector tests**: valid signature, tampered covered component, insufficient covered set, unsupported algorithm, multiple-label confusion.
- [ ] **Step 3: Implement lazy import wrapper** and map exceptions/results to ATI models. Downstream receives only verified covered component values.
- [ ] **Step 4: Verify in core and extra installs** — `pytest tests/identity/crypto/test_rfc9421_adapter.py -v` in both modes.
- [ ] **Step 5: Record Apache-2.0 dependency attribution** in third-party notice.
- [ ] **Step 6: Commit** — `feat: add optional RFC 9421 verification adapter`.

---

### Task 9: Track B — key directories, Agent Cards, safe discovery

**Files:** `identity/crypto/key_resolver.py`, `directory.py`, `agent_card.py`; tests `test_directory.py`, `test_agent_card.py`, `test_discovery_policy.py`.

- [ ] **Step 1: RED SSRF test** with an `ExplodingFetcher` proving an unknown Signature-Agent URI is never fetched under `REGISTRY_ONLY`.
- [ ] **Step 2: RED tests** for malformed JWKS, key validity, rotation overlap, thumbprint consistency, directory-authority mismatch, and self-asserted vs authority-bound Agent Card metadata.
- [ ] **Step 3: Implement pinned draft parsers** behind `StandardsProfile`; stable internal models do not expose draft field names.
- [ ] **Step 4: Keep `PUBLIC_HTTPS` disabled** until Task 11 hardened fetcher; return unsupported/unavailable rather than silently fetching.
- [ ] **Step 5: Verify** — `pytest tests/identity/crypto/test_directory.py tests/identity/crypto/test_agent_card.py tests/identity/crypto/test_discovery_policy.py -v`.
- [ ] **Step 6: Commit** — `feat: add Web Bot Auth key discovery models`.

---

### Task 10: Track B — Web Bot Auth profile and replay controls

**Files:** `identity/crypto/replay.py`, `web_bot_auth.py`, `verifier.py`; tests `test_replay.py`, `test_web_bot_auth.py`, `test_interop_fixture.py`; offline public-key metadata fixture under `tests/fixtures/identity/crypto/`.

- [ ] **Step 1: RED tests** for correct tag, `created`/`expires`, required covered components, covered Signature-Agent, allowed algorithm, active key, directory binding, unsigned Signature-Agent substitution, replayed nonce, and key-only authentication without agent binding.
- [ ] **Step 2: Implement bounded process-local replay cache** by expiry + max entries; never persist nonces.
- [ ] **Step 3: Implement Web Bot Auth verifier**. `AGENT` scope requires trusted key-to-agent binding; a valid signature alone is `KEY` scope.
- [ ] **Step 4: Add offline interoperability fixture** from a currently deployed public signed-agent directory, with retrieval URL/date/SHA-256; CI never contacts the live directory.
- [ ] **Step 5: Verify** — `pytest tests/identity/crypto -v` with verification extra installed.
- [ ] **Step 6: Commit** — `feat: verify Web Bot Auth identities`.

Open PR `feat/v1-crypto` -> `feat/v1-verified-identity` after crypto suite passes.

---

### Task 11: Track C — hardened source fetching and refresh

**Files:** `identity/sources/fetcher.py`, `tests/identity/sources/test_fetcher.py`.

**Produces:** `SafeFetcher.fetch(uri, *, etag=None, last_modified=None) -> FetchResult` with injected resolver/transport seams.

- [ ] **Step 1: RED tests** reject non-HTTPS, embedded credentials, loopback/private/link-local/multicast/unspecified addresses, redirect to disallowed address, >3 redirects, >2 MiB body, wrong media type, malformed redirect.
- [ ] **Step 2: RED tests** for `If-None-Match`, `If-Modified-Since`, and 304 cache reuse.
- [ ] **Step 3: Implement** with standard library behind test seams; re-resolve/revalidate every redirect and validate TLS.
- [ ] **Step 4: Keep unknown public discovery off** even after fetcher exists unless explicit policy enables it; default remains registry-only.
- [ ] **Step 5: Verify** — `pytest tests/identity/sources -v`.
- [ ] **Step 6: Commit** — `feat: add hardened identity source fetcher`.

Open PR `feat/v1-sources` -> `feat/v1-verified-identity` after source suite passes.

---

### Task 12: Integrate resolver, bounded concurrency, Detection and scoring

**Files:**
- Create `identity/resolver.py`, `identity/manager.py`.
- Modify `src/agent_traffic_intelligence/models.py`, `engine.py`; modify `scoring.py` only if tests prove necessary.
- Create `tests/identity/test_resolver.py`, `test_manager.py`, `test_engine_integration.py`; modify `tests/test_models.py`.

**Produces:** `IdentityResolver.resolve()`, `VerificationManager.verify()`, optional `Detection.verification`.

- [ ] **Step 1: RED resolver tests**: provider pass does not verify exact agent; authoritative agent pass -> verified; strong agent conflict -> conflicted; timeout/stale/error cannot -> failed.
- [ ] **Step 2: Implement deterministic resolver**. `VERIFIED` requires authority-bound `AGENT` scope or equivalent trusted crypto chain. Evidence serialization order is stable independent of completion order.
- [ ] **Step 3: RED concurrency tests** using barriers/fake verifiers prove network and crypto overlap, a timeout does not block the other track, and output ordering remains deterministic.
- [ ] **Step 4: Implement bounded `ThreadPoolExecutor` manager** with max workers from policy and no shared identity mutation.
- [ ] **Step 5: Extend `VerificationState` with `CONFLICTED`; add `Detection.verification: VerificationResolution | None = None`**. `Detection.to_dict()` omits `verification` when disabled so V0 output shape stays unchanged.
- [ ] **Step 6: Integrate with `Detector.detect(event, verification_context=None)`**. No context/manager follows V0 code path exactly. Verification-derived `Evidence` can affect identity confidence only.
- [ ] **Step 7: Verify** — `pytest tests/identity/test_resolver.py tests/identity/test_manager.py tests/identity/test_engine_integration.py tests/test_models.py tests/test_scoring.py -v`.
- [ ] **Step 8: Commit** — `feat: integrate verified identity resolution`.

---

### Task 13: CLI, schemas, docs and ADRs

**Files:**
- Modify `cli.py`, `schemas/detection.schema.json`, `docs/schemas.md`, `README.md`, `CHANGELOG.md`, `docs/threat-model.md`, `SECURITY.md`.
- Create `schemas/verification.schema.json`.
- Create docs: `identity-verification.md`, `provider-verification.md`, `web-bot-auth.md`, `standards-status.md`, `source-trust-policy.md`, `source-refresh.md`, `privacy-network-data.md`, `conformance.md`.
- Create ADRs 0003 ephemeral context, 0004 optional crypto dependency, 0005 registry-only Signature-Agent fetching, 0006 provider-vs-agent binding scope.
- Modify `tests/test_cli.py`; create `tests/identity/test_schema_compatibility.py`.

**CLI contract:**
```text
ati analyze INPUT --verify-identity --verification-mode offline|hybrid|live
ati sources status
ati sources refresh [--provider PROVIDER]
ati sources validate
```

- [ ] **Step 1: RED CLI tests**: default analyze has `verify_identity=False`; `--verify-identity` defaults verification mode to offline; source refresh is explicit network-capable command.
- [ ] **Step 2: Implement CLI**. Default path still uses `iter_jsonl`; verification path uses `iter_jsonl_with_context`.
- [ ] **Step 3: Add additive schema**. `verification` is optional in detection schema and references versioned verification schema.
- [ ] **Step 4: Test V0 and V1 schema fixtures** without adding runtime dependencies.
- [ ] **Step 5: Write operator docs/ADRs** with official source URI, review date, binding scope, negative semantics, draft revision, and current limitations.
- [ ] **Step 6: Verify** — `pytest tests/test_cli.py tests/identity/test_schema_compatibility.py -v`.
- [ ] **Step 7: Commit** — `docs: document verified identity operation` plus CLI/schema commit if separation improves reviewability.

Track `docs/v1-identity` may prepare documentation/fixtures in parallel but must rebase on integrated contracts before merge.

---

### Task 14: CI, source-health and safe PR labeling

**Files:**
- Modify `.github/workflows/ci.yml`.
- Create `.github/workflows/source-health.yml`.
- Create `.github/workflows/labeler.yml`.
- Create `.github/labeler.yml`.
- Modify `.github/dependabot.yml` only if needed to keep GitHub Actions updates enabled.

- [ ] **Step 1: Split deterministic CI into core and verification-extra matrices** on Python 3.11/3.12/3.13. Core installs `.[dev]`; verification installs `.[dev,verification]`. Both run Ruff/Mypy/tests/compile/package/CLI smoke as applicable.
- [ ] **Step 2: Add scheduled/manual `source-health.yml`** with `contents: read`, no write token, live provider/IETF checks, schema parse checks, freshness/digest reporting. It never runs on PR and never changes trust policy.
- [ ] **Step 3: Do not use `tj-actions/changed-files`**. If path-specific optimization is useful, use workflow `paths`/`paths-ignore`; otherwise keep the matrix simple until repo size justifies repository-owned diff logic.
- [ ] **Step 4: Add labeler config using only existing labels**:

```yaml
documentation:
  - changed-files:
      - any-glob-to-any-file:
          - "docs/**"
          - "**/*.md"

dependencies:
  - changed-files:
      - any-glob-to-any-file:
          - "pyproject.toml"

github_actions:
  - changed-files:
      - any-glob-to-any-file:
          - ".github/workflows/**"
          - ".github/dependabot.yml"

enhancement:
  - head-branch: ["^feat/", "^feature/"]

bug:
  - head-branch: ["^fix/", "^bugfix/", "^hotfix/"]
```

- [ ] **Step 5: Add metadata-only labeler workflow**:

```yaml
name: Pull request labeler
on:
  pull_request_target:
    types: [opened, synchronize, reopened, ready_for_review]

permissions: {}

jobs:
  label:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Label pull request
        uses: actions/labeler@bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13 # v7.0.0
```

No checkout. No shell step. No PR-head code. No `issues: write`. `sync-labels` remains false.

- [ ] **Step 6: Validate YAML and workflow security**: all third-party actions full-SHA pinned; default permissions read-only/empty; source-health cannot write; labeler cannot create labels.
- [ ] **Step 7: Commit** — `ci: add V1 verification and metadata automation`.

---

### Task 15: Fresh end-to-end verification and PR handoff

**Files:** no new implementation unless failures reveal a scoped defect.

- [ ] **Step 1: Core install verification**

```bash
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest --cov=agent_traffic_intelligence --cov-report=term-missing
python -m compileall -q src
ati registry validate
ati analyze examples/data/access.jsonl --source nginx --output /tmp/v0.jsonl
```

Expected: all green; V0 output contains no `verification` key.

- [ ] **Step 2: Verification-extra install**

```bash
python -m pip install -e ".[dev,verification]"
pytest tests/identity/crypto tests/identity/network tests/identity/sources -v
```
Expected: all green with zero live network dependency.

- [ ] **Step 3: Privacy scan**. Analyze fixtures containing raw IP/query/signature material and assert none appears in detection JSON or normal stderr/log output.
- [ ] **Step 4: Offline/hybrid behavior**. Offline verification uses snapshots only; hybrid/live is explicit and failures become unavailable/indeterminate rather than risk/failure.
- [ ] **Step 5: Package verification**. Build wheel/sdist, inspect wheel for `agents.json` and `identity/verification_profiles.json`, install in clean venv, run `pip check` and CLI smoke.
- [ ] **Step 6: GitHub verification**. Confirm PR CI green on 3.11/3.12/3.13, CodeQL/dependency review green, labeler has metadata-only permissions, source-health is non-merge-blocking.
- [ ] **Step 7: Compare against the 20 acceptance criteria in the approved spec** and record any unverified criterion explicitly; do not mark V1 complete while any criterion lacks evidence.
- [ ] **Step 8: Open one final PR** from `feat/v1-verified-identity` to `main` with architecture summary, provider/standards matrix, privacy guarantees, verification evidence, known limitations, and migration note that V0 default behavior is unchanged.

## Review gates

1. Tasks 1-4 must be reviewed before parallel tracks start.
2. Each track PR must pass its focused suite and not edit frozen shared interfaces without integration-owner approval.
3. Track merge order is sources/network/crypto/docs only when CI proves no conflict; semantic integration is Task 12 regardless of merge order.
4. Final PR does not merge until core + verification matrices, CodeQL, dependency review, packaging, privacy scan, and all applicable acceptance criteria are green.
