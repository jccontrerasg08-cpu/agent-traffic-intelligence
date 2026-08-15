# V1 Repository Hardening Addendum

> **Normative companion to:** `docs/superpowers/plans/2026-08-14-v1-verified-identity.md`
>
> **Source basis:** user-provided TensorFlow repository engineering review, adapted to Agent Traffic Intelligence (ATI). This document adopts engineering patterns, not TensorFlow's architecture or scale.

**Goal:** Strengthen ATI's repository governance, supply-chain security, contribution gates, failure tracking, and stable-vs-experimental boundaries without adding unnecessary runtime complexity or weakening the V1 privacy/identity design.

## Adopt / adapt / reject

### Adopt now

- explicit trust-boundary/threat-model language;
- full-SHA-pinned GitHub Actions;
- least-privilege workflow permissions;
- OpenSSF Scorecard reporting;
- OSV dependency scanning;
- grouped Dependabot updates;
- CODEOWNERS by subsystem;
- tests required for features and bug fixes;
- structured issue forms for security-relevant/data-source failures;
- stable vs experimental API distinction;
- rollback/failure follow-up for autonomous source-health automation;
- build/release provenance and attestations where publishing is introduced.

### Adapt later

- `CITATION.cff` and Zenodo/DOI metadata become appropriate once ATI has a stable public release or research dataset worth citing. Do not block V1 on them.
- Release automation should use build-once/verify/attest/publish discipline when the first stable package release is prepared.

### Explicitly reject for ATI V1

- Bazel;
- TensorFlow-sized monorepo organization;
- huge CPU/GPU/accelerator CI matrices;
- Copybara/internal Google workflows;
- introducing `uv` solely because the reference review mentions it. ATI keeps the current packaging toolchain unless a separate migration is justified and approved.

## Global repository-security rules

1. Every third-party GitHub Action MUST be pinned to a full commit SHA. Version comments are allowed next to the SHA for readability.
2. Workflows default to `permissions: contents: read` or stricter; write scopes are granted only per job when required.
3. `pull_request_target` workflows MUST NOT check out or execute untrusted PR-head code.
4. Security/source-health automation is separated from deterministic PR CI.
5. Feature changes require tests. Bug fixes require a regression test unless the failure is documentation-only or otherwise impossible to exercise programmatically; exceptions must be explained in the PR body.
6. Experimental integrations MUST NOT silently inherit the stability guarantees of the deterministic core.
7. External source material is treated as semi-trusted input: size/type validation -> digest -> parser -> schema validation -> semantic validation -> normalized internal representation.
8. Arbitrary uploads, scraped HTML, downloaded executable/model artifacts, pickle/joblib, and unknown remote content are untrusted. V1 identity verification does not deserialize executable Python objects.

---

## Task H1: Expand the threat model into explicit trust categories

**Files:**
- Modify: `docs/threat-model.md`
- Modify: `SECURITY.md`
- Create: `docs/trust-boundaries.md`

**Required trust classes:**

```text
TRUSTED
├── reviewed repository code
├── version-pinned standards/provider profiles
└── validated local schemas

SEMI_TRUSTED
├── provider-owned IP range documents
├── provider-owned JWKS/key directories
├── authority-bound Agent Cards
├── DNS responses used under documented FCrDNS policy
└── cached/snapshotted external source documents

UNTRUSTED
├── request headers controlled by remote clients
├── unknown Signature-Agent URLs
├── forwarded headers from untrusted peers
├── arbitrary web content
├── malformed JSON/JWKS/Structured Fields
└── uploaded/executable serialized artifacts
```

**Acceptance checks:**
- `Signature-Agent` is explicitly classified untrusted until discovery/binding policy approves it.
- A provider-owned document is not described as infallible; compromise/staleness remains in the threat model.
- Trust category never directly changes `risk_score`; verifiers still produce evidence through the resolver.

**Commit:** `docs: define identity trust boundaries`

---

## Task H2: Add OpenSSF Scorecard with least privilege

**Files:**
- Create: `.github/workflows/scorecard.yml`

**Workflow requirements:**
- use the official `ossf/scorecard-action` only;
- pin every Action to a full SHA verified during implementation;
- default `permissions: read-all` where supported;
- grant only the job scopes needed for Scorecard/SARIF publication;
- do not run project code with write-capable credentials;
- upload SARIF to GitHub Code Scanning only from trusted workflow context;
- set a finite job timeout;
- document why `security-events: write` and any `id-token: write` permission are required.

**Verification:**
- YAML parse/static review;
- all `uses:` lines match `@[0-9a-f]{40}`;
- permissions scan finds no `write-all`.

**Commit:** `ci: add OpenSSF scorecard analysis`

---

## Task H3: Add OSV dependency scanning without coupling it to normal tests

**Files:**
- Create: `.github/workflows/osv-scan.yml`
- Modify: `docs/repository-settings.md`

**Behavior:**
- scheduled weekly plus manual dispatch;
- scan Python dependency metadata/lock material that actually exists in ATI at implementation time;
- do NOT invent `uv.lock` if the repo does not use uv;
- pin the OSV workflow/action to a full SHA;
- minimum permissions (`contents: read`; `security-events: write` only if publishing findings requires it);
- source/network availability failures must not masquerade as Python unit-test failures.

**Acceptance checks:**
- no `write-all`;
- no package publishing token;
- scheduled scan is separate from `.github/workflows/ci.yml`.

**Commit:** `ci: add scheduled OSV dependency scan`

---

## Task H4: Group Dependabot updates

**Files:**
- Modify: `.github/dependabot.yml`

**Required policy:**
- GitHub Actions: monthly, grouped under one logical group;
- Python development/verification dependencies: weekly or monthly, grouped by compatible maintenance purpose rather than one PR per package;
- security updates remain reviewable and are not hidden by grouping policy;
- do not add Docker monitoring until ATI actually ships a Dockerfile/image.

**Verification:** configuration parse/manual review and Dependabot-compatible schema.

**Commit:** `chore: group dependency update automation`

---

## Task H5: Make CODEOWNERS reflect architecture

**Files:**
- Modify: `.github/CODEOWNERS`

**Paths to own explicitly:**

```text
/src/agent_traffic_intelligence/identity/network/
/src/agent_traffic_intelligence/identity/crypto/
/src/agent_traffic_intelligence/identity/sources/
/src/agent_traffic_intelligence/parsers/
/tests/identity/
/schemas/
/docs/
/.github/
```

Use the current maintainer as owner initially if there is only one maintainer. The purpose is architectural ownership and future reviewer routing, not artificial bureaucracy.

**Commit:** `chore: define component ownership`

---

## Task H6: Add specialized structured issue forms

**Files:**
- Create: `.github/ISSUE_TEMPLATE/provider-source-change.yml`
- Create: `.github/ISSUE_TEMPLATE/verification-discrepancy.yml`
- Create: `.github/ISSUE_TEMPLATE/parser-failure.yml`
- Modify: `.github/ISSUE_TEMPLATE/config.yml` only if needed to keep security reports private.

**Provider/source change form requires:** provider, source URI, observed date, previous behavior, new behavior, source digest if available, reproduction command, and whether the change affects binding scope/negative semantics.

**Verification discrepancy form requires:** claimed provider/agent, verification mode, expected state, observed state, relevant evidence codes, ATI version/commit, and sanitized reproduction data. It MUST warn users not to paste raw IPs, cookies, Authorization, full signatures, or private keys.

**Parser failure form requires:** source/profile, sanitized failing shape, ATI version, parser/profile version, and reproduction command.

Security vulnerabilities continue through private reporting instructions rather than a public issue form.

**Commit:** `chore: add identity verification issue forms`

---

## Task H7: Formalize stable vs experimental API boundaries

**Files:**
- Modify: `docs/identity-verification.md` when created by the V1 plan
- Modify: `docs/conformance.md` when created
- Modify: `README.md`
- Modify: `src/agent_traffic_intelligence/__init__.py` only if public exports require clarification

**Policy:**

```text
STABLE CORE
- privacy-minimized RequestEvent/Detection behavior
- deterministic parser/rule/scoring contracts already public
- versioned verification result schema once accepted

VERSIONED / DRAFT-PROFILE
- Web Bot Auth draft adapters
- Signature Agent Card parsing
- JAFAR draft parsing

EXPERIMENTAL / OPTIONAL
- future ML calibration
- future LLM semantic enrichment
- unknown-agent clustering
- future remediation/policy enforcement
```

Draft-profile functionality must expose the implemented standards revision and must not claim RFC-level stability.

**Commit:** `docs: define stable and experimental interfaces`

---

## Task H8: Track source-health failures as engineering events

**Files:**
- Create: `.github/workflows/source-health.yml` as required by the main V1 plan
- Create: `.github/ISSUE_TEMPLATE/source-health-failure.yml` only if automated issue creation uses an issue form-compatible template/documentation pattern
- Create: `docs/source-health-operations.md`

**Behavior:**
- source-health is scheduled/manual and non-merge-blocking;
- checks official provider endpoints, parsability, freshness/digest changes, and tracked IETF profile revisions;
- do not silently rewrite trust policy or provider profiles on `main`;
- when a deterministic source-health failure persists or a reviewed automation opens a tracking issue, include: commit SHA, workflow run, failed stage, source URI, current digest, previous known digest, parser/profile version, and previous successful check;
- never include raw request IPs/signatures/secrets;
- automated issue creation, if enabled, receives only the minimum `issues: write` permission in that specific job.

**Commit:** `ci: add source health failure tracking`

---

## Task H9: Enforce contribution gates in repository documentation

**Files:**
- Modify: `CONTRIBUTING.md`
- Modify: `.github/pull_request_template.md`

**Required contributor checklist:**
- feature has tests;
- bug fix has regression test or documented reason it cannot;
- public/schema compatibility assessed;
- dependency/API/configuration maintenance cost justified;
- privacy impact assessed;
- external sources cite provider/standard authority and review date;
- workflow permissions/actions pinning reviewed for `.github/**` changes.

Add the design-review heuristic: a feature's operational/user value must justify the maintenance burden it introduces. This is a qualitative gate, not a numeric score.

**Commit:** `docs: strengthen contribution quality gates`

---

## Task H10: Prepare release/research metadata only when justified

**V1 behavior:** documentation-only future gate; do not block implementation.

Before the first stable/research-citable release, evaluate:
- `CITATION.cff`;
- Zenodo archive/DOI;
- immutable release assets;
- checksums;
- artifact attestations;
- build-once -> verify -> attest -> publish flow.

Do not create DOI metadata for a pre-alpha development snapshot merely for badges.

---

## Integration order with the main V1 plan

- H1 and H9 may land during the documentation track.
- H4/H5/H6 may land after shared contracts are frozen because they do not affect runtime interfaces.
- H2/H3 should land with the CI hardening task after Action SHAs are freshly verified.
- H7 lands after V1 public module/schema boundaries are known.
- H8 lands with the scheduled source-health workflow.
- H10 remains a release gate outside V1 completion unless a stable/citable release is explicitly requested.

## Additional V1 acceptance criteria

V1 repository hardening is complete when:

1. All third-party `uses:` references are full-SHA pinned.
2. No workflow has `permissions: write-all`.
3. OpenSSF Scorecard exists and can publish results under least privilege.
4. OSV scanning is scheduled separately from deterministic PR CI.
5. Dependabot Actions updates are grouped.
6. CODEOWNERS maps V1 identity subsystems.
7. Structured forms exist for provider/source changes and verification/parser discrepancies.
8. Contribution docs require tests and compatibility/privacy/security review.
9. Stable, draft-profile, and experimental functionality are documented distinctly.
10. Source-health failures have a documented path to a traceable engineering event.
11. No TensorFlow-specific scale tooling (Bazel, accelerator matrix, Copybara) is introduced.
12. No packaging migration to uv is performed without a separate justified decision.
