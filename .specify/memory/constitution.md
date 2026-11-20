# Agent Traffic Intelligence Constitution

These principles were adopted one decision at a time, in the ADRs under `docs/adr/` and in
`CONTRIBUTING.md`. This constitution gathers them into one place so that every
specification, plan and task can be checked against them. Where a principle has an ADR or
a test that enforces it, that source is named. A principle without an enforcing mechanism
is a goal, and says so.

## Core Principles

### I. Observe Before Enforce

ATI classifies and explains traffic. It MUST NOT block, challenge, throttle, rewrite or
otherwise act on traffic, in any component, including the technical service
([ADR 0001](../../docs/adr/0001-observe-before-enforce.md)). A feature that would act on
traffic is out of scope until its false-positive cost against real users has been
measured and a new ADR supersedes ADR 0001.

*Rationale:* a false positive turns a real person away. The system must earn trust before
it acts.

### II. Claims Are Not Identities

Automation, AI-relatedness, identity confidence and risk MUST stay four independent
scores, each with named evidence ([ADR 0002](../../docs/adr/0002-separate-score-dimensions.md)).
A User-Agent, a header or any other request-controlled value MUST yield at most a
`claimed` identity. Only independent evidence may raise it: official ranges,
forward-confirmed reverse DNS, or a verified Web Bot Auth signature bound to its authority
([ADR 0006](../../docs/adr/0006-provider-agent-binding-scope.md)). Evidence that is missing,
stale or operationally unavailable MUST resolve to a neutral outcome, never to `failed`.

*Rationale:* treating a claim as proof is the most common error in this field, and the
most exploitable one.

### III. Privacy by Construction

Raw IP addresses, cookies, query strings, request bodies and signature material MUST NOT
be persisted. Addresses become keyed pseudonyms. Verification material lives only in a
non-serializable context ([ADR 0003](../../docs/adr/0003-ephemeral-verification-context.md)).
Anything shared beyond the local workspace, a warehouse included, MUST be aggregate only
([ADR 0008](../../docs/adr/0008-aggregate-only-warehouse-export.md)). A new feature or data
field MUST document its privacy and re-identification risk before use.

*Rationale:* data that is never stored cannot leak, and cannot be repurposed.

### IV. Evaluation That Cannot Flatter the Model (NON-NEGOTIABLE)

A model is better only if the evidence survives these rules:

- Labels come from a recorded, authorized condition, never from a route, a pacing pattern
  or a header.
- Every column that could encode the label stays out of the model table. The feature
  firewall enforces this ([ADR 0007](../../docs/adr/0007-pf2-feature-firewall.md)).
- Splits are grouped by session, task and participant, and include a forward-chained
  temporal holdout. Request-random splits are never evidence.
- Every candidate is compared with a constant baseline, and a more complex model with the
  simpler one. It wins only when its session-cluster lower bound clears the rung below.
- Every claim is tested against a null control that must not be detected.
- Reports state what was not established: generalization, population false-positive
  rate, calibration and operating threshold.

*Rationale:* a perfect score on a confounded design is worthless, and this project has
already produced one (see `docs/case-study.md`).

### V. Standards Are Pinned and Proven

Internet-Draft revisions MUST be pinned in `StandardsProfile` and MUST NOT advance
silently. `ati standards health` detects drift; adopting a new revision requires a written
review of its normative changes. Where a standard publishes test vectors, they MUST run
through the real verification chain in the test suite. Provider sources follow the
policy ATI sets, not their HTTP caching metadata
([ADR 0009](../../docs/adr/0009-range-snapshot-validity.md)).

*Rationale:* the standards are moving targets. Their own vectors and live data found four
defects that unit tests built from ATI's own assumptions did not.

### VI. Minimal Dependencies, Fail Closed

The deterministic core MUST use the Python standard library only. Cryptography is an
optional extra ([ADR 0004](../../docs/adr/0004-optional-crypto-dependency.md)), and a missing
extra MUST degrade to a neutral outcome. Input that is malformed, out of contract or
ambiguous MUST be refused with a stated reason, never repaired or guessed. Analysis MUST
NOT contact the network. Source refresh is an explicit, separate operation that never
follows a request-controlled URL
([ADR 0005](../../docs/adr/0005-registry-only-signature-agent-discovery.md)).

*Rationale:* every dependency and every silent repair widens the audit surface.

### VII. Evidence Over Assertion

A behaviour change MUST come with a test that fails without it. Before a fix, the failure
MUST be reproduced. A refactor MUST leave its outputs unchanged, proven byte for byte
where outputs exist. A claim in documentation about another project, a paper or live
infrastructure MUST cite its source and date. Measurements are recorded as dated evidence
documents under `docs/architecture/`.

*Rationale:* a reviewer should be able to check every statement this project makes.

## Technical Constraints

- Python 3.11 or later; `mypy --strict` and `ruff` clean; Hypothesis for parsers,
  address logic and evaluation splits.
- The test suite MUST keep at least 85% coverage and MUST pass without the optional
  `verification` extra installed.
- CI installs hash-pinned dependencies. A new runtime dependency in the core requires an
  ADR.
- Public surfaces keep a facade or are versioned explicitly
  (`docs/architecture/modular-boundaries.md`).

## Development Workflow

- New features follow Spec Kit: `/speckit-specify`, `/speckit-plan` (whose Constitution
  Check gates the design against this document), `/speckit-tasks`, `/speckit-implement`
  and `/speckit-converge`. Specifications live under `specs/`.
- A decision that is costly to reverse is recorded as an ADR before it is merged.
- `make check` (lint, types and every test profile) MUST pass before a pull request is
  opened. CI MUST be green before it is merged.
- The relative-link test keeps documentation navigable; dated evidence records are never
  rewritten, only superseded.

## Governance

This constitution takes precedence over other practice documents. Where an ADR and this
constitution disagree, the newer accepted decision wins, and this document MUST be amended
in the same pull request.

- **Amendment:** a pull request that changes this file states the version bump and its
  reason. Removing or redefining a principle requires an ADR.
- **Versioning:** MAJOR for a principle removed or redefined, MINOR for one added or
  materially expanded, PATCH for clarifications.
- **Compliance:** every `plan.md` carries a Constitution Check. A violation is allowed
  only with a recorded justification in its Complexity Tracking table, and reviewers
  check that the justification holds.

**Version**: 1.0.0 | **Ratified**: 2026-11-20 | **Last Amended**: 2026-11-20
