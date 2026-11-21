# Implementation Plan: Content-Conditional Timing

**Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/002-content-conditional-timing/spec.md`

## Summary

The work makes the laboratory able to record reading behaviour, then gives ATI a feature
that reads it:

- **Laboratory.** The closed catalogue gains, for each page, a reading load (`short` or
  `long`) and the text the page shows. The catalogue version moves to
  `ati-pf2-catalogue-2`. The origin renders pages from that text. The executor gains
  scenario `ati-pf2-1.1`: it fetches assets right after their page, and it shows a
  consenting participant each page's text before asking them to continue.
- **ATI.** ATI pins the reading loads and adds a `content_tempo` family with one feature,
  `dwell_ratio_bucket`: mean dwell on long pages over mean dwell on short pages, in four
  buckets.
- **Planner.** The planner gains a reading scenario and two new adversaries. The
  distribution mimic places person-like pauses without regard to content. The
  content-aware mimic places them by content. A laboratory runbook explains how to
  collect the real cohort.

## Technical Context

**Language/Version**: Python 3.11+ (both repositories); JavaScript only for the Worker,
which is unchanged here

**Primary Dependencies**: standard library in ATI. The laboratory keeps FastAPI for the
origin and adds nothing.

**Storage**: N/A. Fixtures and local corpus files only.

**Testing**: pytest in both repositories, with characterization digests for existing
simulations, and parity tests on both sides of the catalogue contract

**Target Platform**: CPython 3.11-3.13; the origin on Railway behind the Cloudflare
Worker

**Project Type**: library and CLI (ATI); web origin, executor CLI and corpus builder
(laboratory)

**Performance Goals**: a reading-scenario sweep of 20 corpora per adversary in minutes,
as in spec 001

**Constraints**: the keypress scenario and every existing corpus reproduce exactly. No
route is added or removed. No raw timing is retained. The Worker's closed route
catalogue is unchanged, because the paths are unchanged.

**Scale/Scope**: about six source files in each repository, plus tests and documents

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status |
|---|---|---|
| I. Observe before enforce | Measurement only | Pass |
| II. Claims are not identities | Behavioural evidence only; the evidence record states that a content-aware mimic defeats it | Pass |
| III. Privacy by construction | One four-level ratio of dwell times already derived in memory. Page texts are fixed filler with no personal data. Participant codes are opaque. The family is reviewed in feature contract 1.2 | Pass |
| IV. Evaluation that cannot flatter the model | Three adversaries plus a null. The content-aware mimic must not be detected, and its detection would mean leakage. Grouped and temporal splits unchanged | Pass, and strengthened |
| V. Standards pinned and proven | Not affected | Pass |
| VI. Minimal dependencies, fail closed | No dependency. A route without a declared load, or a scenario mismatch, is refused. The corpus builder already refuses a scenario version that occurs in one class only | Pass |
| VII. Evidence over assertion | Characterization digests captured before any change; parity tests on both sides; reproduce commands in the evidence record | Pass |

Laboratory ADR 0001 (one catalogue is the contract) is extended rather than broken: the
texts and loads live in the catalogue, so the origin, the executor and ATI cannot drift.

**Post-design re-check**: unchanged; no violations.

## Project Structure

### Documentation (this feature)

```text
specs/002-content-conditional-timing/
├── plan.md  research.md  data-model.md  quickstart.md  tasks.md
├── contracts/catalogue-and-feature.md
└── checklists/requirements.md
```

### Source Code

```text
agent-traffic-intelligence/
├── src/agent_traffic_intelligence/evaluation/pf2/
│   ├── protocol.py       # PF2_READING_LOAD, content_tempo family, dwell ratio
│   └── simulation.py     # reading scenario, content-blind and content-aware mimics
├── src/agent_traffic_intelligence/cli.py      # --scenario, new automation models
└── tests/evaluation/     # parity, feature, simulation digests and adversaries

ati-observation-lab/
├── src/observation_lab/pf2/catalogue.json     # reading_load, text; version 2
├── src/observation_lab/pf2/catalogue.py       # READING_LOAD, PAGE_TEXT
├── src/observation_lab/app.py                 # pages rendered from the catalogue
├── src/observation_lab/pf2/executor.py        # scenario 1.1, shows text, auto assets
├── docs/pf2-collection-runbook.md             # FR-009
└── docs/feature-contract.md                   # 1.2
```

**Structure Decision**: extend the existing modules. The catalogue stays the single
contract (laboratory ADR 0001).

## Complexity Tracking

No constitution violations to justify.
