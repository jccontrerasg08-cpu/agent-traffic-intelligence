# Implementation Plan: Adversarial Timing Robustness

**Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf` | **Date**: 2026-11-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-adversarial-timing/spec.md`

## Summary

Add an imitating automation to the ATI-PF-2 collection planner. Today every simulated
automated pause comes from a uniform timer. With imitation at fidelity *f*, each
automated pause is replaced, with probability *f*, by a pause drawn the way the selected
human model draws one. The traits for that draw come from a persona sampled per
automated session from the participant population. A separate random stream carries
every imitation draw, so fidelity 0 reproduces today's corpora byte for byte, and
different fidelities share the same human sessions (a paired sweep). Planner results
record the automation model and fidelity. The evidence record gains a fidelity sweep at
the recommended design.

## Technical Context

**Language/Version**: Python 3.11+

**Primary Dependencies**: standard library only (`random`, `math`, `dataclasses`, `enum`)

**Storage**: N/A. Plans are JSON written by the CLI.

**Testing**: pytest, with a characterization digest for FR-004 and the existing
Hypothesis setup available

**Target Platform**: any platform running CPython 3.11+, matching CI's 3.11, 3.12 and 3.13

**Project Type**: library plus CLI (`agent_traffic_intelligence.evaluation.pf2.simulation`,
`ati pf2-simulate`)

**Performance Goals**: a five-step fidelity sweep with 20 corpora per step at 72 sessions
in minutes on one machine (measured: about 1.2 s per corpus today)

**Constraints**: no new dependency, no new model feature, no change to the preflight or
the baseline; fidelity 0 output byte-identical to today's

**Scale/Scope**: one module (`evaluation/pf2/simulation.py`), its CLI wiring, tests, and
one evidence document

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status |
|---|---|---|
| I. Observe before enforce | Simulation only; nothing touches traffic | Pass |
| II. Claims are not identities | Not affected | Pass |
| III. Privacy by construction | Synthetic fixtures only; no new data field; output stays marked `fixture: true` | Pass |
| IV. Evaluation that cannot flatter the model | Adds an adversary to the evaluation. At fidelity 1 the run is a null and must behave like one (SC-002). No change to splits, firewall or ladder | Pass, and strengthened |
| V. Standards are pinned and proven | Not affected | Pass |
| VI. Minimal dependencies, fail closed | Standard library only; a fidelity outside [0, 1] or an inconsistent model and fidelity is refused with a reason | Pass |
| VII. Evidence over assertion | A characterization digest, captured before the change, proves FR-004. The null test fails if imitation leaks the label. The evidence record cites reproduce commands | Pass |

**Post-design re-check** (after Phase 1): unchanged. The design adds no dependency, no
persisted field and no model change. Complexity Tracking stays empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-adversarial-timing/
├── plan.md              # This file
├── research.md          # Phase 0: decisions on imitation and random streams
├── data-model.md        # Phase 1: automation pause model, fidelity, plan fields
├── quickstart.md        # Phase 1: commands that prove the feature end to end
├── contracts/
│   └── cli-and-api.md   # Phase 1: CLI flags, Python signature, plan JSON fields
├── checklists/
│   └── requirements.md  # /speckit-specify quality checklist
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
src/agent_traffic_intelligence/
├── evaluation/pf2/
│   ├── simulation.py    # AutomationPauseModel, imitation stream, plan fields
│   └── __init__.py      # export AutomationPauseModel
└── cli.py               # --automation-model, --imitation-fidelity

tests/evaluation/
└── test_pf2_simulation.py   # characterization digest, null at fidelity 1, refusals, CLI

docs/architecture/
└── pf2-model-improvement-evidence.md   # Evidence 4: robustness to imitation
```

**Structure Decision**: extend the existing simulation module in place. The feature is
one more option on an existing planner, so a new module would only add indirection.

## Complexity Tracking

No constitution violations to justify.
