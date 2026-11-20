---
description: "Task list for Adversarial Timing Robustness"
---

# Tasks: Adversarial Timing Robustness

**Input**: Design documents from `specs/001-adversarial-timing/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/cli-and-api.md](contracts/cli-and-api.md)

**Tests**: required. Constitution principle VII asks every behaviour change for a test
that fails without it, and FR-004 needs a characterization test captured before any code
changes.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency)
- **[Story]**: the user story a task belongs to

## Phase 1: Setup

- [X] T001 Record the characterization digest: the SHA-256 of `simulate_matched_corpus`
  records, labels, tasks, windows and groups for `linger` and `lognormal` at
  `sessions_per_cell=2, participants=12, seed=7`, computed on the unchanged code, and
  write it into a new test in `tests/evaluation/test_pf2_simulation.py` (FR-004, SC-001)

## Phase 2: Foundational

- [X] T002 Add `AutomationPauseModel` (`timer`, `imitate`) with docstrings to
  `src/agent_traffic_intelligence/evaluation/pf2/simulation.py`
  ([data-model.md](data-model.md) `AutomationPauseModel`)
- [X] T003 Add the shared validation `_validated_imitation(automation_model, fidelity)`
  to `src/agent_traffic_intelligence/evaluation/pf2/simulation.py`: refuse fidelity
  outside [0, 1] and a non-zero fidelity with `timer` (FR-005; data-model.md
  `Imitation fidelity`; research R5)

**Checkpoint**: T001 still passes, and nothing yet changes behaviour.

## Phase 3: User Story 1 - Test detection against imitating automation (P1) MVP

**Goal**: an imitating automation exists, and at fidelity 1 it behaves as a null.

**Independent Test**: at the recommended design, `plan_collection` with `imitate` at
fidelity 1 detects at most the null's rate, and `timer` output is unchanged (T001).

- [X] T004 [US1] Write failing tests in `tests/evaluation/test_pf2_simulation.py`:
  imitating automated pauses at fidelity 1 are drawn person-like (their spread exceeds
  the timer's range for `linger`); fidelity 0 under `imitate` equals `timer`
  byte for byte; human sessions are identical across fidelities for one seed
  (research R3); no persona is shared with a participant (R2)
- [X] T005 [US1] Implement imitation in `simulate_matched_corpus` in
  `src/agent_traffic_intelligence/evaluation/pf2/simulation.py`: always draw the timer
  pause from the main generator; with a second generator seeded from the corpus seed,
  draw one persona per imitating automated session (data-model.md `Persona.pace`,
  `Persona.irregularity`) and replace each pause with probability fidelity by
  `_pause(...)` for that persona (FR-001, FR-002, FR-003; research R1-R3)
- [X] T006 [US1] Thread `automation_model` and `imitation_fidelity` through
  `plan_collection` and add them to the plan JSON (FR-006; data-model.md
  `Collection plan.automation_model`, `Collection plan.imitation_fidelity`)
- [X] T007 [US1] Add the null test in `tests/evaluation/test_pf2_simulation.py`:
  `lognormal` at `imitate`, fidelity 1, 12 participants, 72 sessions, 3 repeats detects
  0 times (SC-002, fast form)

**Checkpoint**: User Story 1 is complete and independently testable.

## Phase 4: User Story 2 - Map degradation as imitation improves (P2)

**Goal**: the CLI runs any fidelity and refuses invalid input.

**Independent Test**: the CLI writes a plan that records its fidelity, and exits 2 with a
reason for invalid combinations.

- [X] T008 [US2] Add `--automation-model` and `--imitation-fidelity` to
  `ati pf2-simulate` in `src/agent_traffic_intelligence/cli.py` (FR-007;
  [contracts/cli-and-api.md](contracts/cli-and-api.md))
- [X] T009 [P] [US2] Add CLI tests in `tests/evaluation/test_pf2_simulation.py`: the
  plan records `imitate` and the fidelity; fidelity 1.5 and fidelity 0.5 with `timer`
  each exit 2 with a reason and write nothing (FR-005)
- [X] T010 [P] [US2] Export `AutomationPauseModel` from
  `src/agent_traffic_intelligence/evaluation/pf2/__init__.py` (contract)

**Checkpoint**: User Stories 1 and 2 both work independently.

## Phase 5: User Story 3 - Report the robustness frontier (P3)

**Goal**: the evidence record states how detection degrades with imitation.

**Independent Test**: the evidence record has Evidence 4 with the sweep, the reproduce
commands and the synthetic-only limitation.

- [X] T011 [US3] Run the five-step sweep (fidelity 0, 0.25, 0.5, 0.75, 1) for `linger`
  and `lognormal` at 12 participants, sessions-per-cell 2, 20 repeats, per
  [quickstart.md](quickstart.md) step 3 (SC-003)
- [X] T012 [US3] Add Evidence 4 to `docs/architecture/pf2-model-improvement-evidence.md`:
  the detection rate per fidelity, the fidelity at which detection falls below 50% or a
  statement that it never does, the reproduce commands and the synthetic-only limitation;
  update its "does not establish" list (FR-008, SC-004)

## Phase 6: Polish and Cross-Cutting

- [X] T013 [P] Update `CHANGELOG.md` and the `pf2-simulate` paragraph in `README.md`
- [X] T014 Run `make check` and the identity profile without the optional extra; confirm
  coverage stays at or above 85%

## Dependencies and Execution Order

- T001 before every code change (it captures today's behaviour).
- Phase 2 (T002, T003) before Phase 3.
- US1 (T004-T007) before US2: the CLI exposes what US1 implements.
- US3 (T011, T012) after US1 and US2: the sweep uses the CLI.
- Polish last.

## Parallel Opportunities

- T009 and T010 touch different files and can run together after T008.
- T013 can run alongside T011.

## Implementation Strategy

MVP is User Story 1: an imitating adversary and the proof that a perfect mimic is a
null. User Story 2 makes it usable from the command line, and User Story 3 turns it into
a stated limit on what timing shape can claim.

## Phase 7: Convergence

- [X] T015 State in Evidence 4 of `docs/architecture/pf2-model-improvement-evidence.md` the fidelity band where detection falls below 50% (between 0.25 and 0.5) per SC-004 (partial)
- [X] T016 Add a test in `tests/evaluation/test_pf2_simulation.py` that imitating the `uniform` human model runs and reports per spec edge case "With the `uniform` human model, imitation changes nothing" (partial)
