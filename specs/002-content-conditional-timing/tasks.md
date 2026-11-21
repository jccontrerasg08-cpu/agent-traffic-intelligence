---
description: "Task list for Content-Conditional Timing"
---

# Tasks: Content-Conditional Timing

**Input**: Design documents from `specs/002-content-conditional-timing/`

**Tests**: required (constitution VII). Characterization digests are captured before any
change.

## Format: `[ID] [P?] [Story] Description`

## Phase 1: Setup

- [X] T001 Confirm that the spec 001 characterization digests pass on the unchanged code
  (`tests/evaluation/test_pf2_simulation.py`), and record a digest of
  `prepare_pf2_dataset` model rows for a keypress corpus in
  `tests/evaluation/test_pf2_protocol.py` (SC-003)

## Phase 2: Foundational - the catalogue contract

- [X] T002 [P] Add `reading_load`, `title` and `text` to every route in
  `ati-observation-lab/src/observation_lab/pf2/catalogue.json`, and bump the version to
  `ati-pf2-catalogue-2` (FR-001; data-model.md `Catalogue route.reading_load`,
  `Catalogue route.text`)
- [X] T003 Expose `READING_LOAD` and `PAGE_CONTENT` from
  `ati-observation-lab/src/observation_lab/pf2/catalogue.py`, and pin them, with the new
  version, in `ati-observation-lab/tests/test_pf2_catalogue.py` (FR-006)
- [X] T004 [P] Pin `PF2_READING_LOAD` and `PF2_CATALOGUE_VERSION = "ati-pf2-catalogue-2"`
  in `src/agent_traffic_intelligence/evaluation/pf2/protocol.py` and
  `tests/evaluation/test_pf2_catalogue_parity.py` (FR-006; data-model.md `ATI pin`)

## Phase 3: User Story 1 - Detect a mimic that ignores content (P1) MVP

- [X] T005 [US1] Write failing tests in `tests/evaluation/test_pf2_protocol.py`: a session
  that dwells longer on long pages lands in a higher `dwell_ratio_bucket` than one with
  dwell independent of load; asset requests do not count as dwell; a session with no
  short or no long dwell lands in bucket 0; the T001 model-row digest still matches for
  every pre-existing column
- [X] T006 [US1] Implement family `content_tempo` = (`dwell_ratio_bucket`) in
  `src/agent_traffic_intelligence/evaluation/pf2/protocol.py` (FR-005; data-model.md
  `Feature dwell_ratio_bucket`)
- [X] T007 [US1] Write failing tests in `tests/evaluation/test_pf2_simulation.py`: the
  reading scenario fetches assets within a second for both cohorts; people's dwell scales
  with load; `imitate` misplaces the loads and `imitate-content` places them; keypress
  digests are unchanged; `imitate-content` without `reading` is refused (FR-007)
- [X] T008 [US1] Implement `SimulatedScenario` and `AutomationPauseModel.IMITATE_CONTENT`
  in `src/agent_traffic_intelligence/evaluation/pf2/simulation.py`, using their own random
  stream (research R4, R5)
- [X] T009 [US1] Add `--scenario` and `imitate-content` to `ati pf2-simulate` in
  `src/agent_traffic_intelligence/cli.py`, with CLI tests (contract)
- [X] T010 [US1] Add a paired adversary test: in the reading scenario, `imitate` at
  fidelity 1 is detected far more often than `imitate-content` at fidelity 1 on the same
  human sessions (SC-001, SC-002, fast form)

## Phase 4: User Story 2 - Collect reading behaviour in the laboratory (P2)

- [X] T011 [US2] Render pages from the catalogue in
  `ati-observation-lab/src/observation_lab/app.py`, and test that each page serves its
  title and paragraphs and no outside link (FR-002)
- [X] T012 [US2] Add `--scenario-version` to `ati-lab-session` in
  `ati-observation-lab/src/observation_lab/pf2/executor.py`: in `ati-pf2-1.1`, fetch
  assets right after their page for both cohorts, show a participant each page's text,
  and prompt only before navigations; record the scenario version (FR-003, FR-004)
- [X] T013 [US2] Executor tests in `ati-observation-lab/tests/test_pf2_executor.py`: no
  asset prompt, the texts are shown in order, assets do not sleep, 1.0 is unchanged
  (SC-004)
- [X] T014 [P] [US2] Feature contract 1.2 in `ati-observation-lab/docs/feature-contract.md`
  (FR-008)

## Phase 5: User Story 3 - Know how to collect the real data (P3)

- [X] T015 [US3] Write `ati-observation-lab/docs/pf2-collection-runbook.md`: recruitment,
  consent and codes, the assignment table for 12 participants, the pilot, collection,
  reconciliation, evaluation and deletion (FR-009, SC-005)
- [X] T016 [US3] Link the runbook from the laboratory README, the docs map, the consent
  procedure and the datasheet

## Phase 6: Evidence and polish

- [X] T017 Run the reading-scenario sweep for the three adversaries and the null, then
  add Evidence 5 to `docs/architecture/pf2-model-improvement-evidence.md` (FR-010)
- [X] T018 [P] Update the CHANGELOG, the README and the ADR 0007 feature count in ATI, and
  the laboratory README's scenario description
- [ ] T019 Run `make check` in both repositories, the identity profile without the
  optional extra, and the live perimeter after the laboratory deploys

## Dependencies

T001 before any change. Phase 2 before Phases 3 and 4. US1 does not need US2, because the
simulation does not depend on the laboratory. US3 can start after T012. T017 needs T008
to T010. T019 comes last.

## Phase 7: Convergence

Assessed after T001-T018 against spec.md, plan.md and the code in both repositories.

- [X] T020 [US1] The reading-scenario sweep (T017) detected the `uniform` null in 20 of 20
  corpora: simulated people under the null still scaled their dwell by reading load, so
  they differed from the timer and the null was not a null (constitution IV). Make the null
  content-blind in `simulation.py` (`_follows_content`), and add tests that its dwell
  ratio stays near 1 and that the ladder does not detect it in the reading scenario
- [X] T021 [US3] The catalogue has two task branches, not three; the runbook's assignment
  table balances 6 participants per task and 2 per task in each window, and states the
  15-minute signed-session limit
- [X] T022 [P] External check (FR-010): run the dwell ratio on a public dataset with
  controlled labels (Iliou et al., web logs), kept outside both repositories because of
  its licence, and record the result in Evidence 5
