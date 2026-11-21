# Feature Specification: A Laboratory Adversary

**Feature Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf`

**Created**: 2026-11-21

**Status**: Implemented

**Input**: "Let the laboratory run a real adversary, so a model trained on the matched
corpus can be tested against automation that imitates people, not only against a timer."

## Context

Specs 001 and 002 tested timing features against adversaries that exist only in
`ati pf2-simulate`. The laboratory's automated cohort could only run a timer, so no real
corpus could ever show how a trained model fares against imitation. A public dataset
(Evidence 5) showed that content-aware bots already exist in practice.

## User Scenarios & Testing

### User Story 1 - Run an imitating automated session (P1)

An operator runs the automated cohort with `--automation-pacing imitate` or
`imitate-content`, through the same executor, edge, route plan and regimes as the timer.

**Acceptance**:

1. `imitate` draws person-like pauses from a persona of the session's own and places them
   without regard to the page.
2. `imitate-content` stretches each pause by the reading load of the page it leaves, and
   is refused outside the reading scenario `ati-pf2-1.1`.
3. The timer stays the default and draws exactly the pauses it drew before.
4. A consented session cannot take an automation pacing.
5. The record holds the adversary's name and never a pause.

### User Story 2 - One adversary per corpus (P2)

**Acceptance**:

1. The corpus builder records the adversary in its summary, and reads a record from
   before this feature as the timer.
2. It refuses a corpus whose automated sessions mix adversaries, so detection is always
   reported per adversary.
3. An unknown adversary, or one attached to a human session, fails closed.

## Requirements

- **FR-001**: The laboratory's imitation models and reading-load factors match those of
  `ati pf2-simulate`; both repositories pin the factors.
- **FR-002**: No raw pause is recorded; the adversary is an audit field, never a feature.
- **FR-003**: The runbook describes one adversary corpus per adversary, against the same
  human sessions as the timer corpus.

## Success Criteria

- **SC-001**: Over many seeded sessions, the content-aware mimic's long-over-short pause
  ratio exceeds 1.6, the content-blind mimic's stays under 1.4, and the timer's under 1.3.
- **SC-002**: A live `imitate-content` session through the production edge is accepted
  end to end.

Both hold: the executor tests check SC-001, and a live session on 2026-11-21 accepted all
seven requests (SC-002).

## Out of scope

Collecting the adversary corpora and evaluating on them. That waits for the consented
human cohort, as the runbook describes.
