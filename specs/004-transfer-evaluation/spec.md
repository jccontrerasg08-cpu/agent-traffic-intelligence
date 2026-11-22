# Feature Specification: Transfer Evaluation and a Human Reference

**Feature Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf`

**Created**: 2026-11-22

**Status**: Implemented

**Input**: "See how to upgrade our model and investigation."

## Context

Every evaluation so far scored the model on the adversary it was trained against. Two
findings showed why that flatters it:

- In Iliou et al.'s public dataset (Evidence 5), advanced bots dwell more in proportion to
  page length than people do.
- The ladder's logistic rung reads each bucket as one number, so it can only learn "higher
  is more human" or the reverse. Trained against a timer, it should score a bot that
  overdoes reading as more human than people. A scratch run confirmed it (AUC 0.16).

## User Stories

### US1 - Evaluate against unseen automation (P1)

An analyst trains on one adversary and scores another, with different people, and sees
for each score how often it ranks the automation as more human than the people.

**Acceptance**: `ati pf2-transfer` writes a fixture-marked report with each score's mean
AUC, minimum AUC and inverted rate; inconsistent options are refused and nothing is
written.

### US2 - An adversary that overdoes reading (P1)

**Acceptance**: `overread` needs the reading scenario, and its long-over-short dwell ratio
exceeds people's by about 1.6 times; under the null it ignores content like everyone else.

### US3 - A score that does not extrapolate (P2)

**Acceptance**: a human-reference score, learned from the training people only, is not
inverted on average against `overread`, while the logistic rung is; against the null
every score stays near 0.5.

## Requirements

- **FR-001**: The keypress scenario, every existing adversary and every existing corpus are
  unchanged; the load factors pinned with the laboratory are unchanged.
- **FR-002**: The human reference reads only the scale-free families `tempo_shape` and
  `content_tempo`, so the pacing regime cannot drive it.
- **FR-003**: Test corpora use different seeds from training corpora, so no person appears
  in both.
- **FR-004**: The evidence record reports the sweep, the null and the reproduce command.

## Success Criteria

- **SC-001**: Trained on `timer`, the logistic rung is inverted against `overread` in at
  least 90% of repeats; the human reference in at most 10%. Met: 100% and 5%.
- **SC-002**: Against the null, every score's mean AUC lies within 0.35 to 0.65. Met: 0.51 to
  0.52.

## Out of scope

Adding the human reference as a rung of `ati pf2-baseline` and its reports. That changes
the baseline report and export schemas, and should follow the first real corpus.
