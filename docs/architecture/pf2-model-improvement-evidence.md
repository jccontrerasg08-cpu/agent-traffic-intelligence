# ATI-PF-2 Model Improvement Evidence

**Date:** 2026-10-05
**Data:** synthetic matched-executor **fixtures only**. No traffic and no person is in
any number below.
**Question:** how can the ladder tell consenting people from paced automation better,
under the matched-executor design where everything except timing is shared?

This record separates what the fixtures show from what they cannot. They show which
changes let the pipeline detect a difference *if one exists*. They do not show that real
people pause differently from a timer.

## Diagnosis: the features could not see the behaviour under study

In the matched design both cohorts follow the same H1–H3 pacing regimes. The automated
cohort draws each pause uniformly from the regime's range, while a person is shown that
range as guidance and chooses each pause. The only remaining difference is therefore
*how pauses vary inside a regime*.

The tempo family binned pauses on absolute boundaries (1, 4 and 16 s). Every H1 pause
(5–12 s) falls into one bin, and so does every H3 pause (25–45 s), whoever chose it.
More data cannot fix that, and the evidence agrees. With the old features, detection
stays near zero and PR-AUC near 0.6 at every corpus size, from 36 to 288 sessions.

## Changes

| Change | Where | Why |
|---|---|---|
| **Tempo-shape family**: four-level buckets of the pauses' coefficient of variation and of the longest pause over the median one | `evaluation/pf2/protocol.py` | Ratios capture the shape of the pauses, so a regime that rescales them cannot move the value; and they reveal no absolute time. Laboratory feature contract 1.1. |
| **Participant-grouped splits**: an optional audit-only `group` column; the grouped holdout sets aside whole people, and every split drops from training the sessions of anyone in its holdout | `evaluation/pf2/baseline.py`, `ati pf2-preflight --groups-by-session` | When one person contributes several sessions, splitting by session scores a model on someone it was trained on (Kapoor and Narayanan's non-independence leakage). |
| **Participant codes** such as `p01`, recorded by the executor and written to `groups-by-session.json` | laboratory `ati-lab-session --participant`, `ati-lab-corpus` | The corpus builder refuses a consented cohort with an uncoded session or fewer than two participants. |
| **`ati pf2-simulate`**: a power analysis on synthetic corpora with person-level pace | `evaluation/pf2/simulation.py` | Recruitment is planned before anyone is asked to take part. |

## Evidence 1: the new features detect what the old ones could not

Twenty independent corpora per row. In each, the logistic rung counts as detecting only
when its session-cluster lower bound clears the constant baseline on the final temporal
holdout. Three human models are used: `uniform` is the null, identical to the timer;
`linger` runs past the range on 30% of pauses; `lognormal` aims at the middle of the
range with a right-skewed spread.

| Human model | Sessions | Old features: detected / mean PR-AUC | With tempo shape |
|---|---:|---|---|
| uniform (null) | 72 | 0/20 · 0.52 | 0/20 · 0.56 |
| uniform (null) | 288 | 0/20 · 0.50 | 0/20 · 0.52 |
| linger | 36 | 1/20 · 0.66 | 12/20 · 0.86 |
| linger | 72 | 2/20 · 0.61 | **19/20** · 0.87 |
| linger | 288 | 1/20 · 0.60 | **20/20** · 0.83 |
| lognormal | 36 | 0/20 · 0.55 | 10/20 · 0.82 |
| lognormal | 72 | 0/20 · 0.57 | **18/20** · 0.87 |
| lognormal | 288 | 0/20 · 0.56 | **20/20** · 0.85 |

Across all 80 null corpora with the new features, the ladder claimed a difference twice
(2.5%). So the stricter win rule controls false discoveries as intended.

## Evidence 2: a more complex model does not help

A dependency-free gradient-boosted decision-stump model (60 rounds, shrinkage 0.1, at
least 3 sessions per leaf) was compared with the L2 logistic rung on the same final
temporal holdouts, with the new features:

| Human model | Sessions | Mean PR-AUC, logistic | Mean PR-AUC, boosted stumps | Stumps better |
|---|---:|---:|---:|---:|
| linger | 72 / 144 | 0.84 / 0.85 | 0.83 / 0.81 | 3/10 · 3/10 |
| lognormal | 72 / 144 | 0.87 / 0.84 | 0.82 / 0.82 | 2/10 · 2/10 |
| uniform (null) | 72 / 144 | 0.58 / 0.55 | 0.51 / 0.52 | 2/10 · 4/10 |

At these sizes extra capacity only adds variance, so it was **not** added to the ladder.
Better separation came from a feature that can see the behaviour, not from a stronger
learner. The feature contract still allows a later rung, but only one that beats the
logistic on the final temporal holdout.

## Evidence 3: how many people to recruit

These runs use `ati pf2-simulate` with person-level variation: each simulated person has
their own pace, and for `lognormal` their own irregularity. Splits are grouped by
participant, so detection means generalizing to people the model never saw. Each
participant stays in one task and one collection window. Twenty corpora per cell.

| Human model | Participants | 36 sessions | 72 sessions | 144 sessions |
|---|---:|---:|---:|---:|
| uniform (null) | 6 | 0% | 0% | 5% |
| uniform (null) | 12 | 0% | 0% | 0% |
| linger | 6 | 65% | 75% | 95% |
| linger | 12 | 85% | **95%** | 100% |
| lognormal | 6 | 45% | 75% | 85% |
| lognormal | 12 | 40% | **90%** | 95% |

**Recommendation.** Recruit 12 participants, with 3 sessions each, one per regime H1,
H2 and H3, which is about six minutes per person. Match them with the same number of
automated sessions, for 72 in total. That design detects either modelled difference in
90–95% of simulated collections, while the null is never detected. With 6 participants
the same reliability needs about twice the sessions. Assign each participant to a single
task and collection window. Otherwise the participant-grouped temporal and task holdouts
lose their human training sessions, and the ladder refuses them.

## What this does not establish

- That real people pause like either human model. They may be more regular than
  `lognormal` or less than `linger`, and only the consented cohort can tell.
- Any performance on public traffic, a population false-positive rate, calibration or an
  operating threshold.
- That the tempo-shape family stays useful against automation built to imitate it. A
  timer that draws from a person-like distribution is the obvious next adversary, and the
  laboratory can test it with the same matched design.

## Reproduce

```bash
ati pf2-simulate --human-model lognormal --sessions-per-cell 1 2 4 \
  --participants 12 --repeats 20 --output plan-lognormal-12.json
ati pf2-simulate --human-model uniform --sessions-per-cell 1 2 4 \
  --participants 12 --repeats 20 --output plan-null-12.json
```

`--sessions-per-cell` 1, 2 and 4 give corpora of 36, 72 and 144 sessions. Evidence 1 and 2
came from the same generator without person-level variation, so they isolate the effect
of the features and of the model from the effect of person-to-person differences.
