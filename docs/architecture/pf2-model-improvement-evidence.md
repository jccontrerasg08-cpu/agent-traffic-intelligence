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

## Evidence 4: an adversary that imitates people

*Added 2026-11-20 by [spec 001](../../specs/001-adversarial-timing/spec.md).*

The evidence above only faced a plain timer. Here, simulated automation imitates people:
at fidelity *f*, each automated pause is replaced, with probability *f*, by one drawn the
way the human model draws it. The traits for that draw belong to a persona the automated
session samples for itself, never a participant's. Imitation uses its own random stream,
so all fidelities score the same human sessions. At fidelity 0 the corpora are
byte-identical to those above, which a characterization test enforces. The design is the
recommended one: 12 participants, 72 sessions, participant-grouped splits, 20 corpora
per cell.

| Imitation fidelity | 0 | 0.25 | 0.5 | 0.75 | 1 |
|---|---:|---:|---:|---:|---:|
| `linger`: detected | 95% | 50% | 15% | 0% | 0% |
| `linger`: mean PR-AUC | 0.91 | 0.75 | 0.62 | 0.58 | 0.54 |
| `lognormal`: detected | 90% | 50% | 15% | 15% | 0% |
| `lognormal`: mean PR-AUC | 0.85 | 0.74 | 0.59 | 0.61 | 0.55 |

**Timing shape is a fragile signal.** Detection falls below 50% between fidelity 0.25 and
0.5. Imitating a quarter of the pauses halves it, to 50%, and imitating half of them leaves
15%,
which is close to the null. A perfect mimic is not detected at all, as it must not be,
since it is a null. The step from 0.5 to 0.75 for `lognormal` (15% and 15%) is within the
sampling error of 20 corpora.

What follows for the project:

- Timing shape can support a classification against unsophisticated automation, but it
  is cheap to defeat. It must never stand in for identity, which already comes only from
  verification (constitution principle II).
- Any later real-data claim about timing shape must say that it does not survive
  imitation, and quote this curve.
- The laboratory can test a real adversary only once its executor gains an imitating
  pacing mode. That is a separate feature.

## Evidence 5: pauses that follow the content

*Added 2026-11-21 by [spec 002](../../specs/002-content-conditional-timing/spec.md).
Synthetic data only.*

Evidence 4 left a gap: a mimic that draws person-like pauses defeats timing shape. Such a
mimic copies *how long* people pause, not *where*. In the laboratory's reading scenario
`ati-pf2-1.1`, every page declares a reading load in the closed catalogue, and a person's
dwell on a page scales with it. The `content_tempo` family asks one question: is mean
dwell on long pages larger than on short ones (`dwell_ratio_bucket`)?

Three adversaries are run against the same human sessions: the plain timer; `imitate`,
which draws person-like pauses but places them on a shuffled order of the session's pages;
and `imitate-content`, which also places them by each page's load. In the null (`uniform`),
people pause like the timer and ignore content as it does. The design is the recommended
one: 12 participants, 72 sessions, participant-grouped splits, 20 corpora per cell.

| Adversary | Fidelity | `lognormal`: detected · PR-AUC | `linger`: detected · PR-AUC |
|---|---:|---:|---:|
| timer | 0 | 100% · 0.93 | 100% · 0.94 |
| `imitate` | 0.5 | 90% · 0.83 | 95% · 0.88 |
| `imitate` | 1 | 90% · 0.84 | 90% · 0.85 |
| `imitate-content` | 0.5 | 15% · 0.65 | 55% · 0.73 |
| `imitate-content` | 1 | 0% · 0.55 | 0% · 0.54 |
| null (`uniform`) | — | 0% · 0.54 | |

Without the `content_tempo` family, on the same corpora:

| Adversary | Fidelity | `lognormal`: detected · PR-AUC | `linger`: detected · PR-AUC |
|---|---:|---:|---:|
| `imitate` | 0.5 | 35% · 0.67 | 20% · 0.64 |
| `imitate` | 1 | 5% · 0.57 | 10% · 0.58 |

**Where a pause falls survives imitation of how long it is.** A full distribution mimic
goes from 5–10% detected to 90%. A mimic that also follows the content is not detected,
as it must not be: it is a null for this feature. At half fidelity the `linger` model is
still detected 55% of the time, because its overlong pauses are not part of what the
content-aware mimic copies. The null is never detected.

A first run of this sweep found the null detected in 20 of 20 corpora. Simulated people
under the null still followed the content, so they were not indistinguishable from the
timer. The fix makes the null content-blind, and a test now holds it below detection
(spec 002, task T020).

### External check on a public dataset

Iliou et al.'s web bot detection dataset (m4d.iti.gr, CC BY-NC-SA 4.0) is the closest
public match to this protocol: labels come from the condition, with humans browsing a
Wikipedia-derived site and bots driven by the authors, "moderate" and "advanced". The
latter imitate human browsing. It stays outside both repositories because of its licence.
Its web logs give page navigations to the second. We used response size as a proxy for
reading load, split at the median page, and dropped gaps over ten minutes. `ati
external-check --archive dataset.zip --output report.json` reproduces the table from the
archive you download; the report holds aggregates only.

| Comparison | Human ratio (median) | Bot ratio (median) | AUC, human > bot |
|---|---:|---:|---:|
| Phase 1, moderate bots | 1.58 | 0.93 | 0.73 |
| Phase 1, advanced bots | 1.46 | 2.26 | 0.25 |
| Phase 2, advanced bots | 1.37 | 2.62 | 0.19 |

The moderate bots ignore content, and the ratio separates them as the simulation
predicts. The advanced bots go further than any content-aware mimic modelled here: they
dwell *more* in proportion to page length than people do. A detector that takes "dwell
follows content" as the human signature would flag the people. In the same logs,
navigation timing alone does not separate humans from phase-1 advanced bots (AUC
0.41–0.49 across median gap, coefficient of variation and longest gap). Two caveats:
response size is a rough proxy for reading load, and phase-2 human sessions are about six
times longer than bot sessions, so most of the separability there is session length, a
protocol artefact the matched design exists to prevent.

What follows for the project:

- `content_tempo` raises the cost of imitation; it does not close the gap. Content-aware
  bots exist in public data today.
- The ratio's direction must be learned from the matched corpus, never assumed.
- Any real-data claim must report the content-aware mimic beside the distribution mimic.

## Evidence 6: the instrument, live

*Added 2026-11-22 by [spec 003](../../specs/003-laboratory-adversary/spec.md). Real
infrastructure, automated sessions only.*

Evidences 1 to 5 ran on synthetic corpora. This run checks the whole path on the deployed
laboratory: the executor, the Cloudflare Worker at `observe.ati-observation-lab.com`, the
Railway origin, an export of the origin's privacy-safe rows, the laboratory's corpus
builder and ATI's features. Eighteen automated sessions ran in the reading scenario
`ati-pf2-1.1` on 2026-11-22, regime H1, six per adversary, alternating the two tasks.

All 18 sessions were accepted. The export held exactly 126 rows, seven per session, and
the corpus builder reconciled every session with no unmatched identifier. It flagged each
corpus as single-class, as it must without the consented cohort. Measured on the origin's
timestamps:

| Adversary | Dwell ratio, median (range) | `dwell_ratio_bucket` | Pause CV, median | Asset after page, max |
|---|---:|---|---:|---:|
| `timer` | 1.16 (0.93–1.32) | 0, 0, 1, 1, 1, 1 | 0.26 | 0.24 s |
| `imitate` | 0.80 (0.39–1.61) | 0, 0, 0, 0, 1, 1 | 0.45 | 0.23 s |
| `imitate-content` | 2.02 (1.33–5.17) | 1, 1, 1, 2, 3, 3 | 0.38 | 0.30 s |

What it shows:

- **The edge and the network do not erase the behaviour.** The ratios land where each
  adversary aims: about 1 for both content-blind pacings, about 2 for the content-aware
  one, whose factors are 1.6 over 0.8. Person-like pauses are more irregular than the
  timer's, as tempo shape expects.
- **Assets follow their page within a third of a second**, so the reading scenario's
  assumption holds in production (spec 002, SC-004).
- **Bucket 0 conflates two cases.** A ratio below 1 and a session without a measurable
  dwell on both loads share bucket 0. In the reading scenario every session has both, so
  the conflation costs nothing today, but four of six `imitate` sessions landed there for
  the first reason.
- **The direction of the ratio is not monotone in the threat model.** People sit near 2,
  timers near 1, and Evidence 5's advanced bots above people. A logistic rung that reads
  each bucket as one number can only learn "higher is more human", so it would score a
  bot that over-reads as more human than people. Spec 004 addresses this.

Six sessions per adversary say nothing about detection rates; they validate the instrument.

To reproduce, run the sessions with `ati-lab-session --scenario-version ati-pf2-1.1
--cohort automated --automation-pacing <adversary>`, export the origin's rows for the
window from Railway's logs as one JSON object per row, reconcile each adversary's
directory with `ati-lab-corpus --diagnostic`, and read the features from the corpus's
`access.jsonl`.

## Evidence 7: automation the model has never seen

*Added 2026-11-22 by [spec 004](../../specs/004-transfer-evaluation/spec.md). Synthetic data
only.*

Every evidence above scores the model on the adversary it was trained against. A deployed
detector meets new automation. `ati pf2-transfer` trains on one synthetic corpus and scores
a second with different people and a different adversary. It compares three scores: the
ladder's logistic rung; a **human reference**, which learns only what people do (the share
of people showing each value of the scale-free features in `tempo_shape` and
`content_tempo`) and flags whatever departs from them; and their **combination**, each as
its percentile among the training people, taking the larger. The new adversary
`overread` follows the content but overdoes it, with a long-over-short ratio about 1.6
times a person's, as the advanced bots of Evidence 5 do.

Reading scenario, 12 participants, 72 sessions per corpus, `lognormal` people, 20 repeats.
Each cell is the mean AUC, then the share of repeats below 0.5 (the score ranked the
automation as more human than the people):

| Trained on | Tested on | Logistic | Human reference | Combined |
|---|---|---:|---:|---:|
| `timer` | `timer` | 0.94 · 0% | 0.82 · 0% | 0.88 · 0% |
| `timer` | `imitate` | 0.65 · 5% | 0.69 · 0% | 0.68 · 0% |
| `timer` | `imitate-content` | 0.49 · 65% | 0.50 · 60% | 0.48 · 70% |
| `timer` | `overread` | **0.23 · 100%** | **0.67 · 5%** | 0.60 · 10% |
| `imitate` | `timer` | 0.75 · 0% | 0.82 · 0% | 0.81 · 0% |
| `imitate` | `imitate` | 0.80 · 0% | 0.69 · 0% | 0.74 · 0% |
| `imitate` | `overread` | **0.30 · 100%** | **0.67 · 5%** | 0.61 · 10% |

`linger` people give the same picture within 0.05. Against the null (`uniform` people)
every score stays between 0.51 and 0.52.

What it shows:

- **The logistic rung is best on what it was trained on and inverted on an overreader.**
  It learns that long dwell on long pages means a person, and extrapolates: a bot that
  overdoes it scores as more human than people, in every repeat.
- **The human reference never inverts on average.** It does not need to have seen the
  adversary, because it models people only. It gives up some power against the known
  adversary (0.82 against 0.94).
- **A content-aware mimic that matches people stays undetected by every score**, as it
  must: it is a null for these features.
- Indicator (one-hot) coding of the buckets, tried first, did not fix the inversion
  (0.29 against 0.16 in a scratch run), because people also reach the high buckets.

What follows for the project:

- A real-data report must state which adversary each score was trained on, and include
  the human reference beside the logistic rung.
- The human reference can be fitted from the consented cohort alone, so the first real
  corpus can yield it even before any adversary corpus exists.

## What this does not establish

- That real people pause like either human model. They may be more regular than
  `lognormal` or less than `linger`, and only the consented cohort can tell.
- Any performance on public traffic, a population false-positive rate, calibration or an
  operating threshold.
- How a real adversary imitates. Evidence 4 models imitation as a share of person-like
  pauses. A bot that learns from observed traffic, or that imitates only some steps, may
  do better or worse, and no real imitating automation has been run through the
  laboratory.

## Reproduce

```bash
ati pf2-simulate --human-model lognormal --sessions-per-cell 1 2 4 \
  --participants 12 --repeats 20 --output plan-lognormal-12.json
ati pf2-simulate --human-model uniform --sessions-per-cell 1 2 4 \
  --participants 12 --repeats 20 --output plan-null-12.json
```

Evidence 4, one fidelity at a time:

```bash
for f in 0 0.25 0.5 0.75 1; do
  ati pf2-simulate --human-model lognormal --sessions-per-cell 2 --participants 12 \
    --repeats 20 --automation-model imitate --imitation-fidelity "$f" \
    --output "imitate-lognormal-$f.json"
done
```

Evidence 5, in the reading scenario:

```bash
ati pf2-simulate --scenario reading --human-model uniform --sessions-per-cell 2 \
  --participants 12 --repeats 20 --output reading-null.json
for model in imitate imitate-content; do
  for f in 0.5 1; do
    ati pf2-simulate --scenario reading --human-model lognormal --sessions-per-cell 2 \
      --participants 12 --repeats 20 --automation-model "$model" \
      --imitation-fidelity "$f" --output "reading-$model-$f.json"
  done
done
```

Evidence 7, one cell:

```bash
ati pf2-transfer --human-model lognormal --sessions-per-cell 2 --participants 12 \
  --repeats 20 --train-automation-model timer \
  --test-automation-model overread --test-imitation-fidelity 1 --output transfer.json
```

`--sessions-per-cell` 1, 2 and 4 give corpora of 36, 72 and 144 sessions. Evidence 1 and 2
came from the same generator without person-level variation, so they isolate the effect
of the features and of the model from the effect of person-to-person differences.
