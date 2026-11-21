# Implementation Plan: A Laboratory Adversary

**Spec**: [spec.md](spec.md)

## Summary

The laboratory's executor gains `--automation-pacing {timer, imitate, imitate-content}`
for the automated cohort, built on the same models as `ati pf2-simulate`. The corpus
builder records the adversary and refuses mixed corpora. ATI only pins the load factors
the laboratory mirrors; its features and splits are unchanged.

## Constitution Check

| Principle | Gate | Status |
|---|---|---|
| I. Observe before enforce | Measurement only | Pass |
| II. Claims are not identities | Behaviour only; adversaries make the limits measurable | Pass |
| III. Privacy by construction | The adversary's name is an audit field; no pause is recorded | Pass |
| IV. Evaluation that cannot flatter the model | One adversary per corpus, against the same human sessions | Pass, and strengthened |
| V. Standards pinned and proven | Not affected | Pass |
| VI. Minimal dependencies, fail closed | No dependency; unknown or misplaced values are refused | Pass |
| VII. Evidence over assertion | Tests pin behaviour and parity; one live session | Pass |

## Structure

```text
ati-observation-lab/src/observation_lab/pf2/executor.py   # AUTOMATION_PACINGS, LOAD_FACTOR, _Pacer
ati-observation-lab/src/observation_lab/pf2/corpus.py     # adversary in summary, mixed refused
agent-traffic-intelligence/tests/evaluation/test_pf2_simulation.py  # load-factor pin
```

The timer path draws nothing from the random stream beyond its own pause, so seeded timer
sessions are unchanged.
