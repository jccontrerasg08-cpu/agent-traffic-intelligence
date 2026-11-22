# Implementation Plan: Transfer Evaluation and a Human Reference

**Spec**: [spec.md](spec.md)

## Summary

`evaluation/pf2/transfer.py` trains the ladder's logistic rung and a human-reference score
on one synthetic corpus and scores a second built with new people and a chosen adversary.
`simulation.py` gains `AutomationPauseModel.OVERREAD`. `ati pf2-transfer` exposes it.

## Constitution Check

| Principle | Gate | Status |
|---|---|---|
| I. Observe before enforce | Offline evaluation only | Pass |
| II. Claims are not identities | Behaviour only | Pass |
| III. Privacy by construction | Synthetic fixtures; reads only existing permitted features | Pass |
| IV. Evaluation that cannot flatter the model | Trains and tests on different adversaries and people; the null is reported | Pass, and strengthened |
| V. Standards pinned and proven | Not affected | Pass |
| VI. Minimal dependencies, fail closed | Standard library; inconsistent options refused | Pass |
| VII. Evidence over assertion | Tests pin inversion, robustness and the null; sweep in Evidence 7 | Pass |

## Structure

```text
src/agent_traffic_intelligence/evaluation/pf2/transfer.py    # auc, human_reference, plan_transfer
src/agent_traffic_intelligence/evaluation/pf2/simulation.py  # OVERREAD, load factor per session
src/agent_traffic_intelligence/cli.py                        # ati pf2-transfer
tests/evaluation/test_pf2_transfer.py
```
