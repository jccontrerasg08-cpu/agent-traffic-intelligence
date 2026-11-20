# Quickstart: Adversarial Timing Robustness

Prerequisites: the repository installed for development (`make check` passes).

## 1. The default is unchanged

```bash
ati pf2-simulate --human-model lognormal --sessions-per-cell 2 --participants 12 \
  --repeats 3 --output before.json
```

Expected: the same plan as before this feature, plus `"automation_model": "timer"` and
`"imitation_fidelity": 0.0`. The characterization test in
`tests/evaluation/test_pf2_simulation.py` checks the corpus digest.

## 2. A perfect mimic is a null

```bash
ati pf2-simulate --human-model lognormal --sessions-per-cell 2 --participants 12 \
  --automation-model imitate --imitation-fidelity 1 --output mimic.json
```

Expected: a detection rate of at most 5% (SC-002).

## 3. The fidelity sweep

```bash
for f in 0 0.25 0.5 0.75 1; do
  ati pf2-simulate --human-model lognormal --sessions-per-cell 2 --participants 12 \
    --automation-model imitate --imitation-fidelity "$f" --output "sweep-$f.json"
done
```

Expected: one detection rate per fidelity, not rising with fidelity. The rates are
recorded in `docs/architecture/pf2-model-improvement-evidence.md`, Evidence 4.

## 4. Refusals

```bash
ati pf2-simulate --human-model linger --sessions-per-cell 1 --participants 6 \
  --imitation-fidelity 0.5 --output x.json          # exit 2: fidelity needs imitate
ati pf2-simulate --human-model linger --sessions-per-cell 1 --participants 6 \
  --automation-model imitate --imitation-fidelity 1.5 --output x.json   # exit 2
```
