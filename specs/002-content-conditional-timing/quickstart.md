# Quickstart: Content-Conditional Timing

## 1. Existing corpora are unchanged

`pytest tests/evaluation/test_pf2_simulation.py -k characterization` passes with the
spec 001 digests.

## 2. The three adversaries in the reading scenario

```bash
for model in timer imitate imitate-content; do
  fidelity=1; [ "$model" = timer ] && fidelity=0
  ati pf2-simulate --scenario reading --human-model lognormal --sessions-per-cell 2 \
    --participants 12 --repeats 20 --automation-model "$model" \
    --imitation-fidelity "$fidelity" --output "reading-$model.json"
done
```

Expected: `imitate` detected in at least 80% of corpora (SC-001), and `imitate-content`
in at most 10% (SC-002).

## 3. A laboratory session in the reading scenario

```bash
ati-lab-session --scenario-version ati-pf2-1.1 --cohort human-consented --participant p01 \
  --marker owned-domain-2026-09-26-pf2-matched-human-consented --task task-detail \
  --pacing-variant H1 --collection-window 2026-12-01-block-1 --output ./local/s.json
```

Expected: each page's text is shown before the prompt, and there is no prompt for an
asset.
