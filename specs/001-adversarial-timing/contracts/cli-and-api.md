# Contract: CLI and Python API

## CLI: `ati pf2-simulate`

New optional flags; every existing flag is unchanged.

| Flag | Values | Default | Errors |
|---|---|---|---|
| `--automation-model` | `timer`, `imitate` | `timer` | argparse choice error |
| `--imitation-fidelity` | float in [0, 1] | `0.0` | exit 2 with a reason on stderr when outside [0, 1], or when non-zero with `timer` |

Exit status 0 writes the plan JSON and prints `{"fixture": true, "output": <path>}`, as
today. On an error nothing is written.

## Python API

```python
simulate_matched_corpus(
    *,
    human_model: HumanPauseModel,
    sessions_per_cell: int,
    participants: int,
    windows: int = SIMULATED_WINDOWS,
    seed: int = 0,
    automation_model: AutomationPauseModel = AutomationPauseModel.TIMER,
    imitation_fidelity: float = 0.0,
) -> SimulatedCorpus

plan_collection(
    *,
    human_model: HumanPauseModel,
    sessions_per_cell_options: Sequence[int],
    participants: int,
    repeats: int = 20,
    resamples: int = 300,
    seed: int = 0,
    automation_model: AutomationPauseModel = AutomationPauseModel.TIMER,
    imitation_fidelity: float = 0.0,
) -> dict[str, Any]
```

Both raise `ValueError` for the refusals above. `AutomationPauseModel` is exported from
`agent_traffic_intelligence.evaluation.pf2`.

## Plan JSON

The plan gains `automation_model` and `imitation_fidelity` at the top level (see
[data-model.md](../data-model.md)). No field is removed or renamed.
