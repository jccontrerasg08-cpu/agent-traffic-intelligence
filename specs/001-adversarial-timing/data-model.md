# Data Model: Adversarial Timing Robustness

## AutomationPauseModel (enumeration)

| Value | Meaning |
|---|---|
| `timer` | Default. Every automated pause is drawn uniformly within the regime, as today. |
| `imitate` | Each automated pause is person-like with probability `imitation_fidelity`, and otherwise a timer pause. |

## Imitation fidelity

- A real number in [0, 1].
- Validation: outside [0, 1] is refused. A value other than 0 with `timer` is refused as
  inconsistent.
- `imitate` at 0 behaves exactly like `timer`.

## Persona (internal, per imitating automated session)

- `pace`: drawn as for a participant, `exp(N(0, 0.25))`.
- `irregularity`: drawn as for a participant, `U(0.25, 0.55)`.
- Never shared with a participant, and never persisted.

## Collection plan (planner result): added fields

| Field | Type | Meaning |
|---|---|---|
| `automation_model` | string | `timer` or `imitate` |
| `imitation_fidelity` | number | The fidelity used; `0.0` for `timer` |

Existing fields are unchanged: `fixture` (always `true`), `human_model`,
`participants`, `repeats`, `resamples`, `seed`, `sizes[]`.
