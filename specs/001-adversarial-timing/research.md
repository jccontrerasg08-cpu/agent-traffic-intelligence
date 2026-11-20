# Research: Adversarial Timing Robustness

## R1. What imitation means

- **Decision**: each automated pause is, with probability *fidelity*, drawn the way the
  selected human model draws a pause, and otherwise drawn from the regime's uniform
  timer.
- **Rationale**: one number moves the adversary from a plain timer (0) to a
  distributional mimic (1). The curve between those two ends answers User Story 2. A
  mixture is also the cheapest imitation a real bot could deploy: randomize some pauses,
  not all of them.
- **Alternatives considered**: (a) interpolating each pause between timer and human
  values, which changes the distribution's shape in ways no human model describes;
  (b) a bot that learns from observed pauses, which is a different adversary, out of scope
  per the spec's assumptions.

## R2. Whose traits an imitating session uses

- **Decision**: each imitating automated session samples its own persona, a pace and an
  irregularity, from the same population that simulated participants come from.
- **Rationale**: borrowing a real participant's traits would correlate automated and
  human sessions through a shared person. That is a leakage path the participant-grouped
  splits do not purge, because automated sessions are their own groups (spec edge case).
  A fresh persona per session is also what a careful adversary would do.
- **Alternatives considered**: one persona for all automation, which is easier to detect
  and so would flatter the ladder; reusing participant personas, rejected for leakage.

## R3. Keeping fidelity 0 byte-identical

- **Decision**: the main random generator keeps producing exactly the draws it makes
  today, in the same order. In particular, the timer pause for every automated step is
  always drawn. All imitation randomness (whether a pause is replaced, the persona, the
  person-like pause) comes from a second generator, seeded deterministically from the
  corpus seed.
- **Rationale**: this satisfies FR-004 by construction rather than by coincidence. It also
  holds participants, human pauses and timer pauses fixed across fidelities for one seed,
  so a sweep compares paired corpora and its variance comes from imitation alone.
- **Alternatives considered**: drawing imitation from the main generator, which shifts
  every later draw and breaks reproducibility of the existing evidence; skipping the timer
  draw when a pause is replaced, which also shifts the stream.

## R4. Imitating the `uniform` human model

- **Decision**: allowed, and a no-op in distribution. Imitating a timer-like person is
  still a timer.
- **Rationale**: the spec requires that the planner still runs and reports. A refusal here
  would make the sweep tooling special-case one model for no gain.

## R5. Inconsistent options

- **Decision**: refuse a fidelity outside [0, 1], and refuse a non-zero fidelity with the
  plain timer model.
- **Rationale**: the constitution's fail-closed rule (VI). A silently ignored fidelity would
  produce a plan that claims an adversary it never simulated.
