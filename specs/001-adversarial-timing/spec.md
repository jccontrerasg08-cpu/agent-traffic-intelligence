# Feature Specification: Adversarial Timing Robustness

**Feature Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf`

**Created**: 2026-11-20

**Status**: Draft

**Input**: User description: "Measure whether ATI-PF-2's timing-shape detection survives
automation that imitates how people pause, before any claim about it is made on real
data. The model improvement evidence names this as the next adversary: a timer that
draws its pauses from a person-like distribution."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Test detection against automation that imitates people (Priority: P1)

A researcher planning the consented collection already knows, from synthetic fixtures,
that the ladder can detect people when automation uses a plain timer. Before relying on
that, they want to know what happens when automation is built to pause like a person.
They run the collection planner with an imitating automation and read how often the
ladder still claims a difference.

**Why this priority**: an evaluation that has only met a naive adversary overstates what
it can do. Without this, any later real-data result could be dismissed by the obvious
objection that a bot can randomize its timing.

**Independent Test**: run the planner with automation that imitates the human model
perfectly. The ladder must not claim a difference more often than it does against the
null control. That is a complete, reportable result on its own.

**Acceptance Scenarios**:

1. **Given** the recommended design (12 participants, 72 sessions), **When** automation
   draws every pause from the same person-like distribution as the human model, **Then**
   the planner reports a detection rate no higher than the null control's.
2. **Given** the same design, **When** automation is the existing plain timer, **Then**
   the planner reports the same results it reports today for the same seed.

---

### User Story 2 - Map how detection degrades as imitation improves (Priority: P2)

The researcher wants more than "works against a timer, fails against a perfect mimic".
They want to know how much imitation it takes to defeat detection. They sweep imitation
fidelity from none to complete and read a detection rate at each step.

**Why this priority**: the shape of the curve says whether timing shape is a brittle
signal, lost to slight imitation, or one that a bot must work hard to evade. That decides
how much weight it deserves next to the other evidence.

**Independent Test**: run the planner at several fidelity levels with everything else
fixed, and check that the reported detection rate does not rise as fidelity rises.

**Acceptance Scenarios**:

1. **Given** fidelities 0, 0.25, 0.5, 0.75 and 1, **When** the planner runs each with the
   same seed and design, **Then** it reports one detection rate per fidelity, and the
   result records the fidelity it used.
2. **Given** a fidelity outside 0 to 1, **When** the planner is asked to run, **Then** it
   refuses with a reason and produces nothing.

---

### User Story 3 - Report the robustness frontier honestly (Priority: P3)

A reviewer reading the project's evidence sees, next to the claim that timing shape
detects people, the adversary it was tested against and the fidelity at which detection
fails.

**Why this priority**: the project's constitution requires every claim to state what was
not established. This feature makes that statement concrete.

**Independent Test**: the model improvement evidence record contains the fidelity sweep,
the commands that reproduce it, and a limitation stating that the result concerns
synthetic imitation, not any real bot.

**Acceptance Scenarios**:

1. **Given** the sweep results, **When** the evidence record is updated, **Then** it
   reports the detection rate per fidelity and the reproduce commands, and marks the
   data as synthetic.

---

### Edge Cases

- Fidelity exactly 0 must reproduce today's plain-timer corpora exactly, so existing
  evidence stays reproducible.
- Fidelity exactly 1 makes the two cohorts' pauses identically distributed in aggregate,
  so the run is a null and must behave like one.
- An imitating automation has no participant behind it. It must not borrow a simulated
  participant's personal pace or irregularity, which would make automated and human
  sessions correlated through a shared person.
- With the `uniform` human model, imitation changes nothing: the human model already is
  the timer. The planner still runs and reports it.
- Imitated pauses must stay positive and finite, like every other simulated pause.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The collection planner MUST let the user choose how automation pauses: the
  existing plain timer, or imitation of the selected human model.
- **FR-002**: Imitation MUST take a fidelity between 0 and 1, the share of automated
  pauses drawn person-like rather than from the timer.
- **FR-003**: An imitating automated session MUST draw its own person-like traits, such
  as pace and irregularity, from the same population that simulated participants come
  from, independently of every participant.
- **FR-004**: With the plain timer, or fidelity 0, the planner MUST produce exactly the
  corpora and results it produces today for the same inputs and seed.
- **FR-005**: The planner MUST refuse a fidelity outside 0 to 1, and imitation options
  that are inconsistent, with a stated reason, and MUST produce no output.
- **FR-006**: Every planner result MUST record the automation model and fidelity it used,
  and MUST remain marked as a synthetic fixture.
- **FR-007**: The command-line planner MUST expose the automation model and fidelity.
- **FR-008**: The model improvement evidence record MUST report a fidelity sweep at the
  recommended design, with reproduce commands, and MUST state that it concerns synthetic
  imitation only.

### Key Entities

- **Automation pause model**: how simulated automation chooses each pause. Either the
  plain timer that draws uniformly within the regime, or imitation of a human pause model
  at a given fidelity.
- **Fidelity**: the share of an imitating automation's pauses drawn person-like, from 0
  (always the timer) to 1 (always person-like).
- **Collection plan**: the planner's result. For each corpus size it gives the detection
  rate, mean PR-AUC and blocked runs, now labelled with the automation model and fidelity.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For the plain timer and for fidelity 0, every existing planner output is
  identical to the output before this feature, for the same inputs and seed.
- **SC-002**: At fidelity 1 with the `lognormal` and `linger` human models, under the
  recommended design and 20 corpora, the detection rate is at most 5%, the null control's
  ceiling observed so far.
- **SC-003**: A five-step fidelity sweep at the recommended design, 20 corpora per step,
  runs end to end on one machine with the default settings, and its results are recorded
  in the evidence record.
- **SC-004**: A reader of the evidence record can say from it alone at what fidelity
  timing-shape detection falls below 50%, or that it never does within the sweep.

## Assumptions

- The recommended design (12 participants, 3 sessions each, 72 sessions) and the human
  models `linger` and `lognormal` from the model improvement evidence are the reference
  for this feature.
- Imitation is simulated only. Running imitating automation through the live laboratory
  is a separate, later feature, and it would need the executor to gain an imitation
  pacing mode.
- Mixing timer and person-like pauses by fidelity is a deliberately simple model of
  imitation. A real adversary could imitate in other ways, for example by learning from
  observed pauses, and that is out of scope.
- No new model feature, feature family or model rung is added. This feature measures the
  existing ladder.
