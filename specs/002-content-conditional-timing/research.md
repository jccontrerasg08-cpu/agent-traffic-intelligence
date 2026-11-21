# Research: Content-Conditional Timing

## R1. Why dwell ratio, not reading speed

- **Decision**: one feature, the mean dwell on long pages over the mean dwell on short
  pages, bucketed at 1.0, 2.0 and 3.5.
- **Rationale**: a ratio cancels a person's overall pace and the shared pacing regime,
  as the tempo-shape features do. Words per minute would need each page's word count in
  ATI and would be sensitive to pace. The bounds come from the scratch experiment's
  weights (1.8 for long pages, 1.0 or less for short ones), so a reader with no
  conditioning falls near 1.
- **Alternatives considered**: a per-page dwell vector, refused because it is
  high-resolution timing that the feature contract prohibits; correlation between dwell
  and word count, which is too noisy with four navigations per session.

## R2. Where page texts live

- **Decision**: in `catalogue.json`, beside each route's status and category.
- **Rationale**: laboratory ADR 0001. A text held separately by the origin and the
  executor could drift, and the participant would then read something the origin never
  served. ATI pins only the loads, not the texts.

## R3. Assets follow their page

- **Decision**: in scenario 1.1 both cohorts fetch each asset right after its page, and
  dwell attributes the asset to that page.
- **Rationale**: a browser does this without the person. Asking a participant to press
  Enter for a stylesheet records nothing human. The change applies to both cohorts, so
  it cannot separate them.

## R4. The two mimics

- **Decision**: the *distribution mimic* draws person-like pauses scaled by the session's
  reading loads in a random order, so it matches the marginal distribution and breaks
  placement. The *content-aware mimic* scales each pause by the load of the page it
  follows, as people do.
- **Rationale**: they bracket the escalation. The first is what spec 001's mimic becomes
  once page loads exist. The second is the obvious answer to the new feature, and it
  must defeat it, or the feature would be detecting something other than placement.

## R5. Keeping existing corpora identical

- **Decision**: the reading scenario is a new option on `simulate_matched_corpus`,
  defaulting to the keypress scenario. Every new random draw happens only in the new
  scenario, from its own stream.
- **Rationale**: the spec 001 characterization digests must still pass (SC-003).

## R6. How the real data is best obtained

- **Decision**: a laboratory runbook in eight stages:
  1. recruit 12 participants;
  2. obtain consent and assign opaque codes;
  3. give each participant one task and one window, with H1, H2 and H3 in a randomized
     order;
  4. run a two-person pilot outside the corpus;
  5. collect the automated and human cohorts, interleaved, in the same windows;
  6. export and reconcile;
  7. run the preflight and the baseline with groups;
  8. delete raw data on schedule.
- **Rationale**: the power analysis needs 12 people and 72 sessions. The
  participant-grouped splits need one task and one window per person. A pilot catches
  instrument faults without contaminating the corpus. Interleaving the cohorts keeps time
  of day from becoming a class proxy.
