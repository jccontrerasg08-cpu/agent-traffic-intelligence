# Feature Specification: Content-Conditional Timing

**Feature Branch**: `claude/continuar-probar-exhaustivamente-tpmsjf`

**Created**: 2026-11-20

**Status**: Draft

**Input**: User description: "Improve detection beyond what a distributional mimic can
defeat: measure *where* a person pauses, not only how long, and make the laboratory able
to collect it. Also say how to obtain the real data in the best possible way."

## Context

Spec 001 showed that timing shape is defeated by automation that imitates the
distribution of human pauses. A scratch experiment then showed that the time a person
spends on a page relative to how much there is to read is a different signal. It
detected such a mimic in 20 of 20 synthetic corpora, while a null control was detected
in 1 of 20, and a mimic that also conditions its pauses on the page was detected in 1 of
20.

Inspecting the laboratory showed that it cannot produce this signal today:

- every page is a heading and a link, so no page takes longer to read than another;
- a participant never sees the pages. They press Enter at a prompt that names the next
  route, including for the stylesheet and the image, which a browser fetches by itself.

The behaviour recorded today is therefore a person pressing Enter to a pace guide, not a
person browsing. This feature fixes the instrument first, then adds the signal.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect a mimic that ignores content (Priority: P1)

A researcher simulates a reading scenario in which people dwell longer on long pages
than on short ones. They then compare three adversaries: the plain timer, a mimic that
copies the distribution of human pauses but not where they fall, and a mimic that also
conditions on content. The ladder, with a new dwell-ratio feature, should detect the
first two and not the third. Detecting the third would mean the result leaks something
other than content conditioning.

**Why this priority**: it is the evidence that the new signal raises the cost of evasion
beyond what spec 001's adversary pays. Without it, changing the laboratory has no
justification.

**Independent Test**: run the planner in the reading scenario for each adversary at the
recommended design. Detection is high against the content-blind mimic, and at null level
against the content-aware mimic and against a null in which nobody conditions.

**Acceptance Scenarios**:

1. **Given** the reading scenario and a mimic that copies the distribution but not the
   placement of pauses, **When** the planner runs, **Then** detection with the dwell-ratio
   feature is far above the null rate.
2. **Given** the same scenario and a mimic that also conditions on content, **When** the
   planner runs, **Then** detection is at most the null rate.
3. **Given** the existing keypress scenario, **When** the planner runs with any existing
   option, **Then** every corpus is identical to before this feature.

---

### User Story 2 - Collect reading behaviour in the laboratory (Priority: P2)

A consenting participant reads each page in the executor, which shows them the page's
text, and moves on when they are done. The stylesheet and image follow their page
automatically, as in a browser, for both cohorts. The page texts differ in length, so
reading takes measurably different time.

**Why this priority**: the real test of the signal needs this instrument, and the
participant's experience becomes closer to real browsing.

**Independent Test**: a session in the new scenario shows the participant every page's
text, prompts only for navigations, fetches each asset without a pause, records the new
scenario version, and is accepted by the corpus builder and ATI's preflight.

**Acceptance Scenarios**:

1. **Given** the new scenario, **When** a consented session runs, **Then** the participant
   sees each page's text before being asked to continue, and is never asked about an
   asset.
2. **Given** both cohorts in the new scenario, **When** a corpus is built, **Then** asset
   requests follow their page within a second for both, and the scenario version is the
   same in both classes.
3. **Given** the page texts, **When** the origin serves a page, **Then** it serves exactly
   the text the catalogue declares, and that text is also what the executor shows.

---

### User Story 3 - Know how to collect the real data (Priority: P3)

The operator follows a written runbook covering recruitment, consent, scheduling,
session assignment, a pilot, collection, reconciliation, evaluation and deletion. It
lets them obtain the corpus that the recommended design calls for without breaking the
protocol's guarantees.

**Why this priority**: every result so far is synthetic. The data is now limited by
operations, not code, so the operations need to be as rigorous as the code.

**Independent Test**: someone who has not worked on the project can plan a full
collection from the runbook alone, including the assignment of participants to tasks and
windows and a pilot that is not mixed into the corpus.

**Acceptance Scenarios**:

1. **Given** the runbook, **When** an operator plans collection, **Then** each of the 12
   participants has an opaque code, one task, one collection window and three sessions
   (H1, H2, H3) in a randomized order.

### Edge Cases

- A session whose pages have no short page or no long page with a measurable dwell falls
  into the lowest dwell-ratio bucket, like the other tempo features.
- A keypress-scenario corpus (scenario 1.0) keeps producing the same feature values for
  every existing feature. The new feature reads its pages from the same session, so it
  is defined for 1.0 sessions too. There, page loads do not differ in reality, so it
  carries no signal.
- A participant who stops partway through produces an excluded session, as today.
- Page texts must contain no personal data, links outside the catalogue, scripts or
  tracking.
- A corpus that mixes scenarios 1.0 and 1.1 in one class only is refused by the corpus
  builder, which already checks scenario version.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The catalogue MUST declare, for every page route, a reading load (short or
  long) and the text the page shows. Assets and the integrity route have no reading
  load.
- **FR-002**: The origin MUST serve each page's declared text, and the executor MUST show
  the participant the same text.
- **FR-003**: In the new scenario, the executor MUST fetch each asset right after its page
  without waiting, for both cohorts, and MUST prompt a consenting participant only before
  a navigation.
- **FR-004**: The new scenario MUST be recorded as its own scenario version. The keypress
  scenario MUST remain available and unchanged.
- **FR-005**: ATI MUST add a dwell-ratio feature: the time spent on long pages relative to
  short pages, bucketed into four levels, excluding asset requests, with no absolute time
  retained.
- **FR-006**: ATI MUST pin the catalogue version and the reading load of every page, and
  both repositories MUST test that they agree.
- **FR-007**: The collection planner MUST simulate the reading scenario, and adversaries
  that imitate either the distribution of human pauses alone or also their placement by
  content. Every existing option MUST reproduce its earlier corpora exactly.
- **FR-008**: The feature contract MUST record the new family's privacy, class-proxy and
  ablation review.
- **FR-009**: The laboratory MUST provide a collection runbook covering recruitment,
  consent, assignment, a pilot, collection, reconciliation, evaluation and deletion.
- **FR-010**: The evidence record MUST report detection per adversary in the reading
  scenario, with reproduce commands, and state that the data is synthetic.

### Key Entities

- **Reading load**: whether a page is short or long to read. Declared in the catalogue
  and pinned in ATI.
- **Dwell**: the time from a page request to the next navigation request, with assets
  attributed to their page.
- **Scenario version**: `ati-pf2-1.0`, the keypress scenario, or `ati-pf2-1.1`, the
  reading scenario.
- **Adversary**: plain timer, distribution mimic (spec 001's imitation), or
  content-aware mimic.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: At the recommended design (12 participants, 72 sessions, 20 corpora), the
  dwell-ratio feature detects the distribution mimic at full fidelity in at least 80% of
  corpora, against 0% without it.
- **SC-002**: Against the content-aware mimic and against a null in which nobody
  conditions, detection is at most 10% (two corpora in 20).
- **SC-003**: Every existing simulation corpus keeps its characterization digest, and
  every existing feature value of a keypress-scenario session is unchanged.
- **SC-004**: A participant session in the reading scenario has zero prompts for assets,
  and every asset request follows its page within one second.
- **SC-005**: The runbook lets an operator assign 12 participants to cells and draft a
  schedule without asking anyone else.

## Assumptions

- People spend longer on longer texts. The scratch experiment assumed a dwell factor of
  1.8 for long pages and 1.0 or less for short ones. The real cohort will show whether
  this holds and how strongly, and no claim is made before that.
- The page texts are neutral filler about the laboratory itself. Their length, not their
  content, is the manipulation.
- The executor stays a terminal program, so it shows text, not a rendered page. That
  keeps the executor, the User-Agent and the header handling identical across cohorts,
  which is the matched-executor design. A browser-based instrument would change those,
  and is out of scope.
- The planner's reading scenario uses the same pacing regimes. A participant is shown
  the regime as guidance for how long to stay on a page.
