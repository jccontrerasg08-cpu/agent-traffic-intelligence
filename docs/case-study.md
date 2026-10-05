# Case study: telling people from automation without fooling yourself

*Agent Traffic Intelligence (ATI) and its observation laboratory: a self-hosted,
observe-only system for explaining automated and AI-originated web traffic, and a
privacy-first protocol for measuring whether behaviour alone can separate people from
paced automation.*

## The problem

"Bot or human" is the wrong question for modern traffic. A verified search crawler, an AI
training crawler, a user-triggered AI fetcher, browser automation and an abusive scraper
are all automated, yet they differ in identity, purpose and risk. Most tooling collapses
them into one score, trusts the `User-Agent` header, and is tuned on traffic whose labels
are themselves guesses.

ATI keeps four questions separate ([ADR 0002](adr/0002-separate-score-dimensions.md)):

| Dimension | Question |
|---|---|
| `automation_score` | Is this request or session automated? |
| `ai_score` | Is the automation AI-related? |
| `identity_confidence` | Is the claimed actor who it says it is? Answered with official IP ranges, forward-confirmed reverse DNS, or RFC 9421 / Web Bot Auth signatures, never a header. |
| `risk_score` | Is the behaviour operationally risky? |

## Constraints I chose

- **Observe before enforce.** ATI classifies and explains but never blocks, challenges or
  mutates traffic ([ADR 0001](adr/0001-observe-before-enforce.md)). False positives against
  real users are expensive, so the system must earn trust before it acts.
- **Privacy first.** No raw IP addresses, cookies or request bodies are stored. Addresses
  become keyed pseudonyms; raw verification material lives only in a non-serializable
  context object ([ADR 0003](adr/0003-ephemeral-verification-context.md)).
- **Zero third-party runtime dependencies** in the deterministic core: the Python standard
  library only, with cryptography as an optional extra
  ([ADR 0004](adr/0004-optional-crypto-dependency.md)). Fewer dependencies mean less
  supply-chain risk and a smaller audit surface.
- **Labels from ground truth, not inference.** A label comes from a recorded, authorized
  campaign, never from a route, a pacing pattern or a header.

## Architecture

```text
 Observation laboratory (ati-observation-lab)
 ─────────────────────────────────────────────
 executor (records labels)
     │  marker-tagged requests
     ▼
 Cloudflare Worker ── closed route catalogue · campaign marker gate
     │               HMAC-signed sessions · coarse UA provenance
     ▼
 FastAPI origin on Railway ── refuses unvouched traffic · writes pseudonymized JSONL
     │
     ▼
 corpus builder ── joins local labels to exported rows by opaque request id
     │
 ════╪════════════════════════════════════════════════════════════════════
     ▼            ATI (this repository)
 ingestion ─► session features ─► evidence rules ─► four independent scores
 identity: official ranges · forward-confirmed rDNS · RFC 9421 / Web Bot Auth
 evaluation: PF-2 preflight ─► baseline ladder ─► aggregate export ─► BigQuery
```

The laboratory is a deliberately small website whose only purpose is to be visited under
controlled conditions. The Worker at the edge admits only a closed catalogue of nine
`/lab/*` routes (pages, assets and one controlled 404), requires an allowlisted campaign
marker, issues a signed session bound to that one campaign, and forwards a coarse
User-Agent provenance bucket. The origin refuses any request the Worker did not vouch for.
One versioned route catalogue is the contract, and tests hold the edge, the origin, the
executor and ATI to it, so they cannot drift apart.

## The hard part: not fooling yourself

Building a classifier is easy. Building an evaluation that cannot flatter it is the actual
work. Four things went wrong or nearly did, and each one became a structural guard.

**1. Metadata that predicts the label.** Session pseudonyms, tasks and collection windows
predict the label perfectly if they reach the model. They now live in a separate split
manifest that is only ever used to build partitions, and the model table is rejected if it
carries any column outside 67 permitted features
([ADR 0007](adr/0007-pf2-feature-firewall.md)).

**2. A protocol that could not produce a valid corpus.** Re-reading the human-consent
procedure against the code showed its route plan predated the protocol: it ended on a route
the preflight rejects and never reached the completion page every automated session reached.
The human cohort would have been unusable, either rejected or perfectly separable by the
completion flag alone. The fix was to make the route catalogue a single versioned contract
that every component is tested against.

**3. A confound hiding in the executor.** The first executor derived the label from the
pacing regime, so pacing alone would have separated the classes. Cohort and pacing are now
independent inputs, both cohorts run through the same executor (the *matched-executor
design*), and the corpus builder refuses any corpus where an executor, pacing regime,
scenario or catalogue version occurs in one class only. Those fields never reach ATI, so
only the laboratory can check them.

**4. A perfect score that meant nothing.** The same pipeline on two synthetic fixtures
shows why the design matters more than the model:

| Fixture | PR-AUC on final temporal holdout | Beats baseline? | What the ablation shows |
|---|---|---|---|
| Unmatched: humans fetch assets and revisit, automation does not | 1.000 | yes | every feature family alone suffices, because all of them are class proxies |
| Matched: one executor, shared pacing, only timing differs | 0.647 (interval 0.378–0.869) | **no** | only the tempo family carries signal |

The unmatched result looks perfect and is worthless. On the matched fixture the ladder
correctly declines to claim a win, because the session-cluster bootstrap lower bound does
not clear the constant baseline.

## Running it against real infrastructure

- **Perimeter conformance: 22 of 22.** A maintained command, `ati-lab-perimeter`, probes
  production after every deploy: marker gating, refusal of query strings, cookies,
  credentials and non-GET methods, session forgery, tampering and cross-campaign replay,
  HEAD/GET parity, cache and cookie headers, every catalogue route, origin isolation, and
  reachability per executor family.
- **A live campaign.** 24 sessions across six automated executor families: 148 requests,
  zero throttled, 23 sessions reconciled. One was excluded rather than repaired because a
  record fell outside the exported window.
- **Findings that changed the protocol.** Cloudflare silently bans the Python standard
  library's User-Agent before the Worker runs, so one family would have been missing from
  the corpus without any error. The address-derived pseudonym rotated within sessions, so
  grouping must key on the session. Response-header casing differs by hop. And the rate
  limit caps pacing from one host. Each is documented with the evidence
  ([live collection record](architecture/pf2-live-collection-evidence.md)).
- **The preflight refused the live corpus**, as designed: every session was automated, so
  there is no second class. Labelling browser automation as "human" would have manufactured
  one.
- **Standards drift, caught by the project's own monitor.** `ati standards health`
  reported that the IETF had adopted the Web Bot Auth protocol as a working-group draft.
  Reviewing the change and running the draft's official test vectors through the real
  verifier found three defects. A signature could be attributed to another signer's
  `Signature-Agent` member. Recorded logs older than a day failed to verify because the
  signature library judged time by the wall clock. Key discovery followed redirects that
  the protocol forbids. Each fix has a regression test
  ([review record](standards-status.md#review-of-the-working-group-adoption-2026-10-02)).
- **A demo that found a bug.** Writing the README demo against OpenAI's live range lists
  showed that OpenAI verification had never passed. The lists are served with `max-age=0`,
  and ATI read HTTP cache freshness as data validity, so every snapshot was stale on
  arrival. Google's lists had the opposite problem and never expired. Range validity is
  now ATI's own policy ([ADR 0009](adr/0009-range-snapshot-validity.md)).
- **Warehouse.** Run results load into BigQuery as aggregate-only, append-only tables keyed
  by run ([ADR 0008](adr/0008-aggregate-only-warehouse-export.md)), verified end to end in a
  disposable self-test dataset.

## What is not established

- No generalization to unmarked public traffic, no population false-positive rate, no
  calibration and no operating threshold.
- No consented human cohort yet, so no measured behaviour on real people. That is the next
  step, and it is a person's decision, not a code change.

## Engineering practice

- Python 3.11+, `mypy --strict`, `ruff`. 484 tests in ATI with an 85% coverage gate; 110
  Python and 23 Worker tests in the laboratory. Property-based tests (Hypothesis) for the
  parser, the IP-range logic and the evaluation splits.
- CI installs hash-pinned dependencies and runs per-area test profiles, CodeQL, OpenSSF Scorecard, dependency review and a
  scheduled check of the pinned Internet-Draft revisions.
- Refactors are proven, not assumed: outputs are captured before a change and compared
  byte for byte after it. One such check caught a reordering the unit tests did not.
- How the four books this project follows show up in the code is mapped file by file in
  [Engineering principles in practice](engineering-principles.md).
