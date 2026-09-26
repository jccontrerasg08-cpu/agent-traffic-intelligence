# ATI-PF-2 Live Collection and Baseline Evidence

**Run date:** 2026-09-26  
**Edge:** Cloudflare Worker `ati-observation-proxy` at `observe.ati-observation-lab.com`  
**Origin:** Railway service `ati-observation-lab` (project `triumphant-miracle`, `production`)  
**Scope:** Authorized controlled traffic to the closed `/lab/*` catalogue, using only markers already allowlisted in the versioned Worker configuration.

This record separates what was measured from what was **not** established. It does not
claim generalization, a population false-positive rate, calibration, or an operating
threshold for public traffic.

## Campaign as executed

Six automated executor families ran a two-task route graph through the live edge. Each
session burst internally at roughly 0.3 s between requests and then idled, because the
origin rate-limits 30 observations per minute per opaque pseudonym and every family in
this run shares one edge-address pseudonym. A cadence of one session per 16 s held the
run at about 22 observed requests per minute.

| Metric | Value |
|---|---|
| Sessions sent | 24 |
| Observed requests | 148 |
| Throttled (`429`) responses | 0 |
| Non-`200` responses | 0 |
| Elapsed | 373 s |
| Sessions reconciled into the corpus | 23 |
| Corpus rows | 141 |

One session was **excluded**, not repaired: its `/lab/start` row fell outside the
retrieved log windows, so its locally recorded request identifiers did not each match one
exported row. The campaign protocol stops and excludes an incomplete session rather than
inferring the missing record.

### Reconciliation

The executor never sees the origin's opaque session pseudonym; it only sees the random
`X-ATI-Request-ID` returned per request. Local sessions were therefore joined to exported
rows through those opaque identifiers. All 147 exported rows matched a locally recorded
identifier, and every row of each accepted session carried one and the same
`session_id`.

### Corpus composition

Family is audit-only split metadata. It appears here strictly for composition reporting
and is unavailable to feature construction, filtering or score selection.

| Family | Sessions | Mean requests | Mean asset requests | Mean `HEAD` | Mean duplicate routes |
|---|---:|---:|---:|---:|---:|
| curl | 4 | 5.0 | 0 | 0 | 0 |
| wget | 4 | 6.0 | 0 | 1 | 1 |
| requests | 4 | 6.0 | 1 | 0 | 0 |
| httpx | 4 | 7.0 | 2 | 0 | 0 |
| node-fetch | 4 | 6.0 | 0 | 0 | 1 |
| playwright-chromium | 3 | 7.0 | 2 | 0 | 0 |

141 rows over 8 distinct closed routes; 137 `GET` and 4 `HEAD`; all `200`.
12 sessions on `task-detail`, 11 on `task-related`; 12 in the first collection block and
11 in the second.

## The preflight refused the corpus, as designed

```
$ ati pf2-preflight access.jsonl --labels-by-session … --min-sessions-per-task-class 8
error: corpus must contain both classes
```

Every family in this run is an automated executor, so every session is honestly labeled
`automated=true` and the corpus has one class. A Playwright-driven Chromium is **not** a
consented human control: the consent procedure requires an affirmative voluntary record
from a participant, and browsing style is never a label. Labeling browser-driven
automation as human would have manufactured the second class and silently poisoned every
downstream metric.

This is therefore a **positive result for the firewall**: the preflight refused to emit a
model table from real edge traffic that cannot support a target contrast. The baseline
ladder and the warehouse export were exercised against a clearly-labeled synthetic
two-class corpus and against the unit suites instead.

**The remaining blocker is a person, not code.** A two-class ATI-PF-2 corpus needs the
consented human cohort under
[`human-control-consent.md`](https://github.com/jccontrerasg08-cpu/ati-observation-lab/blob/main/docs/human-control-consent.md)
using the `owned-domain-2026-08-25-pf2-human-consented` marker. No amount of additional
automated collection substitutes for it.

## Findings that change the collection protocol

1. **The edge bans one declared executor family before the Worker runs.** Cloudflare
   answers `403` with error `1010` ("banned your access based on your browser's
   signature") for the Python standard-library client's default User-Agent, while
   `curl`, `Wget`, `python-requests`, `python-httpx`, `undici` and a headless-Chrome
   User-Agent all reach the Worker. A family whose client trips that managed rule would
   be **absent** from the corpus rather than visibly failing, biasing composition by
   executor. Verify every declared family reaches the Worker before opening a campaign.

2. **The address-derived pseudonym is not stable within a session.** `client_id` changed
   between requests of a single session in this run, because the collecting host's egress
   address rotates while the edge-derived `session_id` stays fixed. Group splits must key
   on `session_id`; `client_id` is unusable as a grouping key from a multi-address origin
   and must never be treated as a device or person.

3. **Response header casing differs by hop.** The Worker re-emits
   `X-ATI-Lab-Session` in its own casing while the origin's `x-ati-request-id` arrives
   lowercased. An executor doing a case-sensitive lookup silently loses the
   request-correlation identifier and cannot reconcile its labels. Executors must read
   response headers case-insensitively.

4. **The per-pseudonym rate limit caps intra-session pacing from one host.** Sustained
   sub-second pacing across many sessions is impossible from a single edge address under
   a 30-per-minute limit. Bursting within a session and idling between sessions preserves
   realistic intra-session delay bins; a flat inter-request delay would have collapsed
   the coarse tempo features instead.

## The blocker was not only a person

Re-reading the consent procedure against the implementation found a second, harder blocker
that a human participant alone would not have solved. The procedure's route plan predated
ATI-PF-2: it ended at `/lab/missing` and never reached `/lab/complete`.

`/lab/missing` is not in `_APPROVED_ROUTES`, so `prepare_pf2_dataset` rejects any session
containing it with *record path must be an eligible ATI-PF-2 route* — confirmed by running
the documented sequence through the preflight, not inferred from reading. Even with that
route removed, every automated family terminates at `/lab/complete` while that plan never
did, so `completion` and the route-category counts would have separated the cohorts
perfectly: a route category present in only one target class, which the feature contract
forbids outright.

So a human cohort collected exactly as documented would have produced either a rejected
corpus or a model that learned the executor rather than the behavior. The lab repository's
procedure now follows the shared task graph, the approved local executor it assumed exists
as `scripts/lab_session.py`, and `scripts/build_pf2_corpus.py` reconciles session records
against an export. The chain from reconciliation through preflight, baseline and warehouse
export was then verified end to end on a clearly-labeled two-class fixture.

That fixture is separable by construction, so its perfect PR-AUC and its zero ablation
deltas say nothing about detection quality — every permitted family alone suffices there.
Its useful signals are the ones that are not perfect: the train-selected threshold
transferred on the temporal holdout but collapsed recall to zero on both task holdouts,
which is the honest reading of a threshold that does not generalize across tasks.

## Not established by this run

- No generalization to unmarked public traffic.
- No population false-positive rate, no calibration, no operating threshold.
- No human-control cohort, so no measured false-positive behavior on human sessions.
- No claim that a campaign marker proves anything about an external client's identity.
