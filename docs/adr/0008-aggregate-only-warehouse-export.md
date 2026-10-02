# ADR 0008: The warehouse receives aggregates only

## Status

Accepted.

## Context

Comparing baseline runs over time needs a query engine; BigQuery is the target. A warehouse
is also where data outlives its purpose: it is shared, copied and retained more widely
than the local corpus it came from. Two things must not end up there. The first is anything
that identifies a session or ties a row back to traffic. The second is the split manifest,
whose task and window labels would let a later analysis recreate the leakage
[ADR 0007](0007-pf2-feature-firewall.md) prevents.

## Decision

`ati pf2-export-bigquery` writes five append-only tables keyed by `run_id`: run manifest,
per-split metrics, per-family ablations, per-class feature summaries and cohort counts.

- **Aggregates only.** Feature distributions are summarized per class (count, distinct
  values, minimum, maximum, mean). Per-session rows are never exported, because a rare
  feature vector can single out a session.
- **Deny-list as well as schema.** Every row must use only its table's declared columns,
  and no row may carry a session pseudonym, request or client identifier, row index, task,
  collection window or campaign marker, even under a declared name.
- **ATI never uploads.** The command writes newline-delimited JSON, schemas and DDL
  locally. Loading is a separate, deliberate operator step (`bq load`).

## Consequences

- The warehouse can be shared for analysis without granting access to traffic.
- Some questions cannot be answered from the warehouse, such as per-session error analysis.
  Those stay local, against the local corpus, by design.
- Append-only tables keyed by `run_id` make every run an immutable record; the run manifest
  is the index. A corrected run is a new `run_id`, never an update in place.

Implemented in `evaluation/pf2/export.py`; tests in `tests/evaluation/test_pf2_export.py`.
