# ADR 0007: The PF-2 feature firewall

## Status

Accepted.

## Context

A session classifier trained on controlled campaigns is easy to fool by accident. The
campaign metadata that makes evaluation possible (opaque session pseudonym, task, collection
window, executor, pacing regime) also predicts the label perfectly if it ever reaches the
model. A model that learns the executor instead of the behaviour reports an excellent score
and is worthless.

## Decision

The ATI-PF-2 pipeline keeps model inputs and evaluation metadata in **two separate files
that never merge**:

- the *model table* holds the boolean target and the 67 permitted session features, from
  four declared families, and nothing else. Any other column fails the run;
- the *split manifest* holds the opaque session pseudonym, task and collection window. It is
  read only to build train/holdout partitions.

Every learned quantity (standardization statistics, coefficients, and the operating threshold
for a predeclared false-positive rate) is derived from the training partition of each split.
Holdouts are fixed: forward-chained temporal, leave-one-task-out, and grouped by session. A
split that places one session on both sides, or leaves a side with one class, fails closed
instead of producing a number.

## Consequences

- Leakage controls are structural, not advisory: the estimator cannot see a column that is
  not in its file. The report asserts this (`split_metadata_reached_estimator: false`).
- Metadata that never reaches ATI at all, such as the pacing regime and executor, can still
  confound the classes. The laboratory's corpus builder checks those
  ([ati-observation-lab ADR 0002](https://github.com/jccontrerasg08-cpu/ati-observation-lab/blob/main/docs/adr/0002-matched-executor-design.md)).
- Small corpora often fail closed. That is intended: an honest refusal is more useful than
  a metric computed on a degenerate split.

Implemented in `evaluation/pf2/protocol.py` and `evaluation/pf2/baseline.py`. Tests in
`tests/evaluation/test_pf2_baseline.py` cover every refusal, and a property-based test
generates arbitrary valid corpora and asserts that splits stay disjoint and nothing leaks.
