# Event and Detection Schemas

Machine-readable drafts live under `schemas/`.

## RequestEvent

A normalized request deliberately excludes raw IPs, query values, cookies, Authorization values, and bodies. `client_id` is an externally supplied pseudonym or a keyed BLAKE2b pseudonym produced at ingest.

## Detection

A detection contains four independent scores, an optional claimed identity, evidence contributions, and the feature snapshot used to produce the result.

Scores are in `[0, 1]`. V0 scores are heuristic/logistic outputs and are not yet empirically calibrated probabilities.

## Versioning

Breaking schema changes require a documented migration. The V0 Python objects are the reference implementation until formal schema version fields are added to every emitted object.
