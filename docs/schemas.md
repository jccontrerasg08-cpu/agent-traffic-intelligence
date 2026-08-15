# Event and Detection Schemas

Machine-readable drafts live under `schemas/`.

## RequestEvent

A normalized request deliberately excludes raw IPs, query values, cookies, Authorization values, and bodies. `client_id` is an externally supplied pseudonym or a keyed BLAKE2b pseudonym produced at ingest.

## Detection

A detection contains four independent scores, an optional claimed identity, evidence contributions, and the feature snapshot used to produce the result. Detection output now carries `schema_version: 1`; consumers must reject unknown versions or route them through an explicit migration.

The published detection root, identity claim, and evidence objects are closed to undeclared fields. Feature names remain extensible, but their values must be JSON scalars (`number`, `boolean`, `string`, or `null`). Evidence deltas are limited to `automation`, `ai`, `identity`, and `risk` so the public contract matches the scoring model.

Scores are in `[0, 1]`. V0 scores are heuristic/logistic outputs and are not yet empirically calibrated probabilities.

## Verification

The optional `verification` payload is versioned independently with `schema_version: 1`. Its methods and conflict information are emitted only when V1 identity verification is enabled.

## Validation and versioning

`jsonschema` is a development-only dependency. The test suite validates the published RequestEvent, Detection, and Verification schemas, serializations produced by the Python models, and rejection of undeclared detection fields.

Breaking schema changes require a documented migration and a new schema version. Additive fields are not silently accepted at closed object boundaries; update the schema, contract tests, and migration documentation together.
