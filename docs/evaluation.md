# Evaluation and Dataset Plan

## Labels

Maintain both `label` and `label_confidence`/`label_source`. When running the optional manifest-gated evaluation path, each JSONL label must use `automated`, `label_source`, numeric `label_confidence` in `[0, 1]`, and the manifest’s exact `corpus_id`.

Strong labels can come from controlled traffic generation or verifiable provider identity. User-Agent-only labels are weak because they are spoofable.

## Controlled generators

For an end-to-end privacy-first procedure using an allowlisted campaign marker and generated ground-truth labels, see [controlled-observation.md](controlled-observation.md).

Generate authorized lab traffic from:

- browsers used manually;
- curl/wget;
- Python `requests`, `httpx`, and `aiohttp`;
- Scrapy;
- Playwright, Selenium, and Puppeteer;
- known provider crawlers observed on owned infrastructure when identity can be validated.

## Leakage controls

Do not randomly split requests from the same session/client across train and test. Minimum evaluation suites should include:

1. grouped session/client split;
2. temporal holdout;
3. unseen automation-family holdout;
4. provider/UA ablation to test whether the model learned behavior instead of memorizing names.

## Metrics

Primary metrics:

- bot precision and recall;
- PR-AUC;
- false-positive rate on human traffic;
- false-negative rate;
- calibration error / reliability plots;
- latency and memory at the chosen operating threshold.

Accuracy alone is not a useful headline metric on imbalanced traffic.

## Local evaluation harness

ATI now provides a local, JSONL-based harness for evaluating existing `automation_score` output against an **authorized** label corpus. It performs only in-memory metric calculation over privacy-safe request identifiers. It does not train a model, retain traffic, upload data, or claim that heuristic scores are calibrated probabilities.

The detection input must contain a non-empty `request_id` and numeric `automation_score` in `[0, 1]`. The label input is JSONL with a privacy-safe `request_id` and a boolean `automated` field on each line.

```json
{"request_id":"request-001","automated":true}
{"request_id":"request-002","automated":false}
```

Run the evaluator with:

```bash
ati evaluate detections.jsonl --labels labels.jsonl --threshold 0.5
```

The output contains the confusion matrix, precision, recall, F1, accuracy, Brier score, false-positive rate, false-negative rate, PR-AUC, expected calibration error, selected threshold, and two coverage indicators. `unlabeled_request_count` and `unmatched_label_count` must be investigated rather than silently classified as negative traffic. Duplicate label IDs, malformed JSONL, invalid booleans, duplicate detections, and scores outside `[0, 1]` are rejected. Rate metrics are `null` when their corresponding class is absent; PR-AUC is `null` when the evaluated corpus contains no positive examples.

> Brier score and expected calibration error are score-quality diagnostics, not proof of calibration. Expected calibration error uses ten fixed-width score bins and should be interpreted with the corpus size and score distribution. Probability calibration and learned detection still require a time-aware, authorized corpus using the leakage controls above.

## Stratified holdout evaluation

Use `ati evaluate-stratified` only with an authorized manifest and a separate local metadata JSONL. It reports the same metrics overall and by temporal day, declared family and `provider=<declared-provider>|ua=<coarse-bucket>`. It also reports only the number of opaque session groups and missing-session rows. The output intentionally omits raw request IDs, session pseudonyms and full User-Agent strings.

```bash
ati evaluate-stratified detections.jsonl \
  --labels labels.jsonl \
  --metadata stratified-metadata.jsonl \
  --manifest corpus-manifest.json \
  --output stratified-evaluation.json \
  --threshold 0.5
```

Each metadata line has this exact local-only schema:

```json
{"request_id":"privacy-safe-request-id","session_id":"hmac-sha256:<64-lowercase-hex>","family":"playwright","provider":"none","ua_bucket":"headless-chrome","time_iso8601":"2026-08-21T09:00:00+00:00"}
```

The metadata adapter rejects extra fields, duplicate request IDs, missing declared fields and invalid opaque session values. Treat `missing_metadata_count` or `sessionless_request_count` as a leakage-control failure, not as evidence about detection accuracy. A split with only one session or one family is a conformance slice; it cannot establish temporal, family or provider/UA generalization.

## ATI-PF-2 session preflight

`ati pf2-preflight` prepares a **local controlled-lab** table for a future baseline only after it enforces the ATI-PF-2 feature firewall. It accepts an authorized access-log JSONL plus two local JSON objects: one maps opaque session pseudonyms to explicit boolean targets and the other maps the same opaque sessions to audit-only task labels. It writes three paths atomically:

| Artifact | Contents | Permitted use |
|---|---|---|
| Model JSONL | `automated` target and fixed route-category, transition, method/status, completion and coarse delay/duration-bin features | Candidate estimator input after a separately frozen split. |
| Split JSONL | Row index, opaque session pseudonym and audit-only task label | Group and task holdout construction only. Never pass it to an estimator. |
| Preflight JSON | Aggregate counts and one readiness status | Collection-quality gate only. |

```bash
ati pf2-preflight access.jsonl \
  --labels-by-session labels-by-session.json \
  --tasks-by-session tasks-by-session.json \
  --collection-windows-by-session collection-windows.json \
  --model-output model.jsonl \
  --split-output splits.jsonl \
  --preflight-output preflight.json
```

The command rejects unapproved or integrity-only routes, non-GET/HEAD records, invalid statuses, missing targets, absent labeled sessions and task×class cells below the configured floor. Exact timestamps are used in memory only to form four fixed delay bins and one duration bucket; no timestamp or opaque identifier is emitted to the model table. Collection windows are local audit/split labels, never model columns. It reports `blocked-no-feature-variation` if all allowed features are constant, `blocked-no-task-holdout` if there are fewer than two shared tasks, and `blocked-no-temporal-holdout` if fewer than two declared collection windows are available. `ready-for-baseline` means only that those **collection gates** passed; it does not establish generalization, calibration, a population FPR or an operating threshold.

## ATI-PF-2 baseline ladder

`ati pf2-baseline` consumes the two artifacts the preflight wrote and runs the baseline
ladder from the controlled-corpus feature contract: first a non-model constant-prevalence
classifier, then one L2-regularized logistic regression over the permitted feature
families only. It adds no runtime dependency; the estimator is a damped Newton solve in
the standard library.

```bash
ati pf2-baseline model.jsonl \
  --split-manifest splits.jsonl \
  --output baseline.json \
  --target-false-positive-rate 0.05 \
  --resamples 1000 \
  --seed 0
```

The split manifest is used **only** to build partitions. Its columns never reach an
estimator, a scaler, a threshold search or an ablation, and the report never emits an
opaque session pseudonym.

### Holdouts

| Split kind | Construction |
|---|---|
| `temporal` | Forward-chained by declared collection window: window *i* trains only on windows *0…i−1*, so the earliest window is never a holdout and the last is the **final temporal holdout**. |
| `unseen_task` | Leave-one-audit-task-out. |
| `grouped_session` | Deterministic seeded partition of opaque sessions. |

Because the ATI-PF-2 model table holds exactly one row per opaque session, a grouped
session split is a row split by construction, and resampling rows is session-cluster
resampling. Every split is checked for train/holdout session overlap and fails closed.

### Operating point and uncertainty

Standardization statistics, coefficients and the operating threshold are all derived
inside each split's training partition. With `--target-false-positive-rate` the threshold
is the lowest train-partition threshold whose **train** false-positive rate meets the
target; it is never selected after looking at the holdout. Each metric carries a
percentile interval from session-cluster resampling, and
`logistic_beats_constant` requires both a point-estimate win on PR-AUC and a resampled
lower bound above the constant baseline's point estimate.

`--target-false-positive-rate` makes `meets_predeclared_false_positive_rate` meaningful:
a `false` there is the expected, honest signal that a train-selected threshold did not
transfer, not a reason to retune against the holdout.

### Ablations and fail-closed statuses

One refit per permitted feature family reports that family's PR-AUC delta. The run fails
closed with an error on a prohibited model column, a missing or non-boolean target, a
duplicate `row_index`, a duplicate or non-opaque session pseudonym, an unsupported split
field, or a split-manifest row count that does not match the model table. A split whose
train or holdout side lacks a class is recorded as `blocked-single-class` with **no**
metrics, and the overall status becomes `blocked-single-class-split`.

`evaluated` means the declared holdouts were computed. It does not establish
generalization to public traffic, a population false-positive rate, calibrated
probabilities or an enforcement threshold.

## Warehousing a baseline run

`ati pf2-export-bigquery` prepares local, aggregate, firewall-checked warehouse tables
plus their BigQuery schemas and `CREATE TABLE` DDL. **ATI never uploads a corpus**: the
operator loads the artifacts deliberately.

```bash
ati pf2-export-bigquery model.jsonl \
  --report baseline.json \
  --output-dir export/ \
  --run-id 'controlled-pf2-2026-09-26' \
  --corpus-id 'controlled-pf2-2026-09' \
  --dataset ati_pf2
```

| Table | Grain |
|---|---|
| `pf2_run_manifest` | One row per run: status, counts, prevalence, firewall assertions, verdict. |
| `pf2_baseline_metrics` | One row per split × model, including session-cluster interval bounds. |
| `pf2_baseline_ablations` | One row per split × removed feature family. |
| `pf2_feature_summary` | One row per feature × class: count, distinct values, min, max, mean. |
| `pf2_cohort_counts` | One row per task or collection window × class. |

The split manifest is **not exportable** and the exporter refuses it. Per-session feature
rows are not exported either: a rare feature vector can single out a session, which the
feature contract treats as a high-resolution indirect identifier, so the feature table is
reduced to per-class aggregates. The export fails closed if a row carries a column that
is prohibited or absent from the declared schema, and the dataset and project names are
validated before they reach any DDL.

## Corpus handling

Do not commit production logs, raw IP addresses, cookies, Authorization headers, request bodies, or third-party datasets whose license is incompatible with this Apache-2.0 repository. Keep corpora outside version control and record their provenance, authorization, collection window, label source, and known sampling bias in a separate local manifest.

## Authorized corpus manifest

Use `--manifest` when results are intended to inform a benchmark, threshold, or future learned-detection decision. The manifest is one local JSON object and contains metadata only—never traffic records, raw identifiers, or label content. ATI requires the following exact fields:

```json
{
  "schema_version": 1,
  "corpus_id": "owned-shadow-2026-08",
  "authorized": true,
  "collection_start": "2026-08-01T00:00:00Z",
  "collection_end": "2026-08-02T00:00:00Z",
  "split_strategies": [
    "grouped_session_client",
    "temporal_holdout",
    "unseen_family_holdout",
    "provider_ua_ablation"
  ],
  "known_sampling_biases": ["controlled-traffic-overrepresentation"]
}
```

The validator rejects unauthorized corpora, unknown manifest fields, missing leakage-control strategies, duplicate strategies, timezone-free or invalid collection windows, and missing sampling-bias disclosure. Manifest-gated labels must also bind to the exact `corpus_id`, which prevents records from one authorized corpus being mixed silently into another. Their exact permitted fields are `request_id`, `automated`, `label_source`, `label_confidence`, and `corpus_id`; unexpected fields are rejected rather than silently ignored. This does not train, calibrate, or retain a model; it establishes evidence prerequisites only.

```json
{"request_id":"privacy-safe-request-id","automated":true,"label_source":"controlled-generator","label_confidence":1.0,"corpus_id":"owned-shadow-2026-08"}
```

```bash
ati evaluate detections.jsonl --labels labels.jsonl --manifest corpus-manifest.json --threshold 0.5
```

## Local run artifact

When one authorized corpus needs repeatable analysis and evaluation, use `ati run`. It writes a **new** local directory atomically, so a failed parse or evaluation never leaves a partial result in the requested location.

```bash
ATI_HASH_KEY="local-secret" ati run access.jsonl \
  --run-dir runs/owned-shadow-2026-08 \
  --labels labels.jsonl \
  --manifest corpus-manifest.json \
  --threshold 0.5
```

The directory contains `detections.jsonl`, `evaluation.json`, `run.json`, and `summary.md`. It intentionally does **not** copy the raw access log, labels, or corpus manifest; those remain user-owned local inputs. `run.json` records only the ATI version, approved `corpus_id`, non-sensitive analysis options, and fixed artifact names. ATI refuses to overwrite an existing run directory.

> This is a local reproducibility convention, not a database, dashboard, telemetry service, or model-training workflow.

`summary.md` also reports a deterministic **quality status** from the existing evaluation coverage signals. It is `ready` only when at least one detection was evaluated and both `unlabeled_request_count` and `unmatched_label_count` are zero. Otherwise it is `review-required`; investigate the counts in `evaluation.json` before cleaning, comparing, or modeling the corpus. The status does not validate raw-log completeness, remove records, or certify that labels are correct.
