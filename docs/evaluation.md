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
