# Engineering principles in practice

This project follows four books. This page maps each principle to where it shows up in the
code, so a reviewer can check the claim instead of taking it on trust. Paths without a host
are in this repository; `lab:` paths are in
[ati-observation-lab](https://github.com/jccontrerasg08-cpu/ati-observation-lab).

## *The Pragmatic Programmer* (Hunt and Thomas)

| Principle | Where it shows |
|---|---|
| **DRY: one authoritative representation of each piece of knowledge.** | The closed route catalogue exists once, in `lab:src/observation_lab/pf2/catalogue.json`. The origin, the Worker's allowlist, the executor's route plans and ATI's route categories are each held to it by a test (`lab:tests/test_pf2_catalogue.py`, `tests/evaluation/test_pf2_catalogue_parity.py`). The duplication that remains, a JavaScript literal in the Worker, is *checked*, not trusted. |
| **Orthogonality.** | Four independent scores ([ADR 0002](adr/0002-separate-score-dimensions.md)): verifying an identity never changes the automation or risk score. Packages (`ingestion`, `detection`, `identity`, `evaluation`, `runtime`) have explicit contracts ([modular boundaries](architecture/modular-boundaries.md)). |
| **Crash early / design by contract.** | Every pipeline stage fails closed with a named error (`PF2ProtocolError`, `PF2BaselineError`, `PF2ExportError`, `lab: CorpusError`) instead of producing a number from bad input. A single-class split is reported as `blocked-single-class`, never scored. |
| **Tracer bullets.** | A live campaign ran through the real edge and origin, end to end, before any model was trusted. It surfaced four protocol-changing findings no unit test could ([live collection evidence](architecture/pf2-live-collection-evidence.md)). |
| **Don't program by coincidence.** | Refactors are verified by capturing outputs before the change and diffing them after: the CLI parser tree, a baseline report and a warehouse export were byte-identical. For the perimeter checker, the trace caught a probe reordering that every unit test missed. |
| **Don't live with broken windows.** | `tests/test_docs_links.py` fails the build on any broken relative link in the documentation. `ruff`, `mypy --strict` and the coverage gate run in CI. |
| **Ruthless, automated testing.** | `make` profiles per area; `make check` in the laboratory is exactly what CI runs. `ati-lab-perimeter` turns a 22-point production checklist into one command run after every deploy. |

## *Code Complete* (McConnell)

| Principle | Where it shows |
|---|---|
| **Routines do one thing, at one level of abstraction.** | `evaluate_pf2_baseline` reads as: validate options, validate inputs, build splits, assert each disjoint, evaluate each split, assemble the report (`evaluation/pf2/baseline.py`). Before refactoring it was one 157-line routine. |
| **Keep parameter lists short; group what travels together.** | `_LadderOptions` bundles the four hyperparameters every split needs instead of threading them through each call. |
| **Table-driven methods.** | `SCHEMAS` in `evaluation/pf2/export.py` drives three things from one table: the BigQuery DDL, the JSON schema files, and the check that every exported row uses only declared columns. The route catalogue drives the origin's content table and the executor's plans the same way. |
| **Defensive programming at the boundary, trust inside it.** | Input is validated once, where it enters: JSONL line-length limits, opaque-identifier formats (`^hmac-sha256:[0-9a-f]{64}$`) and the permitted-column vocabulary. Internal routines then rely on those guarantees. |
| **Bounded resources.** | `SessionFeatureState` keeps at most `max_clients` sessions with LRU eviction and a sliding time window (`features/session.py`), so memory stays bounded on unbounded input. |
| **Construction quality gates.** | Strict static typing on every module, an 85% coverage floor, hash-pinned dependency installs (`--require-hashes`) and compile checks in CI. |

## *Clean Code* (Martin)

| Principle | Where it shows |
|---|---|
| **Small functions.** | The CLI parser went from one 324-line function to a dispatcher plus one `_add_<command>_command` per subcommand; the 8 copies of `--max-line-characters` became one helper (`cli.py`). The live perimeter checker became five functions, each named for the guarantee it proves (`lab:src/observation_lab/pf2/perimeter.py`). |
| **Names that reveal intent.** | Tests read as specifications: `test_operating_threshold_comes_from_the_training_partition_only`, `test_labels_come_from_the_recorded_cohort_not_from_behaviour`, `test_a_pacing_regime_used_by_one_class_only_blocks_fitting`. |
| **Comments explain *why*, not *what*.** | For example, why a per-session warehouse row is forbidden ("a rare feature vector can single out a session"), or why probe order is part of the perimeter contract. |
| **Error handling is one thing.** | Errors are dedicated exception types caught once, at the CLI boundary, and turned into an exit code and a message; nothing is swallowed. |
| **F.I.R.S.T. tests.** | Fast (the laboratory suite runs in about 2 s), independent (temporary directories), repeatable (seeded randomness), self-validating, and written alongside the code. Property-based tests (Hypothesis) generate arbitrary valid corpora, JSONL input and IP ranges. |

## *Designing Data-Intensive Applications* (Kleppmann)

| Principle | Where it shows |
|---|---|
| **Systems of record versus derived data.** | Privacy-safe access logs are the system of record. Corpora, feature tables, baseline reports and warehouse tables are all *derived*, regenerated by deterministic commands, and never edited by hand. |
| **Batch processing in the Unix style.** | Each stage is a separate command that reads files and writes new files, refusing to overwrite: `ati-lab-corpus` → `ati pf2-preflight` → `ati pf2-baseline` → `ati pf2-export-bigquery` → `bq load`. Any stage can be rerun or inspected in isolation. |
| **Atomic writes: all or nothing.** | Multi-file outputs are written into a staging directory and renamed into place only when complete; on any failure the staging directory is removed and the error re-raised (`_pf2_export_bigquery` and `run` in `cli.py`). A reader never sees half an export. |
| **Immutable, append-only records.** | Warehouse tables are append-only and keyed by `run_id`; a correction is a new run, never an update ([ADR 0008](adr/0008-aggregate-only-warehouse-export.md)). |
| **Explicit schemas and encodings.** | JSON Schemas for events, detections and verification (`schemas/`); a declared BigQuery schema per table, with `REQUIRED` modes that the DDL enforces as `NOT NULL`. |
| **Trust boundaries and integrity between components.** | The origin refuses traffic the edge did not vouch for, using a shared token compared in constant time. Sessions are HMAC-signed and bound to one campaign, so they cannot be forged, extended or replayed elsewhere. Production checks prove all three. |
| **Reliability means faults are expected, not exceptional.** | A session with a missing or mismatched record is *excluded and counted*, never repaired or silently dropped (`lab:src/observation_lab/pf2/corpus.py`). |
| **Doing the right thing with data** (ch. 12). | No raw IP addresses, cookies, credentials or bodies are stored; addresses become keyed pseudonyms; warehouse exports are aggregates only; a human cohort requires recorded, voluntary consent. |

## Where the project still falls short

The same standards applied honestly:

- Several identity-verification routines are still long (`identity/crypto/web_bot_auth.py`
  `verify` is about 150 lines). They are heavily tested, but they are the next refactoring
  candidates.
- Some architecture and evidence records are in Spanish, the language they were written in,
  while the code and newer documents are in English.
- Detection quality on real human traffic is unmeasured until a consented cohort exists.
