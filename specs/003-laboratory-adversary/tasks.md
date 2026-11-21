# Tasks: A Laboratory Adversary

- [X] T001 [US1] Executor tests: default timer recorded; human cohort refused; unknown
  pacing refused; `imitate-content` needs `ati-pf2-1.1`; pauses only before navigations;
  imitation leaves the regime's range at times; long-over-short ratios per adversary; no
  pause in the record; CLI records and refuses (lab `tests/test_pf2_executor.py`)
- [X] T002 [US1] `AUTOMATION_PACINGS`, `LOAD_FACTOR` and `_Pacer` in the lab executor, and
  the `--automation-pacing` flag
- [X] T003 [US2] Corpus tests and implementation: adversary in the summary, legacy record
  as timer, mixed adversaries blocked, unknown value fails closed
- [X] T004 [P] Pin the load factors on both sides (lab executor tests, ATI simulation tests)
- [X] T005 [P] Lab README and runbook: one corpus per adversary against the same humans
- [X] T006 Live `imitate-content` session through the production edge
- [X] T007 `make check` in both repositories
