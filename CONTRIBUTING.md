# Contributing

Thanks for helping improve Agent Traffic Intelligence.

## Principles

- Keep detection explainable. New rules need a named evidence code and a clear reason.
- Keep `automation`, `ai`, `identity`, and `risk` independent.
- Treat User-Agent strings as claims, not verification.
- Do not commit production logs, secrets, raw packet captures, or personal data.
- Prefer primary-source documentation for agent identity registry changes.
- Do not copy code from research references without an explicit license review.

## Development setup

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy src
```

## Pull requests

1. Add or update tests first for behavior changes.
2. Keep changes scoped and document externally visible behavior.
3. Run `make check` before opening a PR.
4. For registry entries, include an official source URL and verification date.
5. For new data/features, document privacy implications and leakage risks.
6. For a new module, preserve a public facade or explicitly version the breaking interface; record the boundary in `docs/architecture/modular-boundaries.md`.
7. For a new environment or variation, add an example under `environments/`, a Makefile profile or an explicit reason not to have one, and a row in `docs/cases-and-variations.md`.
8. For a research track, add a `ResearchCase` contract with owner, data categories, retention policy, metrics, and an authorization reference before it can be marked ready for review.

## Machine-learning contributions

Do not report a model as better based only on request-random train/test splits. Evaluation must group correlated requests and include temporal or unseen-family tests where relevant. Report precision, recall, PR-AUC, false-positive rate, calibration, and the operating threshold.
