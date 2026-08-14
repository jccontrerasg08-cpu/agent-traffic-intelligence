.PHONY: test lint typecheck check smoke

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy src

check: lint typecheck test

smoke:
	ATI_HASH_KEY=local-smoke-key ati analyze examples/data/access.jsonl --output /tmp/ati-detections.jsonl
	ati registry validate
