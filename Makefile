.PHONY: \
	test test-all test-core test-identity test-service test-public test-research test-controlled \
	test-evaluation profile-matrix lint typecheck check package smoke smoke-service

test:
	$(MAKE) test-all

test-all:
	PYTHONPATH=src:. pytest -q

test-core:
	PYTHONPATH=src pytest -q tests/test_models.py tests/test_features.py tests/test_parser.py tests/test_registry.py tests/test_schemas.py tests/test_scoring.py tests/detection tests/ingestion

test-identity:
	PYTHONPATH=src pytest -q tests/identity tests/test_source_health_workflow.py

test-service:
	PYTHONPATH=src pytest -q tests/test_service.py

test-public:
	PYTHONPATH=src:. pytest -q tests/test_public_observation.py

test-research:
	PYTHONPATH=src pytest -q tests/research

test-controlled:
	PYTHONPATH=src:. pytest -q tests/test_cli.py tests/test_evaluation.py tests/lab
	ruff check lab tests/lab
	mypy lab

test-evaluation:
	PYTHONPATH=src pytest -q tests/test_evaluation.py

profile-matrix: test-core test-identity test-service test-public test-research test-controlled test-evaluation smoke-service

lint:
	ruff check src tests

typecheck:
	mypy src

check: lint typecheck test-all

package:
	rm -rf build dist
	pip wheel --no-deps --wheel-dir dist .
	pip check

smoke:
	ATI_HASH_KEY=local-smoke-key ati analyze examples/data/access.jsonl --output /tmp/ati-detections.jsonl
	ati registry validate

smoke-service: package
	pip install --force-reinstall --no-deps dist/*.whl
	./scripts/smoke_service.sh
