.PHONY: help dev test lint typecheck sec cov check scan build docker clean

help:
	@echo "targets:"
	@echo "  dev     install in editable mode with dev tools"
	@echo "  test    run the unit test suite"
	@echo "  lint    run ruff"
	@echo "  sec       run bandit SAST"
	@echo "  typecheck run mypy"
	@echo "  cov       run tests with coverage"
	@echo "  check     lint + typecheck + sec + test"
	@echo "  scan    run coverguard on the bundled examples"
	@echo "  build   build the wheel/sdist"
	@echo "  docker  build the container image"
	@echo "  clean   remove build artifacts and reports"

dev:
	python -m pip install -e ".[dev]"

test:
	cd tests && PYTHONPATH=../src python -m unittest discover -p 'test_*.py'

lint:
	python -m ruff check src tests

sec:
	python -m bandit -r src -q -c .bandit.yaml

typecheck:
	python -m mypy --ignore-missing-imports src

cov:
	cd tests && PYTHONPATH=../src python -m coverage run --source=../src -m unittest discover -p 'test_*.py' && python -m coverage report

check: lint typecheck sec test

scan:
	PYTHONPATH=src python -m coverguard scan \
	  --events examples/events.jsonl \
	  --inventory examples/inventory.json \
	  --vulns examples/vuln_snapshot.json \
	  --roster examples/roster.json \
	  --out-html report.html --out-json report.json

build:
	python -m build

docker:
	docker build -t coverguard:latest .

clean:
	rm -rf build dist src/*.egg-info report.html report.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
