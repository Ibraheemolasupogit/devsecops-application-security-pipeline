.PHONY: setup install format format-check lint type-check test test-coverage quality run docker-build docker-run threat-model-validate threat-model-evidence verify-threat-model-evidence threat-model-report clean

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
UVICORN := $(VENV)/bin/uvicorn

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip==25.1.1
	$(PIP) install -e ".[dev]"

install:
	$(PIP) install -e ".[dev]"

format:
	$(RUFF) format .
	$(RUFF) check --fix .

format-check:
	$(RUFF) format --check .

lint:
	$(RUFF) check .

type-check:
	PYTHONPATH=src $(MYPY) src tests

test:
	PYTHONPATH=src $(PYTEST)

test-coverage:
	PYTHONPATH=src $(PYTEST) --cov --cov-report=term-missing --cov-fail-under=85

quality: format-check lint type-check test-coverage threat-model-validate verify-threat-model-evidence

run:
	PYTHONPATH=src $(UVICORN) genomic_research_access_api.main:app --host 127.0.0.1 --port 8000

docker-build:
	docker build -t genomic-research-access-api:0.1.0 .

docker-run:
	docker run --rm -p 8000:8000 genomic-research-access-api:0.1.0

threat-model-validate:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.threat_model.validate

threat-model-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.threat_model.evidence --timestamp 2026-01-01T00:00:00Z

verify-threat-model-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.threat_model.evidence --verify

threat-model-report:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.threat_model.report

clean:
	rm -rf .coverage .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info src/*.egg-info
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
