.PHONY: setup install format format-check lint type-check test test-coverage auth-test api-security-test terraform-fmt terraform-fmt-check terraform-init terraform-validate terraform-test infrastructure-test infrastructure-evidence verify-infrastructure-evidence infrastructure-report security-tools secrets-scan sast sast-semgrep sast-bandit semgrep-test sca dependency-audit sbom verify-sbom iac-scan checkov-scan container-build-security container-scan appsec-fast appsec-full appsec-evidence verify-appsec-evidence appsec-report dynamic-tools dynamic-server-start dynamic-server-wait dynamic-server-stop schemathesis-test api-schema-security-test zap-baseline zap-api-scan auth-boundary-test authorisation-boundary-test object-access-test input-mutation-test security-header-test cors-test resource-consumption-test audit-dynamic-test dast dynamic-evidence verify-dynamic-evidence dynamic-report dynamic-fast dynamic-full pre-commit-install pre-commit-run quality run docker-build docker-run threat-model-validate threat-model-evidence verify-threat-model-evidence threat-model-report api-security-evidence verify-api-security-evidence api-security-report dev-token-researcher dev-token-approver dev-token-auditor clean

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

auth-test:
	PYTHONPATH=src $(PYTEST) tests/security/test_api_security_controls.py -q -k "token or auth"

api-security-test:
	PYTHONPATH=src $(PYTEST) tests/security/test_api_security_controls.py -q

terraform-fmt:
	PYTHONPATH=src $(PYTHON) scripts/terraform_local.py fmt

terraform-fmt-check:
	PYTHONPATH=src $(PYTHON) scripts/terraform_local.py fmt-check

terraform-init:
	PYTHONPATH=src $(PYTHON) scripts/terraform_local.py init

terraform-validate:
	PYTHONPATH=src $(PYTHON) scripts/terraform_local.py validate

terraform-test:
	PYTHONPATH=src $(PYTHON) scripts/terraform_local.py test

infrastructure-test:
	PYTHONPATH=src $(PYTEST) infrastructure/tests -q

infrastructure-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.infrastructure.evidence --timestamp 2026-01-01T00:00:00Z

verify-infrastructure-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.infrastructure.evidence --verify

infrastructure-report:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.infrastructure.report

security-tools:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py security-tools

secrets-scan:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py gitleaks

sast-semgrep:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py semgrep

semgrep-test:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py semgrep-test

sast-bandit:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py bandit

sast: sast-semgrep sast-bandit

dependency-audit:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py dependency-audit

sca: dependency-audit

sbom:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py sbom

verify-sbom:
	PYTHONPATH=src $(PYTHON) -c "from genomic_research_access_api.security.appsec.parsers import validate_cyclonedx; from genomic_research_access_api.security.appsec.evidence import SBOM_PATH; validate_cyclonedx(SBOM_PATH)"

checkov-scan:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py checkov

iac-scan: checkov-scan

container-build-security:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py container-build

container-scan:
	PYTHONPATH=src $(PYTHON) scripts/appsec_tools.py trivy

appsec-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.appsec.evidence --timestamp 2026-01-01T00:00:00Z

verify-appsec-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.appsec.evidence --verify

appsec-report:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.appsec.report

appsec-fast: secrets-scan sast dependency-audit

appsec-full: appsec-fast sbom verify-sbom checkov-scan container-build-security container-scan appsec-evidence verify-appsec-evidence appsec-report

dynamic-tools:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py tools

dynamic-server-start:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py server-start

dynamic-server-wait:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py server-wait

dynamic-server-stop:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py server-stop

schemathesis-test:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py schemathesis

api-schema-security-test: schemathesis-test

zap-baseline:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py zap

zap-api-scan: zap-baseline

auth-boundary-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k authentication --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

authorisation-boundary-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k authorisation --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

object-access-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k object_level --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

input-mutation-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k input_mutation --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

security-header-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k security_headers --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

cors-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k cors --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

resource-consumption-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k rate_limit --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

audit-dynamic-test:
	PYTHONPATH=src $(PYTEST) tests/dynamic -q -k audit --json-report --json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json

dast: zap-baseline

dynamic-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.dynamic.evidence --timestamp 2026-01-01T00:00:00Z

verify-dynamic-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.dynamic.evidence --verify

dynamic-report:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.dynamic.report

dynamic-fast:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py pytest

dynamic-full:
	PYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py full

pre-commit-install:
	$(PYTHON) -m pip install pre-commit==3.8.0
	$(VENV)/bin/pre-commit install

pre-commit-run:
	$(VENV)/bin/pre-commit run --all-files

quality: format-check lint type-check test-coverage auth-test api-security-test threat-model-validate verify-threat-model-evidence verify-api-security-evidence terraform-fmt-check infrastructure-test verify-infrastructure-evidence verify-appsec-evidence

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

api-security-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.api_security.evidence --timestamp 2026-01-01T00:00:00Z

verify-api-security-evidence:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.api_security.evidence --verify

api-security-report:
	PYTHONPATH=src $(PYTHON) -m genomic_research_access_api.security.api_security.report

dev-token-researcher:
	PYTHONPATH=src $(PYTHON) scripts/generate_dev_token.py --subject researcher-001

dev-token-approver:
	PYTHONPATH=src $(PYTHON) scripts/generate_dev_token.py --subject approver-001

dev-token-auditor:
	PYTHONPATH=src $(PYTHON) scripts/generate_dev_token.py --subject auditor-001

clean:
	rm -rf .coverage .mypy_cache .pytest_cache .ruff_cache build dist *.egg-info src/*.egg-info
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
