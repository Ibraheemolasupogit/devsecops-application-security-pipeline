"""Configuration helpers for the Repository 5 integration contract."""

from __future__ import annotations

import os
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

CONTRACT_NAME = "product-security-control-plane-export"
CONTRACT_VERSION = "1.0"
PRODUCER = "devsecops-application-security-pipeline"
PRODUCER_REPOSITORY = "devsecops-application-security-pipeline"
PRODUCER_SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"
DEPLOYMENT_STATUS = "not_deployed"

CONFIG_DIR = ROOT / "config/integration"
OUTPUT_DIR = ROOT / "outputs/security/integration"
REPORT_DIR = ROOT / "reports/security"
SCHEMA_DIR = ROOT / "schemas/security/integration"


def evidence_timestamp(default: str = DEFAULT_TIMESTAMP) -> str:
    return os.environ.get("EVIDENCE_TIMESTAMP", default)


def integration_as_of_date(default: str = DEFAULT_AS_OF_DATE) -> str:
    return os.environ.get("INTEGRATION_AS_OF_DATE", default)


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return payload
