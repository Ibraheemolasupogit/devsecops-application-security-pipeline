"""Configuration loading for Security Champions."""

from __future__ import annotations

import os
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"
CONFIG_DIR = ROOT / "config" / "security-champions"
OUTPUT_DIR = ROOT / "outputs" / "security" / "champions"
REPORT_DIR = ROOT / "reports" / "security"
DOC_DIR = ROOT / "security-champions"


def evidence_timestamp() -> str:
    return os.environ.get("EVIDENCE_TIMESTAMP", DEFAULT_TIMESTAMP)


def as_of_date() -> str:
    return os.environ.get("CHAMPIONS_AS_OF_DATE", DEFAULT_AS_OF_DATE)


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"Security Champions config must be an object: {name}")
    return payload


def load_configs() -> dict[str, dict[str, Any]]:
    return {
        "policy": load_config("programme-policy.yaml"),
        "squads": load_config("squad-inventory.yaml"),
        "roster": load_config("champion-roster.yaml"),
        "metrics": load_config("metric-definitions.yaml"),
        "workshops": load_config("workshop-catalogue.yaml"),
        "escalation": load_config("escalation-policy.yaml"),
        "maturity": load_config("maturity-model.yaml"),
    }
