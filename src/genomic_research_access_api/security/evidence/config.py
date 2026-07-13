"""Configuration and paths for consolidated evidence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

CONFIG_DIR = ROOT / "config" / "evidence"
OUTPUT_DIR = ROOT / "outputs" / "security" / "evidence"
REPORT_DIR = ROOT / "reports" / "security"
SCHEMA_DIR = ROOT / "schemas" / "security" / "evidence"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"evidence config must be an object: {name}")
    return payload


def evidence_timestamp(default: str = DEFAULT_TIMESTAMP) -> str:
    return os.environ.get("EVIDENCE_TIMESTAMP", default)


def evidence_as_of_date(default: str = DEFAULT_AS_OF_DATE) -> str:
    return os.environ.get("EVIDENCE_AS_OF_DATE", default)


def all_config_files() -> list[Path]:
    return sorted(CONFIG_DIR.glob("*.yaml"))
