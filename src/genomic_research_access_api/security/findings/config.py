"""Configuration loading for Milestone 7 findings normalisation."""

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

OUTPUT_DIR = ROOT / "outputs" / "security" / "findings"
REPORT_DIR = ROOT / "reports" / "security"
CONFIG_DIR = ROOT / "config" / "findings"
SCHEMA_DIR = ROOT / "schemas" / "security" / "findings"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"findings config must be an object: {name}")
    return payload


def all_config_files() -> list[Path]:
    return sorted(CONFIG_DIR.glob("*.yaml"))
