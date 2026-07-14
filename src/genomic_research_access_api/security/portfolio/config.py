"""Configuration for portfolio readiness artefacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

CONFIG_DIR = ROOT / "config" / "portfolio"
OUTPUT_DIR = ROOT / "outputs" / "security" / "portfolio"
PACKAGE_DIR = ROOT / "outputs" / "portfolio"
REPORT_DIR = ROOT / "reports" / "portfolio"
PORTFOLIO_DOCS_DIR = ROOT / "docs" / "portfolio"
DIAGRAM_DIR = ROOT / "docs" / "architecture" / "diagrams"
SCHEMA_DIR = ROOT / "schemas" / "security" / "portfolio"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"{name} must contain an object")
    return cast(dict[str, Any], payload)


def config_files() -> list[Path]:
    return sorted(CONFIG_DIR.glob("*.yaml"))
