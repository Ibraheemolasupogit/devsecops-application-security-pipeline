"""Lifecycle configuration paths and loaders."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json_yaml
from genomic_research_access_api.security.threat_model.io import ROOT

CONFIG_DIR = ROOT / "config" / "lifecycle"
FIXTURE_DIR = CONFIG_DIR / "fixtures"
OUTPUT_DIR = ROOT / "outputs" / "security" / "lifecycle"
REPORT_DIR = ROOT / "reports" / "security"
SCHEMA_DIR = ROOT / "schemas" / "security" / "lifecycle"
FINDINGS_PATH = ROOT / "outputs" / "security" / "findings" / "deduplicated-findings.json"
SOURCE_MAP_PATH = ROOT / "outputs" / "security" / "findings" / "finding-source-map.json"
RELEASE_DECISION_PATH = ROOT / "outputs" / "security" / "release" / "release-gate-decision.json"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"lifecycle config must be an object: {name}")
    return payload


def load_fixture(name: str) -> dict[str, Any]:
    payload = read_json_yaml(FIXTURE_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"lifecycle fixture must be an object: {name}")
    return payload


def policy_version() -> str:
    return str(load_config("lifecycle-policy.yaml")["policy_version"])


def as_of_date(default: str = DEFAULT_AS_OF_DATE) -> str:
    return os.environ.get("LIFECYCLE_AS_OF_DATE", default)


def evidence_timestamp(default: str = DEFAULT_TIMESTAMP) -> str:
    return os.environ.get("EVIDENCE_TIMESTAMP", default)


def all_config_files() -> list[Path]:
    return sorted([*CONFIG_DIR.glob("*.yaml"), *FIXTURE_DIR.glob("*.yaml")])
