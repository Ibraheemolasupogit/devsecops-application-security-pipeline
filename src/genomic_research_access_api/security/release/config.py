"""Release gate configuration loading."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.threat_model.io import ROOT

CONFIG_DIR = ROOT / "config" / "release"
OUTPUT_DIR = ROOT / "outputs" / "security" / "release"
REPORT_DIR = ROOT / "reports" / "security"
SCHEMA_DIR = ROOT / "schemas" / "security" / "release"
FINDINGS_PATH = ROOT / "outputs" / "security" / "findings" / "deduplicated-findings.json"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
DEFAULT_AS_OF_DATE = "2026-01-01"
DEFAULT_ENVIRONMENT = "dev"


def read_json_yaml(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_config(name: str) -> dict[str, Any]:
    payload = read_json_yaml(CONFIG_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"release config must be an object: {name}")
    return payload


def policy_version() -> str:
    return str(load_config("release-policy.yaml")["policy_version"])


def release_environment(default: str = DEFAULT_ENVIRONMENT) -> str:
    return os.environ.get("RELEASE_ENVIRONMENT", default)


def release_as_of_date(default: str = DEFAULT_AS_OF_DATE) -> str:
    return os.environ.get("RELEASE_AS_OF_DATE", default)


def evidence_timestamp(default: str = DEFAULT_TIMESTAMP) -> str:
    return os.environ.get("EVIDENCE_TIMESTAMP", default)


def all_config_files() -> list[Path]:
    return sorted(CONFIG_DIR.glob("*.yaml"))
