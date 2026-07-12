"""Configuration loading for the Milestone 5 AppSec pipeline."""

import json
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from genomic_research_access_api.security.threat_model.io import ROOT

SECURITY_DIR = ROOT / "security"
APPSEC_OUTPUT_DIR = ROOT / "outputs" / "security" / "appsec"
RAW_DIR = APPSEC_OUTPUT_DIR / "raw"
REPORT_DIR = ROOT / "reports" / "security"
TOOLS = {"gitleaks", "semgrep", "bandit", "pip-audit", "cyclonedx", "checkov", "trivy"}


def load_json_yaml(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    suppression_id: str
    tool: str
    rule_or_advisory_id: str
    resource_or_path: str
    reason: str
    owner: str
    approved_by: str
    created_date: date
    review_date: date
    expiry_date: date
    compensating_control: str
    status: str

    @field_validator("tool")
    @classmethod
    def tool_must_be_known(cls, value: str) -> str:
        if value not in TOOLS:
            raise ValueError("unknown tool")
        return value

    @field_validator("resource_or_path")
    @classmethod
    def scope_must_be_narrow(cls, value: str) -> str:
        if value in {"*", "**", "**/*"} or value.endswith("/*"):
            raise ValueError("wildcard suppression scopes are not allowed")
        return value

    @model_validator(mode="after")
    def dates_must_be_valid(self) -> "Suppression":
        if self.expiry_date <= self.created_date:
            raise ValueError("expiry_date must be after created_date")
        if self.status == "active" and self.expiry_date < date.today():
            raise ValueError("active suppression is expired")
        return self


def validate_suppressions(
    path: Path = SECURITY_DIR / "config" / "suppressions.yaml",
) -> list[Suppression]:
    payload = load_json_yaml(path)
    suppressions = [Suppression.model_validate(item) for item in payload["suppressions"]]
    ids = [item.suppression_id for item in suppressions]
    if len(ids) != len(set(ids)):
        raise ValueError("suppression IDs must be unique")
    return suppressions
