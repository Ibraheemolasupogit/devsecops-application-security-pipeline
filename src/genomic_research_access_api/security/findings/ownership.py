"""Deterministic ownership assignment for findings."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from genomic_research_access_api.security.findings.config import load_config
from genomic_research_access_api.security.findings.models import Finding


def apply_ownership(findings: list[Finding]) -> list[Finding]:
    config = load_config("ownership.yaml")
    for finding in findings:
        values = _match_path(config, finding) or config.get("source_tool_defaults", {}).get(
            finding.source_tool
        )
        if values is None:
            values = config["unowned"]
        finding.squad = values["squad"]
        finding.technical_owner = values["technical_owner"]
        finding.risk_owner = values["risk_owner"]
        finding.remediation_owner = values["remediation_owner"]
    return findings


def _match_path(config: dict[str, Any], finding: Finding) -> dict[str, Any] | None:
    candidates = [
        finding.file,
        finding.resource,
        finding.component,
        finding.package_name,
        finding.metadata.get("repository_path") if finding.metadata else None,
    ]
    for rule in config["rules"]:
        pattern = rule["match"]
        for candidate in candidates:
            if candidate and (fnmatch(candidate, pattern) or candidate == pattern):
                return dict(rule)
    return None
