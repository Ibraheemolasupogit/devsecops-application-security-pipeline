"""Asset-context enrichment for canonical findings."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.findings.config import load_config
from genomic_research_access_api.security.findings.models import Finding


def asset_inventory() -> list[dict[str, Any]]:
    assets = load_config("asset-context.yaml")["assets"]
    if not isinstance(assets, list):
        raise ValueError("asset inventory must be a list")
    return [dict(asset) for asset in assets]


def apply_asset_context(findings: list[Finding]) -> list[Finding]:
    assets = {asset["asset_id"]: asset for asset in asset_inventory()}
    for finding in findings:
        asset = assets.get(finding.asset_id or "")
        if asset is None:
            finding.asset_id = finding.asset_id or "unknown"
            continue
        finding.asset_type = asset["type"]
        finding.asset_criticality = asset["criticality"]
        finding.data_sensitivity = asset["data_sensitivity"]
        finding.internet_exposure = asset["internet_exposure"]
        finding.environment = asset["environment"]
        if not finding.threat_ids:
            finding.threat_ids = list(asset.get("threat_ids", []))
        if not finding.security_requirement_ids:
            finding.security_requirement_ids = list(asset.get("security_requirement_ids", []))
        finding.metadata.setdefault("asset_name", asset["name"])
    return findings
