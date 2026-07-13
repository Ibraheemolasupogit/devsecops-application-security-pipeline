"""Validation for canonical findings and deterministic evidence."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from genomic_research_access_api.security.findings.enrichment import asset_inventory
from genomic_research_access_api.security.findings.models import Finding
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

LOCAL_ROOT_PATTERN = re.compile(r"/Users/[^\\s]+|/private/var/")
SECRET_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY")


def validate_findings(findings: list[Finding], as_of_date: str) -> None:
    ids = [finding.finding_id for finding in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("finding IDs must be unique")
    valid_assets = {asset["asset_id"] for asset in asset_inventory()} | {"unknown"}
    for finding in findings:
        if finding.asset_id not in valid_assets:
            raise ValueError(f"invalid asset reference: {finding.finding_id}")
        if finding.risk_score is None or not 0 <= finding.risk_score <= 100:
            raise ValueError(f"invalid risk score: {finding.finding_id}")
        if (
            finding.due_date
            and date.fromisoformat(finding.due_date) < date.fromisoformat(as_of_date)
            and finding.suppression_status != "active"
        ):
            raise ValueError(f"invalid due date: {finding.finding_id}")
        payload = finding.model_dump(mode="json")
        text = str(payload)
        if LOCAL_ROOT_PATTERN.search(text):
            raise ValueError(f"absolute local path leaked: {finding.finding_id}")
        if SECRET_PATTERN.search(text):
            raise ValueError(f"secret-like material leaked: {finding.finding_id}")
        if (
            finding.suppression_status == "active"
            and finding.suppression_expiry
            and date.fromisoformat(finding.suppression_expiry) < date.fromisoformat(as_of_date)
        ):
            raise ValueError(f"expired suppression: {finding.suppression_id}")
    ordered = sorted(findings, key=lambda item: item.finding_id)
    if [item.finding_id for item in findings] != [item.finding_id for item in ordered]:
        raise ValueError("findings are not in stable order")


def verify_manifest(output_dir: Path) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    manifest = read_json(manifest_path)
    for details in manifest["output_files"].values():
        raw_path = Path(details["path"])
        path = raw_path if raw_path.is_absolute() else ROOT / raw_path
        if not path.exists() and not raw_path.parts[:-1]:
            path = output_dir / raw_path
        if not path.exists() or sha256_file(path) != details["sha256"]:
            raise ValueError(f"findings evidence checksum mismatch: {details['path']}")
