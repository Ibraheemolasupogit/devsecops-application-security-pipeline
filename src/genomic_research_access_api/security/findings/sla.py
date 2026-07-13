"""Deterministic remediation SLA calculation."""

from __future__ import annotations

from datetime import date, timedelta

from genomic_research_access_api.security.findings.config import load_config
from genomic_research_access_api.security.findings.models import Finding


def apply_sla(findings: list[Finding], as_of_date: str) -> list[Finding]:
    config = load_config("remediation-sla.yaml")
    base_date = date.fromisoformat(as_of_date)
    for finding in findings:
        days = int(config["sla_days"].get(finding.normalised_severity, 90))
        if finding.suppression_status == "active" and finding.suppression_expiry:
            finding.remediation_sla_days = (
                date.fromisoformat(finding.suppression_expiry) - base_date
            ).days
            finding.due_date = finding.suppression_expiry
        else:
            finding.remediation_sla_days = days
            finding.due_date = (base_date + timedelta(days=days)).isoformat()
    return findings
