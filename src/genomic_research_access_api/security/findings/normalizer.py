"""Findings normalisation, enrichment and output construction."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.findings.adapters import ADAPTERS, load_all
from genomic_research_access_api.security.findings.config import DEFAULT_AS_OF_DATE
from genomic_research_access_api.security.findings.deduplicator import deduplicate
from genomic_research_access_api.security.findings.enrichment import apply_asset_context
from genomic_research_access_api.security.findings.models import Finding
from genomic_research_access_api.security.findings.ownership import apply_ownership
from genomic_research_access_api.security.findings.risk import apply_risk
from genomic_research_access_api.security.findings.sla import apply_sla


def normalise(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    return load_all(as_of_date)


def enrich(findings: list[Finding], as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    apply_asset_context(findings)
    apply_ownership(findings)
    apply_risk(findings)
    apply_sla(findings, as_of_date)
    return sorted(findings, key=lambda item: item.finding_id)


def build(
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> tuple[list[Finding], list[Finding], dict[str, dict[str, Any]]]:
    source_findings = enrich(normalise(as_of_date), as_of_date)
    deduped, source_map = deduplicate(source_findings)
    enrich(deduped, as_of_date)
    return source_findings, deduped, source_map


def source_tool_names() -> list[str]:
    return sorted(name for name in ADAPTERS if name != "suppressions")
