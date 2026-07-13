"""Explicit evidence source discovery."""

from __future__ import annotations

from pathlib import Path

from genomic_research_access_api.security.evidence.config import load_config
from genomic_research_access_api.security.evidence.models import SourceDefinition
from genomic_research_access_api.security.threat_model.io import ROOT


def source_registry() -> list[SourceDefinition]:
    payload = load_config("source-registry.yaml")
    return [SourceDefinition.model_validate(item) for item in payload["sources"]]


def manifest_path(source: SourceDefinition) -> Path:
    return ROOT / source.manifest_path


def validate_source_registry() -> dict[str, object]:
    sources = source_registry()
    errors: list[str] = []
    ids = [item.source_id for item in sources]
    domains = [item.domain for item in sources]
    if len(ids) != len(set(ids)):
        errors.append("source_id values must be unique")
    if len(domains) != len(set(domains)):
        errors.append("domain values must be unique")
    for source in sources:
        if source.required and not manifest_path(source).exists():
            errors.append(f"required source manifest missing: {source.source_id}")
        if source.contains_sensitive_data:
            errors.append(f"source must not contain sensitive data: {source.source_id}")
    return {
        "schema_version": "1.0",
        "source_count": len(sources),
        "valid": not errors,
        "errors": errors,
    }
