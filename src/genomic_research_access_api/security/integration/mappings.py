"""Mapping helpers for the product-security export contract."""

from __future__ import annotations

import hashlib
from typing import Any

from genomic_research_access_api.security.integration.config import (
    CONTRACT_VERSION,
    PRODUCER_REPOSITORY,
    load_config,
)


def stable_export_record_id(finding_id: str) -> str:
    source = f"{CONTRACT_VERSION}|{finding_id}|{PRODUCER_REPOSITORY}"
    return f"EXP-{hashlib.sha256(source.encode('utf-8')).hexdigest()[:12].upper()}"


def status_mapping() -> dict[str, str]:
    return {str(k): str(v) for k, v in load_config("status-mapping.yaml")["statuses"].items()}


def map_status(producer_status: str | None) -> str:
    if producer_status is None:
        return "open"
    return status_mapping().get(producer_status, "open")


def severity_mapping() -> dict[str, str]:
    return {str(k): str(v) for k, v in load_config("severity-mapping.yaml")["severities"].items()}


def approved_owner_values() -> set[str]:
    return set(load_config("ownership-mapping.yaml")["approved_role_values"])


def field_mapping() -> dict[str, Any]:
    return load_config("field-mapping.yaml")
