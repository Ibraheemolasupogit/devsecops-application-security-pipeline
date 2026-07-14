"""Typed records for the Repository 5 integration export."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION: Literal["1.0"] = "1.0"


class ExportFindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: str
    export_record_id: str
    finding_id: str
    source_finding_ids: list[str]
    source_tools: list[str]
    finding_type: str | None
    security_domain: str | None
    title: str
    description: str
    normalised_severity: str | None
    risk_score: float | None
    priority: str | None
    status: str
    producer_status: str | None
    consumer_status: str
    lifecycle_status: str | None
    asset_id: str | None
    asset_type: str | None
    asset_criticality: str | None
    data_sensitivity: str | None
    internet_exposure: str | None
    environment: str | None
    application: str | None
    service: str | None
    repository: str | None
    component: str | None
    resource: str | None
    file: str | None
    line: int | None
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    cve: str | None
    cwe: str | None
    owasp_category: str | None
    cloud_provider: str | None
    region: str | None
    threat_ids: list[str]
    security_requirement_ids: list[str]
    control_ids: list[str]
    squad: str | None
    technical_owner: str | None
    risk_owner: str | None
    remediation_owner: str | None
    first_detected: str | None
    last_detected: str | None
    due_date: str | None
    overdue: bool | None
    remediation_sla_days: int | None
    suppression_id: str | None
    suppression_status: str | None
    exception_id: str | None
    exception_status: str | None
    exception_expiry: str | None
    verification_status: str | None
    release_decision: str | None
    release_impact: str | None
    required_actions: list[str]
    required_approvals: list[str]
    remediation_guidance: str | None
    source_evidence: list[str]
    source_record_hash: str
    lineage_references: list[str]
    producer_metadata: dict[str, Any] = Field(default_factory=dict)


class LineageEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    target_id: str
    relationship: str
    source_domain: str
    target_domain: str
    source_reference: str
    target_reference: str
    checksum: str
