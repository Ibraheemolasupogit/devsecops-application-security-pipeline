"""Pydantic models for canonical product-security findings."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from genomic_research_access_api.security.findings.enums import (
    Confidence,
    FindingStatus,
    FindingType,
    Priority,
    Severity,
    SourceType,
)

SCHEMA_VERSION: Literal["1.0"] = "1.0"


class SourceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    record_pointer: str
    record_hash: str
    summary: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    finding_id: str
    source_finding_id: str
    source_tool: str
    source_type: SourceType
    finding_type: FindingType
    security_domain: str
    title: str
    description: str
    severity: str | None = None
    normalised_severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    exploitability: str = "unknown"
    status: FindingStatus = FindingStatus.ACTIVE
    asset_id: str | None = None
    asset_type: str | None = None
    asset_criticality: str = "unknown"
    data_sensitivity: str = "unknown"
    internet_exposure: str = "unknown"
    authentication_required: str = "unknown"
    privilege_required: str = "unknown"
    environment: str = "unknown"
    application: str = "genomic-research-access-api"
    service: str | None = None
    repository: str = "devsecops-application-security-pipeline"
    component: str | None = None
    resource: str | None = None
    file: str | None = None
    line: int | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    cloud_provider: str | None = None
    account: str | None = None
    region: str | None = None
    threat_ids: list[str] = Field(default_factory=list)
    security_requirement_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    squad: str | None = None
    technical_owner: str | None = None
    risk_owner: str | None = None
    remediation_owner: str | None = None
    first_detected: str
    last_detected: str
    due_date: str | None = None
    remediation_sla_days: int | None = None
    risk_score: float | None = None
    priority: Priority | None = None
    suppression_id: str | None = None
    suppression_status: str | None = None
    suppression_expiry: str | None = None
    suppression_reason: str | None = None
    compensating_control: str | None = None
    verification_status: str = "source-observed"
    remediation_guidance: str | None = None
    source_evidence: list[SourceEvidence] = Field(default_factory=list)
    source_record_hash: str
    deduplication_key: str
    related_finding_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    findings: list[Finding]
