"""Pydantic models for deterministic lifecycle evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from genomic_research_access_api.security.lifecycle.enums import (
    ExceptionDecision,
    ExceptionStatus,
    VerificationMethod,
    VulnerabilityStatus,
)

SCHEMA_VERSION: Literal["1.0"] = "1.0"


class HistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    event_id: str
    vulnerability_id: str
    event_type: str
    from_status: VulnerabilityStatus | None = None
    to_status: VulnerabilityStatus | None = None
    actor_role: str
    reason: str
    timestamp: str
    evidence_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    vulnerability_id: str
    finding_id: str
    source_finding_ids: list[str]
    title: str
    description: str
    severity: str
    priority: str | None
    risk_score: float | None
    status: VulnerabilityStatus
    previous_status: VulnerabilityStatus | None = None
    asset_id: str | None
    component: str | None
    technical_owner: str | None
    risk_owner: str | None
    remediation_owner: str | None
    squad: str | None
    first_detected: str
    last_detected: str
    validated_at: str | None = None
    triaged_at: str | None = None
    assigned_at: str | None = None
    remediation_started_at: str | None = None
    resolved_at: str | None = None
    verified_at: str | None = None
    closed_at: str | None = None
    due_date: str | None = None
    sla_days: int | None = None
    overdue: bool
    remediation_plan: str | None = None
    remediation_reference: str | None = None
    remediation_steps: list[str] = Field(default_factory=list)
    target_completion_date: str | None = None
    implementation_reference: str | None = None
    pull_request_reference: str | None = None
    commit_reference: str | None = None
    compensating_control: str | None = None
    residual_risk: str | None = None
    verification_status: str
    verification_method: str | None = None
    verification_reference: str | None = None
    closure_evidence: str | None = None
    exception_id: str | None = None
    false_positive_reason: str | None = None
    defer_reason: str | None = None
    review_date: str | None = None
    reopened_count: int = 0
    created_at: str
    updated_at: str
    history: list[HistoryEntry]


class VerificationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    verification_id: str
    vulnerability_id: str
    verifier_role: str
    verification_method: VerificationMethod
    verification_reference: str
    expected_result: str
    actual_result: str
    passed: bool
    verified_at: str
    notes: str


class SecurityException(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    exception_id: str
    vulnerability_id: str
    finding_id: str
    status: ExceptionStatus
    requested_by_role: str
    technical_owner: str
    risk_owner: str
    approver_roles: list[str]
    business_justification: str
    technical_rationale: str
    compensating_controls: list[str]
    residual_risk: str
    requested_at: str
    approved_at: str | None
    effective_from: str | None
    expiry_date: str | None
    review_date: str | None
    maximum_duration_days: int
    environment: str
    scope: str
    decision: ExceptionDecision
    decision_reason: str
    evidence_references: list[str]
    revoked_at: str | None = None
    closed_at: str | None = None
    history: list[HistoryEntry]
