"""Pydantic models for release gate evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from genomic_research_access_api.security.release.enums import ReleaseDecision, RuleOutcome

SCHEMA_VERSION: Literal["1.0"] = "1.0"


class GateRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    description: str
    enabled: bool = True
    environments: list[str]
    conditions: list[dict[str, Any]]
    decision: ReleaseDecision
    priority: int
    required_approvals: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    threat_ids: list[str] = Field(default_factory=list)
    security_requirement_ids: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    rationale_template: str


class RuleEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    rule_id: str
    finding_id: str
    outcome: RuleOutcome
    decision: ReleaseDecision | None = None
    rationale: str


class FindingEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    finding_id: str
    matched_rule_ids: list[str]
    decision_contribution: ReleaseDecision
    effective_severity: str
    risk_score: float | None
    priority: str | None
    owner_status: str
    suppression_status: str | None
    due_status: str
    fix_status: str
    environment: str
    rationale: str
    required_actions: list[str]
    required_approvals: list[str]


class ReleaseDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    decision_id: str
    decision: ReleaseDecision
    decision_timestamp: str
    as_of_date: str
    environment: str
    application: str
    repository: str
    policy_version: str
    findings_input_checksum: str
    evaluated_finding_count: int
    blocking_finding_ids: list[str]
    conditional_finding_ids: list[str]
    warning_finding_ids: list[str]
    informational_finding_ids: list[str]
    unowned_finding_ids: list[str]
    expired_suppression_finding_ids: list[str]
    overdue_finding_ids: list[str]
    rules_evaluated: int
    rules_matched: list[str]
    rules_not_matched: list[str]
    required_approvals: list[str]
    required_actions: list[str]
    rationale: str
    limitations: list[str]
    deployment_status: str
    evidence_references: list[str]
