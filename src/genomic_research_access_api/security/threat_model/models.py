"""Typed threat-model records used by the validator."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

RiskRating = Literal["low", "medium", "high", "critical"]
StrideCategory = Literal[
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]
ImplementationStatus = Literal["implemented", "planned", "assumed", "not_started"]


class SecurityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Asset(SecurityModel):
    asset_id: str
    name: str
    description: str
    classification: Literal["public", "internal", "sensitive", "security-sensitive"]
    confidentiality_requirement: str
    integrity_requirement: str
    availability_requirement: str
    owner: str
    current_storage: str
    future_storage: str
    retention_expectation: str
    applicable_controls: list[str]


class Actor(SecurityModel):
    actor_id: str
    type: Literal["human", "non-human"]
    trust_level: Literal["trusted", "partially_trusted", "untrusted", "future_trusted"]
    authentication_status: str
    privileges: list[str]
    expected_actions: list[str]
    potential_misuse: list[str]


class EntryPoint(SecurityModel):
    entry_point_id: str
    name: str
    description: str
    interface_type: str
    current_or_future: Literal["current", "future"]
    trust_boundary_ids: list[str]
    validation_expectation: str


class TrustBoundary(SecurityModel):
    boundary_id: str
    source_zone: str
    destination_zone: str
    data_crossing: str
    authentication_expectation: str
    authorisation_expectation: str
    encryption_expectation: str
    logging_expectation: str
    primary_risks: list[str]


class DataFlow(SecurityModel):
    data_flow_id: str
    name: str
    source: str
    destination: str
    data: str
    trust_boundary_ids: list[str]


class Threat(SecurityModel):
    threat_id: str
    title: str
    description: str
    status: Literal["active", "accepted", "mitigated"]
    scope: Literal["current", "future", "current_and_future"]
    stride_category: StrideCategory
    owasp_api_category: str
    asset_ids: list[str]
    actor_ids: list[str]
    entry_point_ids: list[str]
    data_flow_ids: list[str]
    trust_boundary_ids: list[str]
    attack_scenario: str
    preconditions: list[str]
    likelihood: RiskRating
    impact: RiskRating
    inherent_risk: RiskRating
    existing_controls: list[str]
    planned_controls: list[str]
    required_controls: list[str]
    verification_methods: list[str]
    residual_risk: RiskRating
    risk_owner: str
    technical_owner: str
    review_date: str
    references: list[str]


class SecurityRequirement(SecurityModel):
    requirement_id: str
    title: str
    description: str
    category: str
    priority: RiskRating
    status: Literal["active", "deferred"]
    source_threat_ids: list[str] = Field(default_factory=list)
    policy_source: str | None = None
    implementation_status: ImplementationStatus
    implementation_reference: str
    verification_method: str
    verification_reference: str
    evidence_reference: str
    owner: str
    residual_risk: RiskRating
    planned_milestone: str

    @field_validator("planned_milestone")
    @classmethod
    def milestone_must_be_valid(cls, value: str) -> str:
        allowed = {"Milestone 1", "Milestone 2", "Milestone 3", "Milestone 4", "Milestone 5"}
        allowed.update(
            {
                "Milestone 6",
                "Milestone 7",
                "Milestone 8",
                "Milestone 9",
                "Milestone 10",
                "Milestone 11",
            }
        )
        if value not in allowed:
            raise ValueError("planned_milestone must reference a known portfolio milestone")
        return value


class TraceabilityLink(SecurityModel):
    traceability_id: str
    threat_id: str
    requirement_ids: list[str]
    implementation_references: list[str]
    verification_methods: list[str]
    evidence_references: list[str]
    residual_risk_id: str
    notes: str


class ResidualRisk(SecurityModel):
    risk_id: str
    related_threat_ids: list[str]
    description: str
    current_controls: list[str]
    control_limitations: list[str]
    residual_likelihood: RiskRating
    residual_impact: RiskRating
    residual_rating: RiskRating
    risk_owner: str
    treatment: Literal["accept", "mitigate", "transfer", "avoid"]
    planned_milestone: str
    review_date: str
    status: Literal["open", "accepted", "mitigation_planned"]
