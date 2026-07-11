"""Domain models used by services and repositories."""

from dataclasses import dataclass
from datetime import UTC, datetime

from genomic_research_access_api.domain.enums import (
    AccessLevel,
    AccessRequestStatus,
    ActorRole,
    AuditEventType,
    AuditOutcome,
    DatasetStatus,
    SensitivityClassification,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Dataset:
    dataset_id: str
    name: str
    description: str
    research_domain: str
    sensitivity_classification: SensitivityClassification
    access_level: AccessLevel
    status: DatasetStatus
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class AccessRequest:
    request_id: str
    dataset_id: str
    requester_id: str
    research_purpose: str
    requested_access_level: AccessLevel
    status: AccessRequestStatus
    submitted_at: datetime
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    decision_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ActorContext:
    actor_id: str
    actor_role: ActorRole


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    event_type: AuditEventType
    actor_id: str
    actor_role: ActorRole
    resource_type: str
    resource_id: str
    outcome: AuditOutcome
    timestamp: datetime
    correlation_id: str
    details: dict[str, str]
