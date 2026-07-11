"""Audit event response schemas."""

from datetime import datetime

from genomic_research_access_api.domain.enums import ActorRole, AuditEventType, AuditOutcome
from genomic_research_access_api.schemas.common import ApiModel


class AuditEventResponse(ApiModel):
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
