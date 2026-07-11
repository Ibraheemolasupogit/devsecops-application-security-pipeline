"""Structured audit event handling."""

from collections.abc import Callable

from genomic_research_access_api.domain.clock import Clock
from genomic_research_access_api.domain.enums import ActorRole, AuditEventType, AuditOutcome
from genomic_research_access_api.domain.models import AuditEvent
from genomic_research_access_api.repositories.audit_events import AuditEventRepository


class AuditService:
    def __init__(
        self,
        repository: AuditEventRepository,
        clock: Clock,
        id_factory: Callable[[], str],
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._id_factory = id_factory

    def record(
        self,
        *,
        event_type: AuditEventType,
        actor_id: str,
        actor_role: ActorRole,
        resource_type: str,
        resource_id: str,
        outcome: AuditOutcome,
        correlation_id: str,
        details: dict[str, str] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=self._id_factory(),
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            timestamp=self._clock(),
            correlation_id=correlation_id,
            details=details or {},
        )
        return self._repository.add(event)

    def list_events(self) -> list[AuditEvent]:
        return self._repository.list()
