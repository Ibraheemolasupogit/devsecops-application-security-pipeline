"""In-memory audit event repository."""

from genomic_research_access_api.domain.models import AuditEvent


class AuditEventRepository:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def add(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    def list(self) -> list[AuditEvent]:
        return sorted(self._events, key=lambda event: event.timestamp)
