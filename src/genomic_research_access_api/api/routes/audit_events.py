"""Local demonstration audit event route."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from genomic_research_access_api.domain.enums import AuditEventType, AuditOutcome
from genomic_research_access_api.schemas.audit import AuditEventResponse
from genomic_research_access_api.security.authentication.dependencies import require_permission
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal
from genomic_research_access_api.security.authorisation import Permission

router = APIRouter(prefix="/api/v1/audit-events", tags=["audit events"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(
    request: Request,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_permission(Permission.AUDIT_EVENT_READ))
    ],
) -> list[AuditEventResponse]:
    """Return local in-memory audit events for Milestone 1 demonstration only."""

    request.app.state.audit_service.record(
        event_type=AuditEventType.AUDIT_EVENTS_VIEWED,
        actor_id=principal.subject,
        actor_role=principal.primary_role,
        resource_type="audit_event",
        resource_id="local-demo-audit-events",
        outcome=AuditOutcome.SUCCESS,
        correlation_id=str(request.state.correlation_id),
        details={"reason_code": "audit_read_granted"},
    )
    return [
        AuditEventResponse.model_validate(event, from_attributes=True)
        for event in request.app.state.audit_service.list_events()
    ]
